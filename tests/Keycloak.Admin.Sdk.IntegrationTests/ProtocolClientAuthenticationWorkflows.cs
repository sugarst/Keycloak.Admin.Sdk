using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Protocols;
using Microsoft.IdentityModel.Tokens;

internal static class ProtocolClientAuthenticationWorkflows
{
    internal static async Task RunAsync(KeycloakAdminClient admin, HttpClient http, Uri server, ProtocolTransport transport, string realm, Action<bool, string> check, CancellationToken ct)
    {
        var oidc = new OidcClient(transport); const string clientId = "jwt-private-client";
        using var firstKey = RSA.Create(2048); using var secondKey = RSA.Create(2048);
        using var firstCertificate = new CertificateRequest("CN=jwt-first", firstKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
        using var secondCertificate = new CertificateRequest("CN=jwt-second", secondKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
        ProtocolMapperRepresentation Audience(string id) => new() { Name = "own-audience", Protocol = "openid-connect", ProtocolMapper = "oidc-audience-mapper", Config = new() { ["included.client.audience"] = id, ["access.token.claim"] = "true" } };
        await admin.Clients.CreateClientAsync(realm, new ClientRepresentation { ClientId = clientId, Protocol = "openid-connect", Enabled = true, PublicClient = false, ServiceAccountsEnabled = true,
            ClientAuthenticatorType = "client-jwt", Attributes = new() { ["jwt.credential.certificate"] = Convert.ToBase64String(firstCertificate.RawData), ["token.endpoint.auth.signing.alg"] = "RS256" }, ProtocolMappers = [Audience(clientId)] }, cancellationToken: ct);
        var client = (await admin.Clients.GetClientsAsync(realm, clientId: clientId, cancellationToken: ct)).Body!.Single();
        var service = (await admin.Client.GetServiceAccountUserAsync(realm, client.Id!, ct)).Body!;
        var firstSigner = new ClientAssertionSigner(clientId, oidc, new(new RsaSecurityKey(firstKey), "RS256"));
        var first = OAuthClientAuthentication.JwtAssertion(clientId, firstSigner.CreateAsync);
        var grant = await oidc.ClientCredentialsAsync(first, cancellationToken: ct);
        var verified = await new KeycloakAccessTokenValidator(oidc, clientId).ValidateAsync(grant.Json!.Value.GetProperty("access_token").GetString()!, ct);
        check(verified.Subject == service.Id && verified.Claims.GetProperty("azp").GetString() == clientId, "Private-key JWT client authentication issues a signature-verified token for the configured service account");
        string assertion = await firstSigner.CreateAsync(ct); var fixedAssertion = OAuthClientAuthentication.JwtAssertion(clientId, _ => ValueTask.FromResult(assertion));
        await oidc.ClientCredentialsAsync(fixedAssertion, cancellationToken: ct); bool replay = false;
        try { await oidc.ClientCredentialsAsync(fixedAssertion, cancellationToken: ct); }
        catch (KeycloakProtocolException e) when (e.Error == OAuthError.InvalidClient) { replay = true; }
        check(replay, "Client authentication rejects reuse of a real signed assertion jti");
        async Task<bool> Denied(ClientAssertionSigner signer)
        {
            try { await oidc.ClientCredentialsAsync(OAuthClientAuthentication.JwtAssertion(clientId, signer.CreateAsync), cancellationToken: ct); return false; }
            catch (KeycloakProtocolException e) when (e.Error == OAuthError.InvalidClient) { return true; }
        }
        var wrongKey = new ClientAssertionSigner(clientId, oidc, new(new RsaSecurityKey(secondKey), "RS256"));
        var expired = new ClientAssertionSigner(clientId, oidc, new(new RsaSecurityKey(firstKey), "RS256"), clock: new Clock(DateTimeOffset.UtcNow.AddMinutes(-10)));
        var otherIssuer = new OidcClient(new(http, new("https://attacker.invalid/"), realm));
        var wrongAudience = new ClientAssertionSigner(clientId, otherIssuer, new(new RsaSecurityKey(firstKey), "RS256"));
        check(await Denied(wrongKey) && await Denied(expired) && await Denied(wrongAudience), "Client authentication rejects incorrect signing keys expired assertions and a foreign token-endpoint audience");
        client.Attributes!["jwt.credential.certificate"] = Convert.ToBase64String(secondCertificate.RawData); await admin.Client.UpdateAsync(realm, client.Id!, client, ct);
        var rotated = await oidc.ClientCredentialsAsync(OAuthClientAuthentication.JwtAssertion(clientId, wrongKey.CreateAsync), cancellationToken: ct);
        var rotatedIdentity = await new KeycloakAccessTokenValidator(oidc, clientId).ValidateAsync(rotated.Json!.Value.GetProperty("access_token").GetString()!, ct);
        check(rotatedIdentity.Subject == service.Id && await Denied(firstSigner), "Client signing-key rotation accepts the new credential and rejects a freshly signed assertion from the retired key");
        const string symmetricClient = "jwt-secret-client"; string secret = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        await admin.Clients.CreateClientAsync(realm, new ClientRepresentation { ClientId = symmetricClient, Protocol = "openid-connect", Enabled = true, PublicClient = false, ServiceAccountsEnabled = true,
            ClientAuthenticatorType = "client-secret-jwt", Secret = secret, Attributes = new() { ["token.endpoint.auth.signing.alg"] = "HS256" }, ProtocolMappers = [Audience(symmetricClient)] }, cancellationToken: ct);
        var symmetricSigner = new ClientAssertionSigner(symmetricClient, oidc, new(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret)), "HS256"));
        var symmetric = await oidc.ClientCredentialsAsync(OAuthClientAuthentication.JwtAssertion(symmetricClient, symmetricSigner.CreateAsync), cancellationToken: ct);
        check((await new KeycloakAccessTokenValidator(oidc, symmetricClient).ValidateAsync(symmetric.Json!.Value.GetProperty("access_token").GetString()!, ct)).Claims.GetProperty("azp").GetString() == symmetricClient,
            "Client-secret JWT authentication verifies the configured HMAC assertion without treating it as a resource access token");
    }
    private sealed class Clock(DateTimeOffset now) : TimeProvider { public override DateTimeOffset GetUtcNow() => now; }
}
