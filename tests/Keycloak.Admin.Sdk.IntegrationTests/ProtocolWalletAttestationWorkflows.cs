using System.Net;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Capabilities;
using Keycloak.Admin.Sdk.Protocols;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

internal static class ProtocolWalletAttestationWorkflows
{
    internal static async Task RunAsync(KeycloakAdminClient admin, HttpClient http, ProtocolTransport transport, string realm, Action<bool, string> check, CancellationToken ct)
    {
        using var attester = RSA.Create(2048); using var attacker = RSA.Create(2048); using var walletKey = ECDsa.Create(ECCurve.NamedCurves.nistP256); using var otherWallet = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var holder = Oid4vcProofKey.FromEcdsa(walletKey); var wrongHolder = Oid4vcProofKey.FromEcdsa(otherWallet);
        const string clientId = "wallet-attested", alias = "wallet-attester", attesterIssuer = "https://attester.example.invalid";
        var parameters = attester.ExportParameters(false);
        var jwks = new JsonObject { ["keys"] = new JsonArray(new JsonObject { ["kty"] = "RSA", ["kid"] = "wallet-attester-key", ["use"] = "sig", ["alg"] = "RS256",
            ["n"] = Base64UrlEncoder.Encode(parameters.Modulus), ["e"] = Base64UrlEncoder.Encode(parameters.Exponent) }) };
        await admin.IdentityProviders.CreateAsync(realm, new() { Alias = alias, ProviderId = "default-trust", Enabled = true, HideOnLogin = true,
            Config = new() { ["publicKeySignatureVerifier"] = jwks.ToJsonString(), ["useJwksUrl"] = "false" } }, ct);
        await admin.Clients.CreateClientAsync(realm, new() { ClientId = clientId, Enabled = true, PublicClient = false, Protocol = "openid-connect", ClientAuthenticatorType = "attestation-based",
            ServiceAccountsEnabled = true, Attributes = new() { ["attester_trust_idps"] = alias },
            ProtocolMappers = [new() { Name = "own-audience", Protocol = "openid-connect", ProtocolMapper = "oidc-audience-mapper", Config = new() { ["included.client.audience"] = clientId, ["access.token.claim"] = "true" } }] }, cancellationToken: ct);
        var app = (await admin.Clients.GetClientsAsync(realm, clientId: clientId, cancellationToken: ct)).Body!.Single();
        string expectedUser = (await admin.Client.GetServiceAccountUserAsync(realm, app.Id!, ct)).Body!.Id!;
        string Attestation(RSA key, bool expired = false) => new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = attesterIssuer, Subject = null, TokenType = "oauth-client-attestation+jwt", SigningCredentials = new(new RsaSecurityKey(key) { KeyId = "wallet-attester-key" }, "RS256"),
            IssuedAt = DateTime.UtcNow.AddMinutes(-10), Expires = DateTime.UtcNow.AddMinutes(expired ? -5 : 5),
            Claims = new Dictionary<string, object> { ["sub"] = clientId, ["cnf"] = new Dictionary<string, object> { ["jwk"] = holder.PublicJwk } }
        });
        OAuthClientAuthentication Authentication(RSA issuerKey, Oid4vcProofKey proof, Uri? audience = null, bool expired = false) => OAuthClientAuthentication.Attestation(clientId,
            (_, token) => { token.ThrowIfCancellationRequested(); return ValueTask.FromResult(new OAuthClientAttestation(Attestation(issuerKey, expired), proof.CreateClientAttestationProof(audience ?? transport.Issuer, clientId))); });
        var oidc = new OidcClient(transport); var authentication = Authentication(attester, holder);
        var token = await oidc.ClientCredentialsAsync(authentication, cancellationToken: ct);
        var identity = await new KeycloakAccessTokenValidator(oidc, clientId).ValidateAsync(token.Json!.Value.GetProperty("access_token").GetString()!, ct);
        check(identity.Subject == expectedUser, "Trusted wallet attestation and a fresh client proof authenticate the independently observed service account");
        foreach (var (invalid, reason) in new[] { (Authentication(attacker, holder), "an untrusted attester"), (Authentication(attester, wrongHolder), "a foreign holder"),
            (Authentication(attester, holder, new("https://other.example.invalid/realms/foreign")), "the wrong audience"), (Authentication(attester, holder, expired: true), "an expired attestation") })
        {
            bool rejected = false;
            try { await oidc.ClientCredentialsAsync(invalid, cancellationToken: ct); } catch (KeycloakProtocolException e) when (e.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.Unauthorized) { rejected = true; }
            check(rejected, "Wallet attestation refuses " + reason + " before issuing a client token");
        }
        var flags = new Dictionary<string, bool> { ["KeycloakSdk.Protocols"] = true, ["KeycloakSdk.Protocols.Oidc"] = true, ["KeycloakSdk.Protocols.WalletAttestation"] = false };
        var server = new Uri(transport.Issuer.AbsoluteUri[..transport.Issuer.AbsoluteUri.IndexOf("/realms/", StringComparison.Ordinal)] + "/");
        var gated = new OidcClient(new ProtocolTransport(http, server, realm, new KeycloakFeatureSnapshotGate(flags))); int calls = 0, before = RecordingHandler.SentCount; bool closed = false;
        try { await gated.ClientCredentialsAsync(OAuthClientAuthentication.Attestation(clientId, (_, _) => { calls++; return ValueTask.FromResult(new OAuthClientAttestation("unused", "unused")); }), cancellationToken: ct); }
        catch (InvalidOperationException) { closed = true; }
        check(closed && calls == 0 && before == RecordingHandler.SentCount, "Closing wallet attestation blocks its credential provider and HTTP request independently of ordinary OIDC");
    }
}
