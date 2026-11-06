using System.Net;
using System.Security.Cryptography;
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Capabilities;
using Keycloak.Admin.Sdk.Protocols;

internal static class ProtocolDpopWorkflows
{
    internal static async Task RunAsync(KeycloakAdminClient admin, HttpClient http, Uri server, KeycloakFeatureSnapshotGate flags, string realm, string secret, Action<bool, string> check, CancellationToken ct)
    {
        await admin.Clients.CreateClientAsync(realm, new ClientRepresentation { ClientId = "dpop-app", Protocol = "openid-connect", Enabled = true, PublicClient = true,
            DirectAccessGrantsEnabled = true, Attributes = new() { ["dpop.bound.access.tokens"] = "true" },
            ProtocolMappers = [new ProtocolMapperRepresentation { Name = "own-audience", Protocol = "openid-connect", ProtocolMapper = "oidc-audience-mapper",
                Config = new() { ["included.client.audience"] = "dpop-app", ["access.token.claim"] = "true" } }] }, cancellationToken: ct);
        using var privateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256); var key = DpopProofKey.FromEcdsa(privateKey);
        var transport = new ProtocolTransport(http, server, realm, flags, key); var oidc = new OidcClient(transport);
        var auth = OAuthClientAuthentication.Public("dpop-app");
        var grant = (await oidc.PasswordGrantAsync(auth, "account-user", secret, scope: "openid", cancellationToken: ct)).Json!.Value;
        string access = grant.GetProperty("access_token").GetString()!, refresh = grant.GetProperty("refresh_token").GetString()!;
        var verified = await new KeycloakAccessTokenValidator(oidc, "dpop-app").ValidateAsync(access, ct);
        check(grant.GetProperty("token_type").GetString() == "DPoP" && verified.Claims.GetProperty("cnf").GetProperty("jkt").GetString() == key.Thumbprint,
            "Keycloak issues a signature-verified DPoP access token bound to the supplied public-key thumbprint");
        check((await oidc.GetUserInfoAsync(access, ct)).Json!.Value.GetProperty("sub").GetString() == verified.Subject,
            "Keycloak userinfo accepts a valid DPoP scheme proof method URI and access-token hash");
        bool bearerDenied = false;
        try { await new OidcClient(new(http, server, realm)).GetUserInfoAsync(access, ct); }
        catch (KeycloakProtocolException e) when (e.StatusCode == HttpStatusCode.Unauthorized) { bearerDenied = true; }
        check(bearerDenied, "Keycloak rejects a DPoP token presented as an ordinary bearer token");
        using var wrongPrivateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256); var wrongKey = DpopProofKey.FromEcdsa(wrongPrivateKey);
        bool wrongRefreshDenied = false;
        try { await new OidcClient(new(http, server, realm, flags, wrongKey)).RefreshAsync(auth, refresh, cancellationToken: ct); }
        catch (KeycloakProtocolException e) when (e.StatusCode == HttpStatusCode.BadRequest && e.Error is OAuthError.InvalidGrant or OAuthError.InvalidDpopProof) { wrongRefreshDenied = true; }
        check(wrongRefreshDenied, "Public-client DPoP refresh rejects a key different from the original token binding");
        var refreshed = (await oidc.RefreshAsync(auth, refresh, cancellationToken: ct)).Json!.Value;
        var refreshedIdentity = await new KeycloakAccessTokenValidator(oidc, "dpop-app").ValidateAsync(refreshed.GetProperty("access_token").GetString()!, ct);
        check(refreshedIdentity.Subject == verified.Subject && refreshedIdentity.Claims.GetProperty("cnf").GetProperty("jkt").GetString() == key.Thumbprint,
            "DPoP refresh with the correct key preserves subject and confirmation binding");
        var resource = new Uri("https://resource.invalid/document?view=one"); var verifier = new DpopRequestValidator(new InMemoryDpopReplayStore());
        string proof = key.CreateProof(HttpMethod.Get, resource, access);
        await verifier.ValidateAsync(proof, HttpMethod.Get, resource, verified, cancellationToken: ct);
        bool replayDenied = false, mismatchDenied = false, wrongKeyDenied = false;
        try { await verifier.ValidateAsync(proof, HttpMethod.Get, resource, verified, cancellationToken: ct); }
        catch (DpopValidationException e) when (e.Reason == DpopFailure.Replay) { replayDenied = true; }
        try { await verifier.ValidateAsync(key.CreateProof(HttpMethod.Post, resource, access), HttpMethod.Get, resource, verified, cancellationToken: ct); }
        catch (DpopValidationException e) when (e.Reason == DpopFailure.RequestMismatch) { mismatchDenied = true; }
        try { await verifier.ValidateAsync(wrongKey.CreateProof(HttpMethod.Get, resource, access), HttpMethod.Get, resource, verified, cancellationToken: ct); }
        catch (DpopValidationException e) when (e.Reason == DpopFailure.TokenBinding) { wrongKeyDenied = true; }
        check(replayDenied && mismatchDenied && wrongKeyDenied, "SDK resource-server DPoP validation rejects replay wrong methods and mismatched proof keys for a real Keycloak token");
        key.SetNonce(resource, "resource-nonce");
        await verifier.ValidateAsync(key.CreateProof(HttpMethod.Get, resource, access), HttpMethod.Get, resource, verified, "resource-nonce", ct);
        bool nonceDenied = false;
        try { await verifier.ValidateAsync(key.CreateProof(HttpMethod.Get, resource, access), HttpMethod.Get, resource, verified, "different-nonce", ct); }
        catch (DpopValidationException e) when (e.Reason == DpopFailure.NonceRequired) { nonceDenied = true; }
        check(nonceDenied, "SDK resource-server DPoP nonce policy accepts the expected nonce and rejects a mismatched one");
    }
}
