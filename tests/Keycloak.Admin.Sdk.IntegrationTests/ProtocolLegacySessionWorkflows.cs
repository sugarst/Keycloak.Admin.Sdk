using System.Net;
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Protocols;

internal static class ProtocolLegacySessionWorkflows
{
    internal static async Task RunAsync(KeycloakAdminClient admin, ProtocolTransport transport, string realm, string user, string password, Action<bool, string> check, CancellationToken ct)
    {
        var oidc = new OidcClient(transport); var client = OAuthClientAuthentication.Public("sdk-authentication"); var callback = new Uri("http://127.0.0.1:18089/authentication-callback"); var verifier = new OidcTokenValidator(oidc, client.ClientId);
        async Task<OidcLoginResult> Login(string scope)
        {
            var transaction = await OidcLoginTransaction.StartAsync(oidc, client, callback, scope, cancellationToken: ct);
            var browser = await ProtocolBrowserFixture.LoginAsync(transaction.AuthorizationUri, callback, "auth-user", password, ct);
            return await transaction.CompleteAsync(browser.Callback, client, verifier, ct);
        }
        var regular = await Login("openid"); var offline = await Login("openid offline_access");
        string regularSession = regular.Identity.VerifiedClaims.GetProperty("sid").GetString()!;
        string offlineSession = offline.Identity.VerifiedClaims.GetProperty("sid").GetString()!;
        string clientUuid = (await admin.Clients.GetClientsAsync(realm, clientId: client.ClientId, cancellationToken: ct)).Body!.Single().Id!;
        if (!(await admin.User.GetOfflineSessionsAsync(realm, user, clientUuid, ct)).Body!.Any(s => s.Id == offlineSession)) throw new InvalidDataException("The legacy logout proof requires a real independently observed offline session.");
        var action = await OidcLoginTransaction.StartAsync(oidc, client, callback, options: new() { Action = "UPDATE_PASSWORD", RequiredAuthenticationCapabilities = [KeycloakAuthenticationCapability.LegacyLogoutAllSessions] }, cancellationToken: ct);
        string replacement = password + "Changed!";
        var complete = await ProtocolBrowserFixture.LoginWithAuthenticatorAsync(action.AuthorizationUri, callback, "auth-user", password,
            html => html.Contains("id=\"kc-passwd-update-form\"", StringComparison.Ordinal) ? new() { ["password-new"] = replacement, ["password-confirm"] = replacement, ["logout-sessions"] = "on" } : null, ct);
        var current = await action.CompleteAsync(complete, client, verifier, ct);
        bool revoked = false;
        try { await oidc.RefreshAsync(client, regular.Tokens.Json!.Value.GetProperty("refresh_token").GetString()!, cancellationToken: ct); } catch (KeycloakProtocolException e) when (e.StatusCode == HttpStatusCode.BadRequest) { revoked = true; }
        check(revoked && current.Identity.Subject == user && !(await admin.User.GetSessionsAsync(realm, user, ct)).Body!.Any(s => s.Id == regularSession),
            "Explicit deprecated logout-other-sessions compatibility revokes the independently observed regular session after the user confirms a password change");
        var retained = await oidc.RefreshAsync(client, offline.Tokens.Json!.Value.GetProperty("refresh_token").GetString()!, cancellationToken: ct);
        var retainedIdentity = await verifier.ValidateRefreshedIdTokenAsync(retained.Json!.Value.GetProperty("id_token").GetString()!, offline.Identity, retained.Json.Value.GetProperty("access_token").GetString()!, ct);
        check(retainedIdentity.Subject == user && (await admin.User.GetOfflineSessionsAsync(realm, user, clientUuid, ct)).Body!.Any(s => s.Id == offlineSession),
            "The pinned logout-all-sessions v1 behavior deliberately retains the real offline session and cannot be described as revoking every credential");
    }
}
