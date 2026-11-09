using System.Net;
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Protocols;

internal static class ProtocolTransientUserWorkflows
{
    internal static async Task RunAsync(KeycloakAdminClient admin, HttpClient http, ProtocolTransport transport, string realm, Uri server, string password, Action<bool, string> check, CancellationToken ct)
    {
        string upstream = realm + "-transient-upstream"; const string alias = "transient-upstream";
        await admin.RealmsAdmin.ImportRealmAsync(new StringContent(System.Text.Json.JsonSerializer.Serialize(new RealmRepresentation { Realm = upstream, Enabled = true }, KeycloakJsonContext.Default.RealmRepresentation), System.Text.Encoding.UTF8, "application/json"), ct);
        try
        {
            var issuer = new Uri(server, "realms/" + upstream);
            await admin.Clients.CreateClientAsync(upstream, new() { ClientId = "transient-broker", Protocol = "openid-connect", Enabled = true, Secret = password, PublicClient = false, StandardFlowEnabled = true,
                RedirectUris = [transport.Issuer.AbsoluteUri + "/broker/" + alias + "/endpoint"] }, ct);
            await admin.Users.CreateUserAsync(upstream, new() { Username = "transient-user", FirstName = "Transient", LastName = "User", Email = "transient@example.invalid", EmailVerified = true, Enabled = true,
                Credentials = [new() { Type = "password", Value = password, Temporary = false }] }, ct);
            string externalUser = (await admin.Users.GetUsersAsync(upstream, username: "transient-user", exact: true, cancellationToken: ct)).Body!.Single().Id!;
            await admin.IdentityProviders.CreateAsync(realm, new() { Alias = alias, ProviderId = "oidc", Enabled = true, TrustEmail = true, StoreToken = false,
                Config = new() { ["clientId"] = "transient-broker", ["clientSecret"] = password, ["doNotStoreUsers"] = "true", ["authorizationUrl"] = issuer.AbsoluteUri + "/protocol/openid-connect/auth",
                    ["tokenUrl"] = issuer.AbsoluteUri + "/protocol/openid-connect/token", ["userInfoUrl"] = issuer.AbsoluteUri + "/protocol/openid-connect/userinfo", ["jwksUrl"] = issuer.AbsoluteUri + "/protocol/openid-connect/certs", ["useJwksUrl"] = "true", ["issuer"] = issuer.AbsoluteUri } }, ct);
            var oidc = new OidcClient(transport); var auth = OAuthClientAuthentication.Public("sdk-authentication"); var redirect = new Uri("http://127.0.0.1:18089/authentication-callback");
            async Task<OidcLoginResult> Login()
            {
                var transaction = await OidcLoginTransaction.StartAsync(oidc, auth, redirect, "openid profile email", options: new() { IdentityProvider = alias, RequiredAuthenticationCapabilities = [KeycloakAuthenticationCapability.TransientUsers] }, cancellationToken: ct);
                var browser = await ProtocolBrowserFixture.LoginAsync(transaction.AuthorizationUri, redirect, "transient-user", password, ct);
                return await transaction.CompleteAsync(browser.Callback, auth, new(oidc, auth.ClientId), ct);
            }
            var login = await Login(); string subject = login.Identity.Subject;
            check(subject != externalUser && (await admin.Users.GetUsersAsync(realm, username: "transient-user", exact: true, cancellationToken: ct)).Body!.Count == 0
                && (await admin.User.GetSessionsAsync(realm, subject, ct)).Body!.Any(s => s.TransientUser == true),
                "A signature-verified transient broker identity retains a marked server session without persisting an ordinary local user");
            string refresh = login.Tokens.Json!.Value.GetProperty("refresh_token").GetString()!;
            var refreshed = await oidc.RefreshAsync(auth, refresh, cancellationToken: ct);
            var identity = await new OidcTokenValidator(oidc, auth.ClientId).ValidateRefreshedIdTokenAsync(refreshed.Json!.Value.GetProperty("id_token").GetString()!,
                login.Identity, refreshed.Json.Value.GetProperty("access_token").GetString()!, ct);
            check(identity.Subject == subject && (await admin.Users.GetUsersAsync(realm, username: "transient-user", exact: true, cancellationToken: ct)).Body!.Count == 0,
                "Refreshing a transient identity preserves its verified session subject without silently storing a local account");
            string currentRefresh = refreshed.Json.Value.GetProperty("refresh_token").GetString()!;
            await oidc.LogoutAsync(auth, currentRefresh, cancellationToken: ct);
            bool invalidated = false;
            try { await oidc.RefreshAsync(auth, currentRefresh, cancellationToken: ct); } catch (KeycloakProtocolException e) when (e.StatusCode == HttpStatusCode.BadRequest) { invalidated = true; }
            var next = await Login();
            check(invalidated && next.Identity.Subject != subject && (await admin.Users.GetUsersAsync(realm, username: "transient-user", exact: true, cancellationToken: ct)).Body!.Count == 0,
                "Transient logout invalidates its refresh credential and a subsequent broker login creates a distinct session identity without a persistent user");
        }
        finally { using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(30)); await admin.RealmAdmin.DeleteRealmAsync(upstream, cleanup.Token); }
    }
}
