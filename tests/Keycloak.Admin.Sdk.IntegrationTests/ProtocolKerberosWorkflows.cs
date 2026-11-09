using System.Net;
using System.Net.Http.Headers;
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Protocols;

internal static class ProtocolKerberosWorkflows
{
    internal static async Task RunAsync(KeycloakAdminClient admin, HttpClient http, ProtocolTransport transport, string realm, Action<bool, string> check, CancellationToken ct)
    {
        string image = Environment.GetEnvironmentVariable("KC_TEST_KERBEROS_IMAGE_ID") ?? throw new InvalidDataException("An owned Kerberos counterpart is required.");
        if (!image.StartsWith("sha256:", StringComparison.Ordinal) || image.Length != 71) throw new InvalidDataException("Kerberos counterpart must have an immutable image identity.");
        var settings = (await admin.RealmAdmin.GetRealmAsync(realm, ct)).Body!;
        await admin.Component.CreateAsync(realm, new() { Name = "owned-mit-kerberos", ProviderType = "org.keycloak.storage.UserStorageProvider", ProviderId = "kerberos", ParentId = settings.Id,
            Config = new() { ["enabled"] = ["true"], ["priority"] = ["0"], ["allowKerberosAuthentication"] = ["true"], ["kerberosRealm"] = ["SDK.TEST"],
                ["serverPrincipal"] = ["HTTP/localhost@SDK.TEST"], ["keyTab"] = ["/kerberos/service.keytab"], ["allowPasswordAuthentication"] = ["false"], ["updateProfileFirstLogin"] = ["false"], ["editMode"] = ["READ_ONLY"] } }, ct);
        var federation = (await admin.Component.GetComponentsAsync(realm, name: "owned-mit-kerberos", cancellationToken: ct)).Body!.Single();
        if ((await admin.Users.GetUsersAsync(realm, username: "kerberos-user", exact: true, cancellationToken: ct)).Body!.Count != 0) throw new InvalidDataException("Kerberos proof must start without an ordinary local account.");
        // A required SPNEGO-only flow prevents fallback to an unrelated password identity from making this proof pass.
        var imported = new RealmRepresentation { Realm = realm, AuthenticationFlows = [new() { Alias = "sdk-kerberos", BuiltIn = false, TopLevel = true, ProviderId = "basic-flow",
            AuthenticationExecutions = [new() { Authenticator = "auth-spnego", AuthenticatorFlow = false, Requirement = "REQUIRED", Priority = 0 }] }] };
        await admin.AuthenticationManagement.CreateFlowAsync(realm, imported.AuthenticationFlows[0], ct);
        var flow = (await admin.AuthenticationManagement.GetFlowsAsync(realm, ct)).Body!.Single(f => f.Alias == "sdk-kerberos");
        await admin.AuthenticationManagement.AddExecutionAsync(realm, new() { ParentFlow = flow.Id, Authenticator = "auth-spnego", AuthenticatorFlow = false, Requirement = "REQUIRED", Priority = 0 }, ct);
        settings = (await admin.RealmAdmin.GetRealmAsync(realm, ct)).Body!; settings.BrowserFlow = "sdk-kerberos"; await admin.RealmAdmin.UpdateRealmAsync(realm, settings, ct);
        var oidc = new OidcClient(transport); var client = OAuthClientAuthentication.Public("sdk-authentication"); var redirect = new Uri("http://127.0.0.1:18089/authentication-callback");
        async Task<(Uri? Callback, bool Challenged)> Negotiate(OidcLoginTransaction transaction, string? ticket)
        {
            using var handler = new HttpClientHandler { AllowAutoRedirect = false, UseCookies = true }; using var browser = new HttpClient(handler);
            browser.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Version/18.0 Safari/605.1.15");
            using var first = await browser.GetAsync(transaction.AuthorizationUri, ct);
            bool challenge = first.StatusCode == HttpStatusCode.Unauthorized && first.Headers.WwwAuthenticate.Any(h => h.Scheme == "Negotiate");
            if (!challenge || ticket is null) return (null, challenge);
            using var request = new HttpRequestMessage(HttpMethod.Get, transaction.AuthorizationUri); request.Headers.Authorization = new("Negotiate", ticket);
            using var response = await browser.SendAsync(request, ct);
            Console.WriteLine("Kerberos fixture response: " + (int)response.StatusCode + " " + response.Headers.Location?.AbsolutePath);
            if ((int)response.StatusCode is >= 300 and < 400 && response.Headers.Location is { } location)
            {
                location = new Uri(transaction.AuthorizationUri, location);
                if (location.GetLeftPart(UriPartial.Path) == redirect.AbsoluteUri) return (location, true);
                if (location.GetLeftPart(UriPartial.Path) == transport.Issuer.AbsoluteUri + "/login-actions/required-action")
                {
                    var callback = await ProtocolBrowserFixture.LoginWithAuthenticatorAsync(location, redirect, "kerberos-user", "unused",
                        html => html.Contains("id=\"kc-update-profile-form\"", StringComparison.Ordinal)
                            ? new() { ["firstName"] = "Kerberos", ["lastName"] = "User", ["email"] = "kerberos-user@sdk.test", ["username"] = "kerberos-user" } : null,
                        ct, browser);
                    return (callback, true);
                }
            }
            return (null, true);
        }
        async Task<OidcLoginTransaction> Start() => await OidcLoginTransaction.StartAsync(oidc, client, redirect, options: new() { RequiredAuthenticationCapabilities = [KeycloakAuthenticationCapability.Kerberos] }, cancellationToken: ct);
        var missing = await Negotiate(await Start(), null);
        check(missing.Challenged && missing.Callback is null, "A Kerberos-only login issues a real Negotiate challenge and cannot create an application identity without a service ticket");
        string ticket = (await http.GetStringAsync("http://127.0.0.1:18091/ticket", ct)).Trim();
        var login = await Start(); var result = await Negotiate(login, ticket);
        if (result.Callback is null) throw new InvalidDataException("The trusted Kerberos service ticket did not complete SPNEGO login.");
        var identity = await login.CompleteAsync(result.Callback, client, new(oidc, client.ClientId), ct);
        var account = (await admin.Users.GetUsersAsync(realm, username: "kerberos-user", exact: true, cancellationToken: ct)).Body!.Single();
        check(identity.Identity.Subject == account.Id && account.FederationLink == federation.Id && account.Attributes!["KERBEROS_PRINCIPAL"].Single() == "kerberos-user@SDK.TEST",
            "A real MIT Kerberos SPNEGO service ticket maps only its configured principal to the independently observed signature-verified application identity");
        var duplicate = await Negotiate(await Start(), ticket);
        check(duplicate.Callback is null, "Replaying a consumed Kerberos service authenticator cannot create another application login");
        byte[] invalid = Convert.FromBase64String((await http.GetStringAsync("http://127.0.0.1:18091/ticket", ct)).Trim()); invalid[^1] ^= 1;
        check((await Negotiate(await Start(), Convert.ToBase64String(invalid))).Callback is null,
            "A modified Kerberos service authenticator cannot create a verified application identity");
        await admin.Component.RemoveComponentAsync(realm, federation.Id!, ct);
    }
}
