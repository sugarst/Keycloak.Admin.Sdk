using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Capabilities;
using Keycloak.Admin.Sdk.Protocols;

internal static class ProtocolAuthenticationWorkflows
{
    internal static async Task RunAsync(KeycloakAdminClient admin, HttpClient http, ProtocolTransport parent, string password, Action<bool, string> check, CancellationToken ct)
    {
        string realm = Uri.UnescapeDataString(parent.Issuer.Segments[^1]) + "-authentication"; var server = new Uri(parent.Issuer.AbsoluteUri[..parent.Issuer.AbsoluteUri.IndexOf("realms/", StringComparison.Ordinal)]);
        AuthenticationExecutionExportRepresentation Auth(string name, int order) => new() { Authenticator = name, Requirement = "REQUIRED", Priority = order, AuthenticatorFlow = false };
        AuthenticationFlowRepresentation Flow(string alias, params AuthenticationExecutionExportRepresentation[] steps) => new() { Alias = alias, BuiltIn = false, TopLevel = true, ProviderId = "basic-flow", AuthenticationExecutions = [.. steps] };
        var settings = new RealmRepresentation { Realm = realm, Enabled = true, BrowserFlow = "sdk-password", WebAuthnPolicySignatureAlgorithms = ["ES256"], WebAuthnPolicyUserVerificationRequirement = "required",
            WebAuthnPolicyPasswordlessSignatureAlgorithms = ["ES256"], WebAuthnPolicyPasswordlessUserVerificationRequirement = "required", WebAuthnPolicyPasswordlessResidentKey = "required", WebAuthnPolicyPasswordlessPasskeysEnabled = true,
            AuthenticationFlows = [Flow("sdk-password", Auth("auth-username-password-form", 0)), Flow("sdk-webauthn", Auth("auth-username-form", 0), Auth("webauthn-authenticator", 10)),
                Flow("sdk-passkey", Auth("webauthn-authenticator-passwordless", 0)), Flow("sdk-legacy-passkey", Auth("passkeys-authenticator", 0)), Flow("sdk-recovery", Auth("auth-username-password-form", 0), Auth("auth-recovery-authn-code-form", 10))] };
        await admin.RealmsAdmin.ImportRealmAsync(new StringContent(JsonSerializer.Serialize(settings, KeycloakJsonContext.Default.RealmRepresentation), Encoding.UTF8, "application/json"), ct);
        try
        {
            var flags = new Dictionary<string, bool> { ["KeycloakSdk.Protocols"] = true, ["KeycloakSdk.Protocols.Oidc"] = true, ["KeycloakSdk.Protocols.Authentication"] = true, ["KeycloakSdk.Protocols.IdentityBrokerLogin"] = true };
            foreach (var capability in Enum.GetValues<KeycloakAuthenticationCapability>()) flags["KeycloakSdk.Protocols.Authentication" + capability] = true;
            var gate = new KeycloakFeatureSnapshotGate(flags); var transport = new ProtocolTransport(http, server, realm, gate); var oidc = new OidcClient(transport);
            var redirect = new Uri("http://127.0.0.1:18089/authentication-callback"); var auth = OAuthClientAuthentication.Public("sdk-authentication"); var validator = new OidcTokenValidator(oidc, auth.ClientId);
            await admin.Clients.CreateClientAsync(realm, new() { ClientId = auth.ClientId, Protocol = "openid-connect", PublicClient = true, Enabled = true, StandardFlowEnabled = true, RedirectUris = [redirect.AbsoluteUri], Attributes = new() { ["pkce.code.challenge.method"] = "S256" } }, ct);
            await admin.Users.CreateUserAsync(realm, new() { Username = "auth-user", FirstName = "Authentication", LastName = "User", Email = "auth@example.invalid", EmailVerified = true, Enabled = true,
                Credentials = [new() { Type = "password", Value = password, Temporary = false }] }, ct);
            string user = (await admin.Users.GetUsersAsync(realm, username: "auth-user", exact: true, cancellationToken: ct)).Body!.Single().Id!;
            async Task<string> LoginAsync(OidcAuthorizationOptions options, Func<string, Dictionary<string, string>?> challenge)
            {
                var transaction = await OidcLoginTransaction.StartAsync(oidc, auth, redirect, options: options, cancellationToken: ct);
                var callback = await ProtocolBrowserFixture.LoginWithAuthenticatorAsync(transaction.AuthorizationUri, redirect, "auth-user", password, challenge, ct);
                return (await transaction.CompleteAsync(callback, auth, validator, ct)).Identity.Subject;
            }
            async Task SetFlow(string alias)
            { var current = (await admin.RealmAdmin.GetRealmAsync(realm, cancellationToken: ct)).Body!; current.BrowserFlow = alias; await admin.RealmAdmin.UpdateRealmAsync(realm, current, ct); }
            async Task EnableAction(string alias)
            { var action = (await admin.AuthenticationManagement.GetRequiredActionAsync(realm, alias, ct)).Body!; action.Enabled = true; await admin.AuthenticationManagement.UpdateRequiredActionAsync(realm, alias, action, ct); }
            using var securityKey = new ProtocolWebAuthnAuthenticator(server);
            await EnableAction("webauthn-register");
            check(await LoginAsync(new() { Action = "webauthn-register" }, securityKey.Respond) == user && securityKey.Registrations == 1
                && (await admin.User.CredentialsAsync(realm, user, ct)).Body!.Any(c => c.Type == "webauthn"), "A real WebAuthn registration persists its public credential only after the bound PKCE login and server-verified ceremony");
            await SetFlow("sdk-webauthn");
            check(await LoginAsync(new() { RequiredAuthenticationCapabilities = [KeycloakAuthenticationCapability.WebAuthn] }, securityKey.Respond) == user && securityKey.Authentications == 1,
                "WebAuthn login verifies a fresh challenge RP origin user presence verification and authenticator signature before the application accepts its signed subject");
            foreach (bool wrongOrigin in new[] { true, false })
            {
                securityKey.TamperOrigin = wrongOrigin; securityKey.TamperSignature = !wrongOrigin; bool refused = false;
                try { await LoginAsync(new() { RequiredAuthenticationCapabilities = [KeycloakAuthenticationCapability.WebAuthn] }, securityKey.Respond); }
                catch (InvalidDataException) { refused = true; }
                check(refused, wrongOrigin ? "An assertion from a foreign WebAuthn origin cannot produce a verified application login" : "A modified real WebAuthn assertion signature cannot produce a verified application login");
            }
            securityKey.TamperOrigin = false; securityKey.TamperSignature = false;
            await SetFlow("sdk-password"); await EnableAction("webauthn-register-passwordless");
            using var passkey = new ProtocolWebAuthnAuthenticator(server);
            check(await LoginAsync(new() { Action = "webauthn-register-passwordless", RequiredAuthenticationCapabilities = [KeycloakAuthenticationCapability.Passkeys] }, passkey.Respond) == user
                && (await admin.User.CredentialsAsync(realm, user, ct)).Body!.Any(c => c.Type == "webauthn-passwordless"), "Passkey registration persists a resident user-verified public credential through the protected application-initiated action");
            await SetFlow("sdk-passkey");
            check(await LoginAsync(new() { RequiredAuthenticationCapabilities = [KeycloakAuthenticationCapability.Passkeys] }, passkey.Respond) == user && passkey.Authentications == 1,
                "A discoverable passkey authenticates its bound account without sending an account password to the application or authenticator");
            await SetFlow("sdk-legacy-passkey"); passkey.UseConditionalUi = true;
            check(await LoginAsync(new() { RequiredAuthenticationCapabilities = [KeycloakAuthenticationCapability.LegacyConditionalPasskeyUi, KeycloakAuthenticationCapability.Passkeys] }, passkey.Respond) == user,
                "The explicitly enabled deprecated conditional Passkey authenticator preserves its resident credential challenge signature and original verified account");
            passkey.TamperOrigin = true; bool legacyOrigin = false;
            try { await LoginAsync(new() { RequiredAuthenticationCapabilities = [KeycloakAuthenticationCapability.LegacyConditionalPasskeyUi] }, passkey.Respond); } catch (InvalidDataException) { legacyOrigin = true; }
            check(legacyOrigin, "The deprecated conditional Passkey authenticator cannot turn a foreign-origin assertion into a verified application identity");
            passkey.TamperOrigin = false; passkey.UseConditionalUi = false;
            await SetFlow("sdk-password"); await EnableAction("CONFIGURE_RECOVERY_AUTHN_CODES");
            string[] recovery = [];
            Dictionary<string, string>? Recovery(string html)
            {
                if (html.Contains("name=\"generatedRecoveryAuthnCodes\"", StringComparison.Ordinal))
                {
                    string codes = Hidden(html, "generatedRecoveryAuthnCodes"), generated = Hidden(html, "generatedAt"); recovery = codes.Split(',', StringSplitOptions.RemoveEmptyEntries);
                    return new() { ["generatedRecoveryAuthnCodes"] = codes, ["generatedAt"] = generated, ["userLabel"] = "Owned recovery fixture" };
                }
                return html.Contains("name=\"recoveryCodeInput\"", StringComparison.Ordinal) ? new() { ["recoveryCodeInput"] = recovery[0] } : null;
            }
            check(await LoginAsync(new() { Action = "CONFIGURE_RECOVERY_AUTHN_CODES" }, Recovery) == user && recovery.Length >= 10
                && (await admin.User.CredentialsAsync(realm, user, ct)).Body!.Any(c => c.Type == "recovery-authn-codes"), "Recovery codes are generated and explicitly confirmed in the server-hosted action before their credential is persisted");
            await SetFlow("sdk-recovery");
            check(await LoginAsync(new() { RequiredAuthenticationCapabilities = [KeycloakAuthenticationCapability.RecoveryCodes] }, Recovery) == user,
                "A real one-time recovery code completes the configured second-factor login for the original verified user");
            bool replay = false;
            try { await LoginAsync(new() { RequiredAuthenticationCapabilities = [KeycloakAuthenticationCapability.RecoveryCodes] }, Recovery); } catch (InvalidDataException) { replay = true; }
            check(replay, "A consumed recovery code cannot authenticate a subsequent application login");
            await SetFlow("sdk-password"); await EnableAction("UPDATE_EMAIL");
            await using (var smtp = new ProtocolSmtpReceiver())
            {
                var emailRealm = (await admin.RealmAdmin.GetRealmAsync(realm, ct)).Body!;
                emailRealm.SmtpServer = new() { ["host"] = "127.0.0.1", ["port"] = ProtocolSmtpReceiver.Port.ToString(System.Globalization.CultureInfo.InvariantCulture), ["from"] = "issuer@example.invalid" };
                await admin.RealmAdmin.UpdateRealmAsync(realm, emailRealm, ct);
                await admin.AuthenticationManagement.UpdateRequiredActionConfigAsync(realm, "UPDATE_EMAIL", new() { Config = new() { ["verifyEmail"] = "true" } }, ct);
                using var emailHandler = new HttpClientHandler { AllowAutoRedirect = false, UseCookies = true }; using var emailBrowser = new HttpClient(emailHandler);
                var emailAction = await OidcLoginTransaction.StartAsync(oidc, auth, redirect, options: new() { Action = "UPDATE_EMAIL" }, cancellationToken: ct);
                bool submitted = false, pending = false;
                Dictionary<string, string>? EmailForm(string html)
                {
                    if (html.Contains("id=\"kc-update-email-form\"", StringComparison.Ordinal)) { submitted = true; return new() { ["email"] = "confirmed-auth@example.invalid" }; }
                    if (submitted) throw new EmailConfirmationPendingException(); return null;
                }
                try { await ProtocolBrowserFixture.LoginWithAuthenticatorAsync(emailAction.AuthorizationUri, redirect, "auth-user", password, EmailForm, ct, emailBrowser); }
                catch (EmailConfirmationPendingException) { pending = true; }
                var message = await smtp.ReceiveAsync(ct); var link = message.ActionLink(transport.Issuer);
                check(pending && message.Recipient.Contains("confirmed-auth@example.invalid", StringComparison.Ordinal)
                    && (await admin.User.GetUserAsync(realm, user, cancellationToken: ct)).Body!.Email == "auth@example.invalid",
                    "An application-initiated email update sends a bound confirmation to the new address while the independently observed account retains its old email");
                int tokenStart = link.AbsoluteUri.IndexOf("key=", StringComparison.Ordinal) + 4; char[] modified = link.AbsoluteUri.ToCharArray();
                modified[tokenStart] = modified[tokenStart] == 'A' ? 'B' : 'A'; var tampered = new Uri(new string(modified));
                using (var invalid = await emailBrowser.GetAsync(tampered, ct))
                    check((int)invalid.StatusCode >= 400 && (await admin.User.GetUserAsync(realm, user, cancellationToken: ct)).Body!.Email == "auth@example.invalid",
                        "A modified email action token cannot confirm or replace the account address");
                using (var confirmation = await emailBrowser.GetAsync(link, ct))
                    if (!confirmation.IsSuccessStatusCode) throw new InvalidDataException("The valid email action confirmation was refused.");
                var changed = (await admin.User.GetUserAsync(realm, user, cancellationToken: ct)).Body!;
                check(changed.Email == "confirmed-auth@example.invalid" && changed.EmailVerified == true
                    && await LoginAsync(new() { RequiredAuthenticationCapabilities = [KeycloakAuthenticationCapability.UpdateEmail] }, _ => null) == user,
                    "Only the valid email confirmation persists the verified target address and the next signature-verified login preserves the original account identity");
                using var duplicate = await emailBrowser.GetAsync(link, ct);
                check((int)duplicate.StatusCode >= 400 && (await admin.User.GetUserAsync(realm, user, cancellationToken: ct)).Body!.Email == "confirmed-auth@example.invalid",
                    "A consumed email confirmation action token is rejected on replay without another account change");
            }
            await SetFlow("browser");
            await ProtocolTransientUserWorkflows.RunAsync(admin, http, transport, realm, server, password, check, ct);
            await ProtocolKerberosWorkflows.RunAsync(admin, http, transport, realm, check, ct);
            await SetFlow("sdk-password");
            await ProtocolLegacySessionWorkflows.RunAsync(admin, transport, realm, user, password, check, ct);
            await SetFlow("browser");
            await ProtocolSocialWorkflows.RunAsync(admin, transport, realm, server, password, check, ct);
            foreach (var capability in Enum.GetValues<KeycloakAuthenticationCapability>())
            {
                string feature = "KeycloakSdk.Protocols.Authentication" + capability; flags[feature] = false; gate.Replace(flags); int before = RecordingHandler.SentCount; bool denied = false;
                try { await OidcLoginTransaction.StartAsync(oidc, auth, redirect, options: new() { RequiredAuthenticationCapabilities = [capability] }, cancellationToken: ct); }
                catch (InvalidOperationException e) when (e.Message.StartsWith("Protocol disabled by host:", StringComparison.Ordinal)) { denied = true; }
                check(denied && RecordingHandler.SentCount == before, "Closing the independent " + capability + " authentication flag prevents authorization initiation before protocol HTTP"); flags[feature] = true;
            }
        }
        finally { using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(30)); await admin.RealmAdmin.DeleteRealmAsync(realm, cleanup.Token); }
    }
    private static string Hidden(string html, string name)
    {
        var match = Regex.Match(html, "name=\"" + name + "\"[^>]*value=\"([^\"]*)\"", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
        if (!match.Success) throw new InvalidDataException("Pinned required-action field was absent."); return WebUtility.HtmlDecode(match.Groups[1].Value);
    }
    private sealed class EmailConfirmationPendingException : Exception;
}
