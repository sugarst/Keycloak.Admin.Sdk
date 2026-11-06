#if KEYCLOAK_HOSTING
using System.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml.Linq;
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Hosting;
using Keycloak.Admin.Sdk.Protocols;

internal static class ProtocolSamlWorkflows
{
    internal static async Task RunAsync(KeycloakAdminClient admin, HttpClient http, ProtocolTransport transport, string realm, string secret, Action<bool, string> check, CancellationToken ct)
    {
        var callback = new Uri("https://app.invalid/saml/callback");
        using var signingKey = RSA.Create(2048);
        using var signingCertificate = new CertificateRequest("CN=sdk-saml-sp", signingKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
        string publicCertificate = Convert.ToBase64String(signingCertificate.RawData);
        await admin.Clients.CreateClientAsync(realm, new ClientRepresentation { ClientId = "urn:sdk:saml", Protocol = "saml", Enabled = true, RedirectUris = [callback.AbsoluteUri],
            Attributes = new() { ["saml.assertion.signature"] = "true", ["saml.server.signature"] = "true", ["saml.client.signature"] = "true", ["saml.signing.certificate"] = publicCertificate,
                ["saml_name_id_format"] = "username", ["saml_single_logout_service_url_redirect"] = callback.AbsoluteUri } }, cancellationToken: ct);
        var certificates = await KeycloakSamlMetadata.LoadSigningCertificatesAsync(http, transport, allowLoopbackHttp: true, cancellationToken: ct);
        try
        {
            var provider = new KeycloakSamlServiceProvider(transport, "urn:sdk:saml", callback, certificates, new InMemoryDpopReplayStore(), signingCertificate);
            check(certificates.Count > 0 && XDocument.Parse(provider.CreateMetadata()).Root!.Attribute("entityID")!.Value == "urn:sdk:saml", "SAML metadata binds the exact realm signing trust SP identity and assertion-consumer endpoint");
            var transaction = await provider.StartLoginAsync(cancellationToken: ct);
            var form = await ProtocolBrowserFixture.LoginPostAsync(transaction.AuthorizationUri, callback, "account-user", secret, ct);
            var verified = await transaction.CompleteAsync(callback, form["SAMLResponse"], form["RelayState"], ct);
            check(verified.NameId == "account-user" && verified.Principal.Identity!.IsAuthenticated && !string.IsNullOrWhiteSpace(verified.SessionIndex), "SAML browser login verifies the real signed response assertion audience recipient lifetime and request correlation");
            bool replay = false, mismatch = false, tampering = false;
            try { await transaction.CompleteAsync(callback, form["SAMLResponse"], form["RelayState"], ct); } catch (InvalidDataException) { replay = true; }
            var unrelated = await provider.StartLoginAsync(cancellationToken: ct);
            try { await unrelated.CompleteAsync(callback, form["SAMLResponse"], form["RelayState"], ct); } catch (InvalidDataException) { mismatch = true; }
            var fresh = await provider.StartLoginAsync(cancellationToken: ct);
            var freshForm = await ProtocolBrowserFixture.LoginPostAsync(fresh.AuthorizationUri, callback, "account-user", secret, ct);
            string xml = Encoding.UTF8.GetString(Convert.FromBase64String(freshForm["SAMLResponse"]));
            var document = XDocument.Parse(xml, LoadOptions.PreserveWhitespace); XNamespace assertion = "urn:oasis:names:tc:SAML:2.0:assertion";
            document.Descendants(assertion + "NameID").Single().Value = "attacker";
            try { await fresh.CompleteAsync(callback, Convert.ToBase64String(Encoding.UTF8.GetBytes(document.ToString(SaveOptions.DisableFormatting))), freshForm["RelayState"], ct); } catch (InvalidDataException) { tampering = true; }
            check(replay && mismatch && tampering, "SAML rejects replay mismatched browser transactions and a tampered real signed assertion");
            var user = (await admin.Users.GetUsersAsync(realm, username: "account-user", exact: true, cancellationToken: ct)).Body!.Single();
            string sessionId = verified.SessionIndex!.Split("::", 2)[0];
            bool existed = (await admin.User.GetSessionsAsync(realm, user.Id!, ct)).Body!.Any(s => s.Id == sessionId);
            var logout = await provider.StartLogoutAsync(verified, ct);
            var logoutCallback = await ProtocolBrowserFixture.LoginAsync(logout.AuthorizationUri, callback, "unused", "unused", ct);
            await logout.CompleteRedirectAsync(logoutCallback.Callback, ct);
            check(existed && !(await admin.User.GetSessionsAsync(realm, user.Id!, ct)).Body!.Any(s => s.Id == sessionId), "SAML signed single logout validates the real redirect response and independently removes the bound Keycloak session");
            await admin.Clients.CreateClientAsync(realm, new ClientRepresentation { ClientId = "urn:sdk:saml-encrypted", Protocol = "saml", Enabled = true, RedirectUris = [callback.AbsoluteUri],
                Attributes = new() { ["saml.assertion.signature"] = "true", ["saml.server.signature"] = "true", ["saml.client.signature"] = "true", ["saml.signing.certificate"] = publicCertificate,
                    ["saml.encrypt"] = "true", ["saml.encryption.certificate"] = publicCertificate, ["saml_name_id_format"] = "username" } }, cancellationToken: ct);
            var encryptedProvider = new KeycloakSamlServiceProvider(transport, "urn:sdk:saml-encrypted", callback, certificates, new InMemoryDpopReplayStore(), signingCertificate, [signingCertificate]);
            var encryptedTransaction = await encryptedProvider.StartLoginAsync(cancellationToken: ct);
            var encryptedForm = await ProtocolBrowserFixture.LoginPostAsync(encryptedTransaction.AuthorizationUri, callback, "account-user", secret, ct);
            var encryptedDocument = XDocument.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(encryptedForm["SAMLResponse"])));
            bool ciphertext = encryptedDocument.Descendants(assertion + "EncryptedAssertion").Any() && !encryptedDocument.Descendants(assertion + "Assertion").Any();
            var encryptedIdentity = await encryptedTransaction.CompleteAsync(callback, encryptedForm["SAMLResponse"], encryptedForm["RelayState"], ct);
            check(ciphertext && encryptedIdentity.NameId == "account-user", "SAML decrypts an actually encrypted Keycloak assertion before validating its signed identity audience and recipient");
            var client = (await admin.Clients.GetClientsAsync(realm, clientId: "urn:sdk:saml", cancellationToken: ct)).Body!.Single();
            client.Attributes!["saml_assertion_consumer_url_post"] = callback.AbsoluteUri;
            client.Attributes["saml.force.post.binding"] = "false";
            client.Attributes["saml_assertion_consumer_url_redirect"] = callback.AbsoluteUri;
            client.Attributes["saml_idp_initiated_sso_url_name"] = "sdk-saml";
            await admin.Client.UpdateAsync(realm, client.Id!, client, ct);
            foreach (var requestBinding in new[] { SamlBrowserBinding.Redirect, SamlBrowserBinding.Post })
            foreach (var responseBinding in new[] { SamlBrowserBinding.Redirect, SamlBrowserBinding.Post })
            {
                var bound = await provider.StartLoginAsync(new SamlLoginOptions { RequestBinding = requestBinding, ResponseBinding = responseBinding }, ct);
                VerifiedSamlSession identity;
                if (requestBinding == SamlBrowserBinding.Post)
                {
                    var browser = await ProtocolBrowserFixture.LoginFromPostAsync(bound.AuthorizationUri, callback, bound.FormFields!, "account-user", secret, responseBinding == SamlBrowserBinding.Post, ct);
                    identity = browser.Form is null ? await bound.CompleteRedirectAsync(browser.Callback, ct) : await bound.CompleteAsync(callback, browser.Form["SAMLResponse"], browser.Form["RelayState"], ct);
                }
                else if (responseBinding == SamlBrowserBinding.Post)
                {
                    var browser = await ProtocolBrowserFixture.LoginPostAsync(bound.AuthorizationUri, callback, "account-user", secret, ct);
                    identity = await bound.CompleteAsync(callback, browser["SAMLResponse"], browser["RelayState"], ct);
                }
                else identity = await bound.CompleteRedirectAsync((await ProtocolBrowserFixture.LoginAsync(bound.AuthorizationUri, callback, "account-user", secret, ct)).Callback, ct);
                check(identity.NameId == "account-user" && identity.Principal.Identity!.IsAuthenticated,
                    "SAML " + requestBinding + " request and " + responseBinding + " response preserve signed identity and the original browser correlation");
            }
            var idpInitiated = await provider.StartIdpInitiatedLoginAsync("sdk-saml", ct);
            var idpForm = await ProtocolBrowserFixture.LoginPostAsync(idpInitiated.AuthorizationUri, callback, "account-user", secret, ct);
            check((await idpInitiated.CompleteAsync(callback, idpForm["SAMLResponse"], idpForm["RelayState"], ct)).NameId == "account-user",
                "An explicitly initiated IdP SSO URL retains a protected browser transaction without accepting an unsolicited assertion");
            client.Attributes["saml_artifact_binding_url"] = callback.AbsoluteUri; await admin.Client.UpdateAsync(realm, client.Id!, client, ct);
            foreach (var requestBinding in new[] { SamlBrowserBinding.Redirect, SamlBrowserBinding.Post })
            {
                var artifact = await provider.StartLoginAsync(new SamlLoginOptions { RequestBinding = requestBinding, ResponseBinding = SamlBrowserBinding.Artifact }, ct);
                IReadOnlyDictionary<string, string> fields;
                if (artifact.FormFields is not null)
                    fields = (await ProtocolBrowserFixture.LoginFromPostAsync(artifact.AuthorizationUri, callback, artifact.FormFields, "account-user", secret, true, ct)).Form!;
                else
                {
                    var browser = await ProtocolBrowserFixture.LoginAsync(artifact.AuthorizationUri, callback, "account-user", secret, ct);
                    fields = browser.Callback.Query.TrimStart('?').Split('&').Select(p => p.Split('=', 2)).ToDictionary(p => Uri.UnescapeDataString(p[0]), p => Uri.UnescapeDataString(p[1]));
                }
                var identity = await artifact.CompleteArtifactAsync(callback, fields["SAMLart"], fields["RelayState"], http, ct);
                check(identity.NameId == "account-user", "SAML " + requestBinding + " artifact delivery resolves a signed one-use SOAP response before verifying the original assertion and browser transaction");
            }
            client.Attributes["saml.allow.ecp.flow"] = "true"; await admin.Client.UpdateAsync(realm, client.Id!, client, ct);
            var ecp = await provider.AuthenticateEcpAsync(http, _ => ValueTask.FromResult(new System.Net.NetworkCredential("account-user", secret)), allowLoopbackHttp: true, cancellationToken: ct);
            check(ecp.NameId == "account-user" && ecp.Principal.Identity!.IsAuthenticated, "SAML ECP verifies its signed SOAP identity and exact assertion consumer endpoint using only per-call user credentials");
            bool wrongCredentials = false;
            try { await provider.AuthenticateEcpAsync(http, _ => ValueTask.FromResult(new System.Net.NetworkCredential("account-user", "incorrect-password")), allowLoopbackHttp: true, cancellationToken: ct); }
            catch (InvalidDataException) { wrongCredentials = true; }
            check(wrongCredentials, "SAML ECP rejects incorrect user credentials without yielding a local identity");
            var logoutProvider = new KeycloakSamlServiceProvider(transport, "urn:sdk:saml", callback, certificates, new InMemoryDpopReplayStore(), signingCertificate, singleLogoutService: ProtocolSamlLogoutReceiver.Endpoint);
            var localLogin = await logoutProvider.StartLoginAsync(cancellationToken: ct);
            var localForm = await ProtocolBrowserFixture.LoginPostAsync(localLogin.AuthorizationUri, callback, "account-user", secret, ct);
            var local = await localLogin.CompleteAsync(callback, localForm["SAMLResponse"], localForm["RelayState"], ct);
            await using (var receiver = new ProtocolSamlLogoutReceiver(logoutProvider, local) { FailStorage = true })
            {
                client.Attributes["saml_single_logout_service_url_soap"] = ProtocolSamlLogoutReceiver.Endpoint.AbsoluteUri;
                client.FrontchannelLogout = false;
                await admin.Client.UpdateAsync(realm, client.Id!, client, ct);
                await admin.User.LogoutAsync(realm, user.Id!, ct);
                Console.WriteLine($"SAML logout fixture: failures={receiver.Failures}; successes={receiver.Successes}; captured={receiver.CapturedSoap is not null}; active={receiver.Persisted().Active}; effects={receiver.Persisted().Effects}");
                check(receiver.Failures > 0 && receiver.Persisted().Active && receiver.Persisted().Effects == 0 && receiver.CapturedSoap is not null,
                    "A real IdP SOAP logout cannot acknowledge or reserve its replay receipt when local session storage fails");
                receiver.FailStorage = false;
                string reply = await logoutProvider.HandleLogoutSoapAsync(ProtocolSamlLogoutReceiver.Endpoint, receiver.CapturedSoap!, receiver, ct);
                await logoutProvider.HandleLogoutSoapAsync(ProtocolSamlLogoutReceiver.Endpoint, receiver.CapturedSoap!, receiver, ct);
                var persisted = receiver.Persisted();
                check(!persisted.Active && persisted.Effects == 1 && XDocument.Parse(reply).Descendants(XName.Get("Signature", "http://www.w3.org/2000/09/xmldsig#")).Any(),
                    "Retrying a verified IdP SOAP logout atomically persists exactly one local session revocation before returning its signed correlated response");
            }
            client.Attributes.Remove("saml_single_logout_service_url_soap");
            client.Attributes["saml_force_name_id_format"] = "true";
            foreach (string format in new[] { "persistent", "transient", "email" })
            {
                client.Attributes["saml_name_id_format"] = format; await admin.Client.UpdateAsync(realm, client.Id!, client, ct);
                async Task<VerifiedSamlSession> LoginNameId()
                {
                    var next = await provider.StartLoginAsync(cancellationToken: ct);
                    var browser = await ProtocolBrowserFixture.LoginPostAsync(next.AuthorizationUri, callback, "account-user", secret, ct);
                    return await next.CompleteAsync(callback, browser["SAMLResponse"], browser["RelayState"], ct);
                }
                var first = await LoginNameId(); var second = await LoginNameId();
                string expectedFormat = format == "email" ? "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" : "urn:oasis:names:tc:SAML:2.0:nameid-format:" + format;
                check(first.NameIdFormat == expectedFormat && second.NameIdFormat == expectedFormat &&
                    (format == "persistent" ? first.NameId == second.NameId : format == "transient" ? first.NameId != second.NameId : first.NameId == "protocols@example.invalid"),
                    "SAML " + format + " NameID retains its verified format and server-defined identity lifecycle without assuming every subject is a username");
            }
            client.Attributes["saml_single_logout_service_url_post"] = callback.AbsoluteUri; await admin.Client.UpdateAsync(realm, client.Id!, client, ct);
            var postLogin = await provider.StartLoginAsync(cancellationToken: ct);
            var postLoginForm = await ProtocolBrowserFixture.LoginPostAsync(postLogin.AuthorizationUri, callback, "account-user", secret, ct);
            var postSession = await postLogin.CompleteAsync(callback, postLoginForm["SAMLResponse"], postLoginForm["RelayState"], ct);
            var postLogout = await provider.StartLogoutAsync(postSession, SamlBrowserBinding.Post, ct);
            var postLogoutResponse = await ProtocolBrowserFixture.LoginFromPostAsync(postLogout.AuthorizationUri, callback, postLogout.FormFields!, "unused", "unused", true, ct);
            await postLogout.CompletePostAsync(callback, postLogoutResponse.Form!["SAMLResponse"], postLogoutResponse.Form["RelayState"], ct);
            check(!(await admin.User.GetSessionsAsync(realm, user.Id!, ct)).Body!.Any(s => s.Id == postSession.SessionIndex!.Split("::", 2)[0]),
                "SAML signed POST single logout verifies its correlated POST response and removes the independently observed Keycloak session");
            await ProtocolSamlAssuranceWorkflows.RunAsync(admin, http, transport, realm, secret, signingCertificate, check, ct);
        }
        finally { foreach (var certificate in certificates) certificate.Dispose(); }
    }
}
#endif
