#if KEYCLOAK_HOSTING
using System.Net;
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Capabilities;
using Keycloak.Admin.Sdk.Hosting;
using Keycloak.Admin.Sdk.Protocols;

internal static class ProtocolSamlAssuranceWorkflows
{
    internal static async Task RunAsync(KeycloakAdminClient admin, HttpClient http, ProtocolTransport parent, string realm, string password,
        System.Security.Cryptography.X509Certificates.X509Certificate2 signingCertificate, Action<bool, string> check, CancellationToken ct)
    {
        await using var fixture = await ProtocolAssuranceFixture.CreateAsync(admin, realm, password, ct);
        var server = new Uri(parent.Issuer.AbsoluteUri[..parent.Issuer.AbsoluteUri.IndexOf("/realms/", StringComparison.Ordinal)] + "/");
        var gate = new KeycloakFeatureSnapshotGate(new Dictionary<string, bool> { ["KeycloakSdk.Protocols"] = true, ["KeycloakSdk.Protocols.Saml"] = true, ["KeycloakSdk.Protocols.SamlStepUp"] = true });
        var transport = new ProtocolTransport(http, server, fixture.Realm, gate); var callback = new Uri("https://app.invalid/saml/step-up");
        const string entity = "urn:sdk:saml-assurance";
        await admin.Clients.CreateClientAsync(fixture.Realm, new() { ClientId = entity, Protocol = "saml", Enabled = true, RedirectUris = [callback.AbsoluteUri],
            Attributes = new() { ["saml.assertion.signature"] = "true", ["saml.server.signature"] = "true", ["saml.force.post.binding"] = "true", ["saml_name_id_format"] = "username",
                ["saml.client.signature"] = "true", ["saml.signing.certificate"] = Convert.ToBase64String(signingCertificate.RawData),
                ["acr.loa.map"] = "{\"urn:sdk:loa:1\":1,\"urn:sdk:loa:2\":2}" },
            ProtocolMappers = [new() { Name = "achieved-assurance", Protocol = "saml", ProtocolMapper = "saml-authn-context-class-ref-mapper", Config = [] }] }, cancellationToken: ct);
        var certificates = await KeycloakSamlMetadata.LoadSigningCertificatesAsync(http, transport, allowLoopbackHttp: true, cancellationToken: ct);
        try
        {
            var provider = new KeycloakSamlServiceProvider(transport, entity, callback, certificates, new InMemoryDpopReplayStore(), signingCertificate);
            using var browser = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false, UseCookies = true });
            var low = await provider.StartLoginAsync(authenticationContexts: [new("urn:sdk:loa:1")], cancellationToken: ct);
            var first = await ProtocolBrowserFixture.LoginWithOtpAsync(low.AuthorizationUri, callback, ProtocolAssuranceFixture.Username, password, fixture.CurrentOtpAsync, true, browser, ct);
            var firstIdentity = await low.CompleteAsync(callback, first.Form!["SAMLResponse"], first.Form["RelayState"], ct);
            check(firstIdentity.AuthenticationContext == "urn:sdk:loa:1" && first.PasswordChallenges == 1 && first.OtpChallenges == 0,
                "SAML assurance level one is verified from an actual signed authentication context after password-only login");
            var high = await provider.StartLoginAsync(authenticationContexts: [new("urn:sdk:loa:2")], cancellationToken: ct);
            var second = await ProtocolBrowserFixture.LoginWithOtpAsync(high.AuthorizationUri, callback, ProtocolAssuranceFixture.Username, password, fixture.CurrentOtpAsync, true, browser, ct);
            var secondIdentity = await high.CompleteAsync(callback, second.Form!["SAMLResponse"], second.Form["RelayState"], ct);
            check(secondIdentity.NameId == firstIdentity.NameId && secondIdentity.AuthenticationContext == "urn:sdk:loa:2" && second.PasswordChallenges == 0 && second.OtpChallenges == 1,
                "SAML step-up reuses the original browser session but requires a real OTP challenge before its signed context can attain level two");
            bool unmapped = false;
            try
            {
                var unsupported = await provider.StartLoginAsync(authenticationContexts: [new("urn:sdk:loa:3")], cancellationToken: ct);
                var response = await ProtocolBrowserFixture.LoginWithOtpAsync(unsupported.AuthorizationUri, callback, ProtocolAssuranceFixture.Username, password, fixture.CurrentOtpAsync, true, browser, ct);
                await unsupported.CompleteAsync(callback, response.Form!["SAMLResponse"], response.Form["RelayState"], ct);
            }
            catch (InvalidDataException) { unmapped = true; }
            check(unmapped, "SAML refuses a requested authentication context absent from the server assurance mapping instead of substituting a lower signed context");
            bool wrongOtp = false;
            try
            {
                var forced = await provider.StartLoginAsync(true, [new("urn:sdk:loa:2")], ct);
                async ValueTask<string> Wrong(CancellationToken token) => await fixture.CurrentOtpAsync(token) == "000000" ? "000001" : "000000";
                var response = await ProtocolBrowserFixture.LoginWithOtpAsync(forced.AuthorizationUri, callback, ProtocolAssuranceFixture.Username, password, Wrong, true, browser, ct);
                await forced.CompleteAsync(callback, response.Form!["SAMLResponse"], response.Form["RelayState"], ct);
            }
            catch (InvalidDataException) { wrongOtp = true; }
            check(wrongOtp, "Forced SAML level-two authentication cannot turn an incorrect OTP into a local verified identity");
            gate.Replace(new Dictionary<string, bool> { ["KeycloakSdk.Protocols"] = true, ["KeycloakSdk.Protocols.Saml"] = true });
            bool closed = false;
            try { await provider.StartLoginAsync(authenticationContexts: [new("urn:sdk:loa:2")], cancellationToken: ct); } catch (InvalidOperationException) { closed = true; }
            check(closed, "Closing the SAML step-up host flag blocks assurance initiation independently of ordinary SAML login");
        }
        finally { foreach (var certificate in certificates) certificate.Dispose(); }
    }
}
#endif
