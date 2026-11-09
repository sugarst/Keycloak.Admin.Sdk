using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Capabilities;
using Keycloak.Admin.Sdk.Protocols;

internal static class ProtocolOidcAssuranceWorkflows
{
    internal static async Task RunAsync(KeycloakAdminClient admin, HttpClient http, ProtocolTransport parent, string realm, string password, Action<bool, string> check, CancellationToken ct)
    {
        await using var fixture = await ProtocolAssuranceFixture.CreateAsync(admin, realm, password, ct);
        var server = new Uri(parent.Issuer.AbsoluteUri[..parent.Issuer.AbsoluteUri.IndexOf("/realms/", StringComparison.Ordinal)] + "/");
        var enabled = new Dictionary<string, bool> { ["KeycloakSdk.Protocols"] = true, ["KeycloakSdk.Protocols.Oidc"] = true, ["KeycloakSdk.Protocols.OidcAssurance"] = true };
        var gate = new KeycloakFeatureSnapshotGate(enabled); var transport = new ProtocolTransport(http, server, fixture.Realm, gate); var oidc = new OidcClient(transport);
        var callback = new Uri("https://app.invalid/assurance"); const string id = "assurance-app";
        await fixture.CreateOidcClientAsync(id, callback, null, ct); var client = OAuthClientAuthentication.Public(id); var validator = new OidcTokenValidator(oidc, id);
        using var browser = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false, UseCookies = true });
        var lowPolicy = new OidcAssuranceRequirement(["urn:sdk:loa:1"], TimeSpan.FromMinutes(5), ["pwd"]);
        var low = await OidcLoginTransaction.StartAsync(oidc, client, callback, options: new() { RequiredAssurance = lowPolicy }, cancellationToken: ct);
        var lowBrowser = await ProtocolBrowserFixture.LoginWithOtpAsync(low.AuthorizationUri, callback, ProtocolAssuranceFixture.Username, password, fixture.CurrentOtpAsync, false, browser, ct);
        var lowIdentity = await low.CompleteAsync(lowBrowser.Callback, client, validator, ct);
        check(lowIdentity.Identity.Subject == fixture.UserId && lowBrowser.PasswordChallenges == 1 && lowBrowser.OtpChallenges == 0,
            "OIDC required assurance verifies the signed password context auth_time and actual pwd method for the independently observed user");
        var clock = new AssuranceClock(); var highPolicy = new OidcAssuranceRequirement(["urn:sdk:loa:2"], TimeSpan.FromMinutes(5), ["pwd", "otp"], clock);
        bool lower = false; try { highPolicy.Validate(lowIdentity.Identity); } catch (InvalidDataException) { lower = true; }
        check(lower, "A correctly signed password-only OIDC identity cannot satisfy an application requirement for level two and OTP");
        var high = await OidcLoginTransaction.StartAsync(oidc, client, callback, options: new() { RequiredAssurance = highPolicy }, cancellationToken: ct);
        var highBrowser = await ProtocolBrowserFixture.LoginWithOtpAsync(high.AuthorizationUri, callback, ProtocolAssuranceFixture.Username, password, fixture.CurrentOtpAsync, false, browser, ct);
        var highIdentity = await high.CompleteAsync(highBrowser.Callback, client, validator, ct);
        check(highIdentity.Identity.Subject == fixture.UserId && highBrowser.PasswordChallenges == 0 && highBrowser.OtpChallenges == 1,
            "OIDC step-up retains its original user and browser session but requires a real OTP before signed acr and amr can satisfy level two");
        clock.Now += TimeSpan.FromMinutes(6); bool stale = false;
        try { highPolicy.Validate(highIdentity.Identity); } catch (InvalidDataException) { stale = true; }
        check(stale, "An already verified OIDC identity expires against signed auth_time independently of a newly issued token or an existing application session");
        bool hardware = false;
        try { new OidcAssuranceRequirement(requiredMethods: ["hwk"]).Validate(highIdentity.Identity); } catch (InvalidDataException) { hardware = true; }
        check(hardware, "A real password-and-OTP ID token cannot invent the hardware authentication method required by a stronger application policy");
        enabled["KeycloakSdk.Protocols.OidcAssurance"] = false; gate.Replace(enabled); int credentials = 0, before = RecordingHandler.SentCount; bool closed = false;
        try { await OidcLoginTransaction.StartAsync(oidc, OAuthClientAuthentication.SecretPost(id, _ => { credentials++; return ValueTask.FromResult(password); }), callback, options: new() { RequiredAssurance = highPolicy }, cancellationToken: ct); }
        catch (InvalidOperationException) { closed = true; }
        check(closed && credentials == 0 && before == RecordingHandler.SentCount,
            "Closing the OIDC assurance host flag prevents a new assurance transaction before reading client credentials or sending any protocol request");
    }
    internal sealed class AssuranceClock : TimeProvider
    {
        private TimeSpan offset;
        internal DateTimeOffset Now { get => DateTimeOffset.UtcNow + offset; set => offset = value - DateTimeOffset.UtcNow; }
        public override DateTimeOffset GetUtcNow() => Now;
    }
}
