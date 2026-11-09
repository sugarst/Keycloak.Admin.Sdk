#if KEYCLOAK_HOSTING
using System.Collections.Concurrent;
using System.Net;
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Capabilities;
using Keycloak.Admin.Sdk.Hosting;
using Keycloak.Admin.Sdk.Protocols;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

internal static class ProtocolHostAssuranceWorkflows
{
    internal static async Task RunAsync(KeycloakAdminClient admin, HttpClient http, ProtocolTransport parent, string realm, string password, Action<bool, string> check, CancellationToken ct)
    {
        await using var fixture = await ProtocolAssuranceFixture.CreateAsync(admin, realm + "-host", password, ct);
        var server = new Uri(parent.Issuer.AbsoluteUri[..parent.Issuer.AbsoluteUri.IndexOf("/realms/", StringComparison.Ordinal)] + "/");
        var enabled = new Dictionary<string, bool> { ["KeycloakSdk.Protocols"] = true, ["KeycloakSdk.Protocols.Oidc"] = true, ["KeycloakSdk.Protocols.BrowserOidc"] = true,
            ["KeycloakSdk.Protocols.OidcAssurance"] = true, ["KeycloakSdk.Protocols.BrowserOidcAssurance"] = true };
        var gate = new KeycloakFeatureSnapshotGate(enabled); var transport = new ProtocolTransport(http, server, fixture.Realm, gate);
        var host = new Uri("http://127.0.0.1:18086/"); var callback = new Uri(host, "signin-assurance"); const string clientId = "host-assurance";
        await fixture.CreateOidcClientAsync(clientId, callback, password, ct);
        var clock = new ProtocolOidcAssuranceWorkflows.AssuranceClock(); var requirement = new OidcAssuranceRequirement(["urn:sdk:loa:2"], TimeSpan.FromMinutes(5), ["pwd", "otp"], clock);
        var tickets = new Tickets(); int credentials = 0;
        var client = OAuthClientAuthentication.SecretBasic(clientId, _ => { credentials++; return ValueTask.FromResult(password); });
        var builder = WebApplication.CreateSlimBuilder(); builder.Logging.ClearProviders(); builder.WebHost.UseUrls(host.AbsoluteUri);
        builder.Services.AddDataProtection().UseEphemeralDataProtectionProvider(); builder.Services.AddAuthorization();
        builder.Services.AddAuthentication(options => { options.DefaultAuthenticateScheme = "assurance.cookie"; options.DefaultChallengeScheme = "assurance"; })
            .AddKeycloakWebApp("assurance", transport, client, tickets, new InMemoryKeycloakLogoutStore(), allowLoopbackHttp: true, requiredAssurance: requirement);
        await using var app = builder.Build(); app.UseExceptionHandler(error => error.Run(context => { context.Response.StatusCode = 503; return Task.CompletedTask; }));
        app.UseAuthentication(); app.UseAuthorization();
        app.MapGet("/login", async context => await context.ChallengeAsync("assurance", new AuthenticationProperties { RedirectUri = "/session" }));
        app.MapGet("/session", (HttpContext context) => context.Response.WriteAsync(context.User.FindFirst("sub")!.Value, context.RequestAborted))
            .RequireAuthorization(new Microsoft.AspNetCore.Authorization.AuthorizeAttribute { AuthenticationSchemes = "assurance.cookie" });
        await app.StartAsync(ct);
        try
        {
            using var browser = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false, UseCookies = true });
            using var lowChallenge = await browser.GetAsync(new Uri(host, "login"), ct); var original = lowChallenge.Headers.Location!;
            var parameters = QueryHelpers.ParseQuery(original.Query).ToDictionary(p => p.Key, p => (string?)p.Value.ToString()); parameters["acr_values"] = "urn:sdk:loa:1";
            var altered = new Uri(QueryHelpers.AddQueryString(original.GetLeftPart(UriPartial.Path), parameters));
            var low = await ProtocolBrowserFixture.LoginWithOtpAsync(altered, callback, ProtocolAssuranceFixture.Username, password, fixture.CurrentOtpAsync, false, browser, ct);
            using var rejected = await browser.GetAsync(low.Callback, ct);
            check(rejected.StatusCode == HttpStatusCode.BadRequest && tickets.Count == 0,
                "Host OIDC rejects a real lower-assurance signed ID token even when the browser changes acr_values while preserving valid protected correlation");
            using var highChallenge = await browser.GetAsync(new Uri(host, "login"), ct);
            var high = await ProtocolBrowserFixture.LoginWithOtpAsync(highChallenge.Headers.Location!, callback, ProtocolAssuranceFixture.Username, password, fixture.CurrentOtpAsync, false, browser, ct);
            using var accepted = await browser.GetAsync(high.Callback, ct); using var session = await browser.GetAsync(new Uri(host, "session"), ct);
            check(accepted.StatusCode == HttpStatusCode.Redirect && session.IsSuccessStatusCode && await session.Content.ReadAsStringAsync(ct) == fixture.UserId && tickets.Count == 1 && high.OtpChallenges == 1,
                "Host OIDC creates its opaque server ticket only after a real OTP and signed acr auth_time and amr satisfy the application policy");
            clock.Now += TimeSpan.FromMinutes(6);
            using var stale = await browser.GetAsync(new Uri(host, "session"), ct);
            check(stale.StatusCode == HttpStatusCode.Unauthorized && tickets.Count == 0,
                "A local host cookie cannot outlive the mandatory signed authentication freshness even while its application ticket has remaining lifetime");
            enabled["KeycloakSdk.Protocols.BrowserOidcAssurance"] = false; gate.Replace(enabled); int before = RecordingHandler.SentCount, reads = credentials;
            using var closed = await browser.GetAsync(new Uri(host, "login"), ct);
            check(closed.StatusCode == HttpStatusCode.ServiceUnavailable && credentials == reads && before == RecordingHandler.SentCount,
                "Closing host OIDC assurance blocks its next challenge before metadata HTTP or client credential access independently of ordinary browser login");
        }
        finally { using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(10)); await app.StopAsync(stop.Token); }
    }
    private sealed class Tickets : ITicketStore
    {
        private readonly ConcurrentDictionary<string, AuthenticationTicket> tickets = new(StringComparer.Ordinal);
        internal int Count => tickets.Count;
        public Task<string> StoreAsync(AuthenticationTicket ticket) { string key = Guid.NewGuid().ToString("N"); tickets[key] = ticket; return Task.FromResult(key); }
        public Task RenewAsync(string key, AuthenticationTicket ticket) { tickets[key] = ticket; return Task.CompletedTask; }
        public Task<AuthenticationTicket?> RetrieveAsync(string key) => Task.FromResult(tickets.TryGetValue(key, out var ticket) ? ticket : null);
        public Task RemoveAsync(string key) { tickets.TryRemove(key, out _); return Task.CompletedTask; }
    }
}
#endif
