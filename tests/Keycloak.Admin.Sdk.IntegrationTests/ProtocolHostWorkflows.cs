#if KEYCLOAK_HOSTING
using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Hosting;
using Keycloak.Admin.Sdk.Protocols;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;

internal static class ProtocolHostWorkflows
{
    internal static async Task RunAsync(KeycloakAdminClient admin, ProtocolTransport transport, string realm, string secret, Action<bool, string> check, CancellationToken ct)
    {
        const string scheme = "host"; var host = new Uri("http://127.0.0.1:18082/"); var callback = new Uri(host, "signin-host");
        // This workflow deliberately logs out every session of its user; isolate it from Account/UMA fixtures.
        await admin.Users.CreateUserAsync(realm, new UserRepresentation { Username = "host-user", FirstName = "Host", LastName = "User", Email = "host@example.invalid", EmailVerified = true,
            Enabled = true, Credentials = [new() { Type = "password", Value = secret, Temporary = false }] }, cancellationToken: ct);
        await admin.Clients.CreateClientAsync(realm, new ClientRepresentation { ClientId = "host-app", Enabled = true, Protocol = "openid-connect", PublicClient = false,
            Secret = secret, StandardFlowEnabled = true, DirectAccessGrantsEnabled = true, RedirectUris = [callback.AbsoluteUri],
            Attributes = new() { ["backchannel.logout.url"] = new Uri(host, "backchannel").AbsoluteUri, ["backchannel.logout.session.required"] = "true", ["post.logout.redirect.uris"] = new Uri(host, "signout-callback-host").AbsoluteUri },
            ProtocolMappers = [new() { Name = "resource", Protocol = "openid-connect", ProtocolMapper = "oidc-audience-mapper", Config = new() { ["included.custom.audience"] = new Uri(host, "mcp").AbsoluteUri, ["access.token.claim"] = "true" } }] }, cancellationToken: ct);
        var builder = WebApplication.CreateSlimBuilder(); builder.Logging.ClearProviders(); builder.WebHost.UseUrls(host.AbsoluteUri);
        builder.Services.AddDataProtection().UseEphemeralDataProtectionProvider(); builder.Services.AddAuthorization();
        var logout = new InMemoryKeycloakLogoutStore(); var tickets = new Tickets(); var authentication = OAuthClientAuthentication.SecretBasic("host-app", _ => ValueTask.FromResult(secret));
        builder.Services.AddAuthentication(options => { options.DefaultAuthenticateScheme = scheme + ".cookie"; options.DefaultChallengeScheme = scheme; })
            .AddKeycloakWebApp(scheme, transport, authentication, tickets, logout, allowLoopbackHttp: true)
            .AddKeycloakBearer("api", transport, new Uri(host, "mcp").AbsoluteUri, allowLoopbackHttp: true);
        await using var app = builder.Build(); app.UseExceptionHandler(error => error.Run(context => { context.Response.StatusCode = 503; return Task.CompletedTask; }));
        app.UseAuthentication(); app.UseAuthorization();
        app.MapGet("/login", async context => await context.ChallengeAsync(scheme, new AuthenticationProperties { RedirectUri = "/session" }));
        app.MapGet("/session", (HttpContext context) => context.Response.WriteAsync(context.User.FindFirst("sub")!.Value, context.RequestAborted)).RequireAuthorization();
        app.MapGet("/mcp", (HttpContext context) => { context.Response.StatusCode = 204; return Task.CompletedTask; }).RequireAuthorization(new Microsoft.AspNetCore.Authorization.AuthorizeAttribute { AuthenticationSchemes = "api" });
        app.MapKeycloakBackchannelLogout("/backchannel", transport, "host-app", logout);
        var resource = new KeycloakProtectedResource(transport, new(host, "mcp"), ["openid", "tools:read"], allowLoopbackHttp: true); resource.MapMetadata(app);
        app.MapGet("/challenge", (HttpContext context) => { context.Response.Headers.WWWAuthenticate = resource.Challenge; context.Response.StatusCode = 401; return Task.CompletedTask; });
        await app.StartAsync(ct);
        string? rotationComponentId = null;
        try
        {
            using (var nonceHandler = new HttpClientHandler { AllowAutoRedirect = false, UseCookies = true })
            using (var nonceBrowser = new HttpClient(nonceHandler))
            {
                using var initial = await nonceBrowser.GetAsync(new Uri(host, "login"), ct);
                var pending = await ProtocolBrowserFixture.LoginAsync(initial.Headers.Location!, callback, "host-user", secret, ct, nonceBrowser);
                using var strippedHandler = new HttpClientHandler { AllowAutoRedirect = false, UseCookies = true }; bool removed = false;
                foreach (Cookie pendingCookie in nonceHandler.CookieContainer.GetCookies(callback))
                {
                    if (pendingCookie.Name.Contains(".OpenIdConnect.Nonce.", StringComparison.Ordinal)) { removed = true; continue; }
                    strippedHandler.CookieContainer.Add(new Cookie(pendingCookie.Name, pendingCookie.Value, pendingCookie.Path, pendingCookie.Domain) { Secure = pendingCookie.Secure, HttpOnly = pendingCookie.HttpOnly });
                }
                using var stripped = new HttpClient(strippedHandler); using var deniedNonce = await stripped.GetAsync(pending.Callback, ct);
                check(removed && deniedNonce.StatusCode == HttpStatusCode.BadRequest && tickets.Count == 0,
                    "Host custom code redemption refuses a real signed callback that retains protected correlation but loses its initiating nonce cookie");
            }
            using var handler = new HttpClientHandler { AllowAutoRedirect = false, UseCookies = true }; using var browser = new HttpClient(handler);
            using var challenge = await browser.GetAsync(new Uri(host, "login"), ct); var authorize = challenge.Headers.Location!;
            var query = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(authorize.Query);
            check(challenge.StatusCode == HttpStatusCode.Redirect && query["response_type"] == "code" && query["code_challenge_method"] == "S256" && query.ContainsKey("nonce")
                && challenge.Headers.GetValues("Set-Cookie").All(v => !v.Contains(secret, StringComparison.Ordinal)), "Host OIDC challenge uses PKCE nonce and protected browser correlation without disclosing a client secret");
            var completed = await ProtocolBrowserFixture.LoginAsync(authorize, callback, "host-user", secret, ct, browser);
            using var wrongBrowser = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false });
            using var missingCorrelation = await wrongBrowser.GetAsync(completed.Callback, ct);
            check(missingCorrelation.StatusCode == HttpStatusCode.BadRequest && tickets.Count == 0, "Host OIDC rejects a real callback without its initiating browser correlation cookie");
            using var accepted = await browser.GetAsync(completed.Callback, ct); accepted.EnsureSuccessOrRedirect();
            var actual = (await admin.Users.GetUsersAsync(realm, username: "host-user", exact: true, cancellationToken: ct)).Body!.Single();
            using var session = await browser.GetAsync(new Uri(host, "session"), ct);
            bool correctUser = await session.Content.ReadAsStringAsync(ct) == actual.Id;
            Console.WriteLine($"Host fixture session: status={(int)session.StatusCode}; tickets={tickets.Count}; expected-user={correctUser}; cookie-present={handler.CookieContainer.GetCookies(host).Count != 0}");
            check(session.IsSuccessStatusCode && correctUser && tickets.Count == 1, "Host OIDC completes a real signed Keycloak login and stores the authenticated ticket on the server");
            string cookie = handler.CookieContainer.GetCookieHeader(host);
            check(!cookie.Contains("eyJ", StringComparison.Ordinal) && !cookie.Contains(secret, StringComparison.Ordinal), "Host browser cookie contains an opaque protected ticket reference rather than ID access or refresh tokens");
            using var replay = await browser.GetAsync(completed.Callback, ct);
            check(replay.StatusCode == HttpStatusCode.BadRequest, "Host OIDC callback replay cannot create a second authenticated ticket");
            var oidc = new OidcClient(transport); var tokens = await oidc.PasswordGrantAsync(authentication, "host-user", secret, scope: "openid", cancellationToken: ct);
            using var bearer = new HttpRequestMessage(HttpMethod.Get, new Uri(host, "mcp")); bearer.Headers.Authorization = new("Bearer", tokens.Json!.Value.GetProperty("access_token").GetString());
            using var allowed = await browser.SendAsync(bearer, ct);
            using var wrongToken = new HttpRequestMessage(HttpMethod.Get, new Uri(host, "mcp")); wrongToken.Headers.Authorization = new("Bearer", tokens.Json.Value.GetProperty("id_token").GetString());
            using var denied = await browser.SendAsync(wrongToken, ct);
            check(allowed.StatusCode == HttpStatusCode.NoContent && denied.StatusCode == HttpStatusCode.Unauthorized, "Host resource authentication accepts the exact verified audience and refuses ID-token substitution");
            var priorKeys = (await admin.Component.GetComponentsAsync(realm, providerId: "rsa-generated", cancellationToken: ct)).Body!.Where(c => c.Config?.GetValueOrDefault("enabled")?.FirstOrDefault() != "false").ToArray();
            var realmSettings = (await admin.RealmAdmin.GetRealmAsync(realm, cancellationToken: ct)).Body!;
            await admin.Component.CreateAsync(realm, new() { Name = "host-key-rotation", ProviderId = "rsa-generated", ProviderType = "org.keycloak.keys.KeyProvider", ParentId = realmSettings.Id,
                Config = new() { ["priority"] = ["1000"], ["active"] = ["true"], ["enabled"] = ["true"], ["algorithm"] = ["RS256"], ["keySize"] = ["2048"] } }, ct);
            rotationComponentId = (await admin.Component.GetComponentsAsync(realm, name: "host-key-rotation", cancellationToken: ct)).Body!.Single().Id!;
            var rotatedTokens = await oidc.PasswordGrantAsync(authentication, "host-user", secret, scope: "openid", cancellationToken: ct);
            string oldToken = tokens.Json.Value.GetProperty("access_token").GetString()!, rotatedToken = rotatedTokens.Json!.Value.GetProperty("access_token").GetString()!;
            using var rotatedCall = new HttpRequestMessage(HttpMethod.Get, new Uri(host, "mcp")); rotatedCall.Headers.Authorization = new("Bearer", rotatedToken);
            using var rotatedReply = await browser.SendAsync(rotatedCall, ct);
            check(new JsonWebToken(oldToken).Kid != new JsonWebToken(rotatedToken).Kid && rotatedReply.StatusCode == HttpStatusCode.NoContent,
                "Host resource authentication refreshes pinned realm JWKS and accepts an actually rotated Keycloak signing key");
            try
            {
                foreach (var component in priorKeys) { component.Config!["enabled"] = ["false"]; await admin.Component.UpdateComponentAsync(realm, component.Id!, component, ct); }
                using var retiredCall = new HttpRequestMessage(HttpMethod.Get, new Uri(host, "mcp")); retiredCall.Headers.Authorization = new("Bearer", oldToken);
                using var retiredReply = await browser.SendAsync(retiredCall, ct);
                check(retiredReply.StatusCode == HttpStatusCode.Unauthorized, "Host resource authentication stops trusting a retired Keycloak signing key even for a previously valid unexpired token");
            }
            finally { foreach (var component in priorKeys) { component.Config!["enabled"] = ["true"]; await admin.Component.UpdateComponentAsync(realm, component.Id!, component, ct); } }
            using var metadata = await browser.GetAsync(resource.MetadataUri, ct); using var document = JsonDocument.Parse(await metadata.Content.ReadAsStringAsync(ct));
            using var unauthorized = await browser.GetAsync(new Uri(host, "challenge"), ct);
            check(document.RootElement.GetProperty("resource").GetString() == new Uri(host, "mcp").AbsoluteUri
                && document.RootElement.GetProperty("authorization_servers")[0].GetString() == transport.Issuer.AbsoluteUri
                && unauthorized.Headers.WwwAuthenticate.ToString().Contains(resource.MetadataUri.AbsoluteUri, StringComparison.Ordinal), "MCP protected-resource metadata and Bearer challenge advertise the exact resource and pinned Keycloak authorization server");
            using var forged = await browser.PostAsync(new Uri(host, "backchannel"), new FormUrlEncodedContent(new Dictionary<string, string> { ["logout_token"] = "forged.jwt.value" }), ct);
            using var survived = await browser.GetAsync(new Uri(host, "session"), ct);
            check(forged.StatusCode == HttpStatusCode.BadRequest && survived.IsSuccessStatusCode, "Host back-channel logout rejects an unsigned forged notification without invalidating the victim session");
            using var wrongSession = await browser.GetAsync(new Uri(host, "frontchannel-host?iss=" + Uri.EscapeDataString(transport.Issuer.AbsoluteUri) + "&sid=unrelated"), ct);
            using var notLoggedOut = await browser.GetAsync(new Uri(host, "session"), ct);
            check(notLoggedOut.IsSuccessStatusCode && tickets.Count == 1, "Host front-channel logout refuses an issuer query targeting an unrelated browser session");
            string sid = tickets.SessionId;
            using var frontchannel = await browser.GetAsync(new Uri(host, "frontchannel-host?iss=" + Uri.EscapeDataString(transport.Issuer.AbsoluteUri) + "&sid=" + Uri.EscapeDataString(sid)), ct);
            check(tickets.Count == 0, "Host front-channel logout clears only the initiating browser ticket whose signed session identifier matches the notification");
            using var newChallenge = await browser.GetAsync(new Uri(host, "login"), ct);
            var newCallback = await ProtocolBrowserFixture.LoginAsync(newChallenge.Headers.Location!, callback, "host-user", secret, ct, browser);
            using var newLogin = await browser.GetAsync(newCallback.Callback, ct); newLogin.EnsureSuccessOrRedirect();
            // Admin logout triggers Keycloak's actual signed back-channel notification to the registered application.
            await admin.User.LogoutAsync(realm, actual.Id!, ct);
            using var loggedOut = await browser.GetAsync(new Uri(host, "session"), ct);
            check(!loggedOut.IsSuccessStatusCode && tickets.Count == 0, "A real Keycloak back-channel logout revokes the matching local host ticket before the next authenticated request");
        }
        finally
        {
            using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await app.StopAsync(stop.Token);
            // Restore the owned realm's signing configuration: later wallet workflows require their CA-issued signing key.
            if (rotationComponentId is not null) await admin.Component.RemoveComponentAsync(realm, rotationComponentId, stop.Token);
        }
    }
    private sealed class Tickets : ITicketStore
    {
        private readonly ConcurrentDictionary<string, AuthenticationTicket> tickets = new(StringComparer.Ordinal);
        internal int Count => tickets.Count;
        internal string SessionId => tickets.Values.Single().Principal.FindFirst("sid")!.Value;
        public Task<string> StoreAsync(AuthenticationTicket ticket) { string key = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)); tickets[key] = ticket; return Task.FromResult(key); }
        public Task RenewAsync(string key, AuthenticationTicket ticket) { tickets[key] = ticket; return Task.CompletedTask; }
        public Task<AuthenticationTicket?> RetrieveAsync(string key) => Task.FromResult(tickets.TryGetValue(key, out var ticket) ? ticket : null);
        public Task RemoveAsync(string key) { tickets.TryRemove(key, out _); return Task.CompletedTask; }
    }
    private static void EnsureSuccessOrRedirect(this HttpResponseMessage response) { if (!response.IsSuccessStatusCode && response.StatusCode != HttpStatusCode.Redirect) response.EnsureSuccessStatusCode(); }
}
#endif
