using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text.Json.Nodes;
using Keycloak.Admin.Sdk.Hosting;
using Keycloak.Admin.Sdk.Protocols;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.VisualStudio.TestTools.UnitTesting;

[TestClass]
public sealed class WebAuthenticationEventTests
{
    [TestMethod]
    public async Task ReloadedNamedOptionsRetainTheSameHostGateAndSafeCookieConfiguration()
    {
        using var fixture = new EventsFixture();
        var oidcFactory = fixture.Provider.GetRequiredService<IOptionsFactory<OpenIdConnectOptions>>();
        var cookieFactory = fixture.Provider.GetRequiredService<IOptionsFactory<CookieAuthenticationOptions>>();
        var bearerFactory = fixture.Provider.GetRequiredService<IOptionsFactory<JwtBearerOptions>>();
        var first = oidcFactory.Create("app"); var second = oidcFactory.Create("app");
        Assert.AreNotSame(first, second);
        foreach (var cookie in new[] { cookieFactory.Create("app.cookie"), cookieFactory.Create("app.cookie") })
        { Assert.AreEqual(CookieSecurePolicy.Always, cookie.Cookie.SecurePolicy); Assert.IsNotNull(cookie.SessionStore); }
        var bearers = new[] { bearerFactory.Create("api"), bearerFactory.Create("api") };
        fixture.Tokens.Flags.Replace([]);
        foreach (var options in new[] { first, second })
            await Assert.ThrowsAsync<InvalidOperationException>(() => options.Events.OnMessageReceived(new(fixture.Context(), fixture.Scheme, options, new())));
        foreach (var options in bearers)
            await Assert.ThrowsAsync<InvalidOperationException>(() => options.Events.OnMessageReceived(new(fixture.Context(), new("api", null, typeof(JwtBearerHandler)), options)));
    }

    [TestMethod]
    public async Task FrameworkCallbacksAlsoAwaitAsynchronousHostPoliciesAndSessionStorage()
    {
        using var fixture = new EventsFixture(asynchronous: true);
        var options = fixture.Options;
        var cookies = fixture.Provider.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>().Get("app.cookie");
        var cookie = new CookieValidatePrincipalContext(fixture.Context(), new("app.cookie", null, typeof(CookieAuthenticationHandler)), cookies, new(Principal(), "app.cookie"));
        await cookies.Events.OnValidatePrincipal(cookie); Assert.IsNotNull(cookie.Principal);
        var redirect = new Microsoft.AspNetCore.Authentication.OpenIdConnect.RedirectContext(fixture.Context(), fixture.Scheme, options, new()) { ProtocolMessage = new() };
        await options.Events.OnRedirectToIdentityProvider(redirect);
        await options.Events.OnMessageReceived(new(fixture.Context(), fixture.Scheme, options, new()));
        fixture.Tokens.Respond = async (_, ct) => { await Task.Delay(5, ct); return new(HttpStatusCode.OK) { Content = new StringContent("{\"access_token\":\"access\"}") }; };
        var code = new AuthorizationCodeReceivedContext(fixture.Context(), fixture.Scheme, options, new()) { TokenEndpointRequest = new() { Code = "code", RedirectUri = "https://app.invalid/callback" } };
        code.TokenEndpointRequest.SetParameter("code_verifier", new string('v', 43));
        await options.Events.OnAuthorizationCodeReceived(code); Assert.IsTrue(code.HandledCodeRedemption);
        await options.Events.OnRedirectToIdentityProviderForSignOut(redirect);
        await options.Events.OnRemoteSignOut(new(fixture.Context(), fixture.Scheme, options, new() { Sid = "session", Iss = fixture.Tokens.Transport.Issuer.AbsoluteUri }));
        var bearer = fixture.Provider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>().Get("api");
        await bearer.Events.OnMessageReceived(new(fixture.Context(), new("api", null, typeof(JwtBearerHandler)), bearer));
    }

    [TestMethod]
    public async Task CookieValidationRejectsMalformedRevokedOrInsufficientAssuranceSessions()
    {
        using var fixture = new EventsFixture(new(["strong"]));
        var options = fixture.Provider.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>().Get("app.cookie");
        foreach (string variant in new[] { "valid", "null", "empty", "no-sid", "no-sub", "no-iat", "bad-iat", "negative-iat", "overflow-iat", "revoked",
            "missing-snapshot", "null-snapshot", "malformed-snapshot", "weak-snapshot" })
        {
            var properties = new AuthenticationProperties();
            properties.Items[".keycloak.verified-assurance"] = variant switch
            { "null-snapshot" => null, "malformed-snapshot" => "{", "weak-snapshot" => "{\"acr\":\"weak\"}", _ => "{\"acr\":\"strong\"}" };
            if (variant == "missing-snapshot") properties.Items.Clear();
            var context = new CookieValidatePrincipalContext(fixture.Context(), new("app.cookie", null, typeof(CookieAuthenticationHandler)), options,
                new AuthenticationTicket(Principal(variant), properties, "app.cookie"));
            if (variant == "null") context.Principal = null;
            fixture.Logout.Revoked = variant == "revoked";
            int before = fixture.Authentication.SignOuts;
            await options.Events.OnValidatePrincipal(context);
            bool valid = variant == "valid";
            Assert.AreEqual(valid, context.Principal is not null, variant);
            Assert.AreEqual(before + (valid ? 0 : 1), fixture.Authentication.SignOuts, variant);
        }
        var redirect = new RedirectContext<CookieAuthenticationOptions>(fixture.Context(), new("app.cookie", null, typeof(CookieAuthenticationHandler)), options, new(), "https://app.invalid/login");
        await options.Events.OnRedirectToLogin(redirect); Assert.AreEqual(401, redirect.Response.StatusCode);
        await options.Events.OnRedirectToAccessDenied(redirect); Assert.AreEqual(403, redirect.Response.StatusCode);
        using var plain = new EventsFixture();
        var plainOptions = plain.Provider.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>().Get("app.cookie");
        var accepted = new CookieValidatePrincipalContext(plain.Context(), new("app.cookie", null, typeof(CookieAuthenticationHandler)), plainOptions, new(Principal(), "app.cookie"));
        await plainOptions.Events.OnValidatePrincipal(accepted); Assert.IsNotNull(accepted.Principal);
    }

    [TestMethod]
    public async Task OidcCallbacksPreserveTrustedChoicesCodeRedemptionAndSignOutWhileHonoringGates()
    {
        using var fixture = new EventsFixture(new(["strong"], TimeSpan.FromMinutes(5)), development: true);
        var options = fixture.Options;
        Assert.AreEqual("/callback", options.CallbackPath.Value); Assert.AreEqual("/signed-out", options.SignedOutCallbackPath.Value);
        Assert.AreEqual(CookieSecurePolicy.SameAsRequest, options.CorrelationCookie.SecurePolicy);
        var cookies = fixture.Provider.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>().Get("app.cookie");
        Assert.AreEqual("app", cookies.Cookie.Name);
        var properties = new AuthenticationProperties().WithKeycloakAuthentication(action: "UPDATE_EMAIL", identityProvider: "trusted");
        var redirect = new Microsoft.AspNetCore.Authentication.OpenIdConnect.RedirectContext(fixture.Context(), fixture.Scheme, options, properties) { ProtocolMessage = new() };
        await options.Events.OnRedirectToIdentityProvider(redirect);
        Assert.AreEqual("UPDATE_EMAIL", redirect.ProtocolMessage.GetParameter("kc_action")); Assert.AreEqual("trusted", redirect.ProtocolMessage.GetParameter("kc_idp_hint"));
        Assert.AreEqual("strong", redirect.ProtocolMessage.AcrValues); Assert.AreEqual("300", redirect.ProtocolMessage.MaxAge);
        await options.Events.OnMessageReceived(new(fixture.Context(), fixture.Scheme, options, new()));
        fixture.Tokens.Respond = async (request, ct) =>
        {
            Assert.IsTrue(request.RequestUri!.AbsolutePath.EndsWith("/token", StringComparison.Ordinal));
            string body = await request.Content!.ReadAsStringAsync(ct);
            StringAssert.Contains(body, "code=code"); StringAssert.Contains(body, "code_verifier=vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv");
            return new(HttpStatusCode.OK) { Content = new StringContent("{\"access_token\":\"access\",\"id_token\":\"id\",\"token_type\":\"Bearer\"}") };
        };
        var code = new AuthorizationCodeReceivedContext(fixture.Context(), fixture.Scheme, options, new())
        { TokenEndpointRequest = new() { Code = "code", RedirectUri = "https://app.invalid/callback" } };
        code.TokenEndpointRequest.SetParameter("code_verifier", new string('v', 43));
        await options.Events.OnAuthorizationCodeReceived(code); Assert.IsTrue(code.HandledCodeRedemption);
        Assert.AreEqual("access", code.TokenEndpointResponse!.AccessToken);
        await Assert.ThrowsAsync<InvalidDataException>(() => options.Events.OnAuthorizationCodeReceived(new(fixture.Context(), fixture.Scheme, options, new())));
        await options.Events.OnRedirectToIdentityProviderForSignOut(redirect); Assert.AreEqual("client", redirect.ProtocolMessage.ClientId);
        var failure = new RemoteFailureContext(fixture.Context(), fixture.Scheme, options, new IOException("provider unavailable"));
        await options.Events.OnRemoteFailure(failure); Assert.AreEqual(400, failure.Response.StatusCode); Assert.IsTrue(failure.Result!.Handled);
        options.ConfigurationManager!.RequestRefresh(); fixture.Tokens.Respond = null;
        var configuration = await options.ConfigurationManager.GetConfigurationAsync(default); Assert.IsTrue(configuration.SigningKeys.Any());
        fixture.Tokens.Flags.Replace([]);
        await Assert.ThrowsAsync<InvalidOperationException>(() => options.Events.OnMessageReceived(new(fixture.Context(), fixture.Scheme, options, new())));
        using var plain = new EventsFixture();
        var defaultRedirect = new Microsoft.AspNetCore.Authentication.OpenIdConnect.RedirectContext(plain.Context(), plain.Scheme, plain.Options, new()) { ProtocolMessage = new() };
        await plain.Options.Events.OnRedirectToIdentityProvider(defaultRedirect); Assert.IsNull(defaultRedirect.ProtocolMessage.AcrValues);
    }

    [TestMethod]
    public async Task SignedOidcTokensRequireSessionBindingAndPersistOnlyVerifiedAssurance()
    {
        using var fixture = new EventsFixture(new(["strong"]));
        foreach (string variant in new[] { "valid", "missing-acr", "weak-acr", "no-sid", "no-sub", "no-iat", "revoked", "no-typ", "numeric-typ", "null-token", "malformed-payload", "inner-token" })
        {
            string nonce = fixture.Options.ProtocolValidator.GenerateNonce();
            var payload = fixture.Tokens.Payload(); payload["nonce"] = nonce; payload["typ"] = "ID"; payload["acr"] = "strong";
            payload["auth_time"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(); payload["amr"] = new JsonArray("pwd");
            if (variant == "missing-acr") payload.Remove("acr");
            if (variant == "weak-acr") payload["acr"] = "weak";
            if (variant == "no-typ") { payload.Remove("typ"); payload.Remove("auth_time"); payload.Remove("amr"); }
            if (variant == "numeric-typ") payload["typ"] = 7;
            string encoded = fixture.Tokens.Sign(payload); var signed = new JwtSecurityToken(encoded);
            JwtSecurityToken? token = variant switch
            {
                "null-token" => null,
                "malformed-payload" => new(new JwtHeader(), new JwtPayload(), "header", Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode("{"), "signature"),
                "inner-token" => new(new JwtHeader(), signed, "header", "key", "iv", "ciphertext", "tag"),
                _ => signed
            };
            var context = new Microsoft.AspNetCore.Authentication.OpenIdConnect.TokenValidatedContext(fixture.Context(), fixture.Scheme, fixture.Options, Principal(variant), new())
            { SecurityToken = token!, Nonce = nonce, ProtocolMessage = new() { Code = "code" }, TokenEndpointResponse = new() { IdToken = encoded, AccessToken = "access", TokenType = "Bearer" } };
            fixture.Logout.Revoked = variant == "revoked";
            await fixture.Options.Events.OnTokenValidated(context);
            bool expected = variant is "valid" or "no-typ" or "inner-token";
            Assert.AreEqual(expected, context.Result?.Failure is null, variant);
            if (expected) StringAssert.Contains(context.Properties!.Items[".keycloak.verified-assurance"]!, "strong");
        }
    }

    [TestMethod]
    public async Task RemoteSignOutAndBearerValidationDoNotAcceptAnotherSessionOrTokenKind()
    {
        using var fixture = new EventsFixture();
        foreach (string variant in new[] { "match", "no-message", "no-sid", "other-sid", "other-issuer", "anonymous", "no-claim" })
        {
            fixture.Authentication.Principal = variant == "anonymous" ? null : Principal(variant == "no-claim" ? "no-sid" : "valid");
            var context = new RemoteSignOutContext(fixture.Context(), fixture.Scheme, fixture.Options,
                variant == "no-message" ? null! : new() { Sid = variant == "no-sid" ? null : variant == "other-sid" ? "other" : "session",
                    Iss = variant == "other-issuer" ? "https://attacker.invalid" : fixture.Tokens.Transport.Issuer.AbsoluteUri });
            await fixture.Options.Events.OnRemoteSignOut(context); Assert.AreEqual(variant != "match", context.Result?.Handled == true, variant);
        }
        var bearer = fixture.Provider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>().Get("api");
        await bearer.Events.OnMessageReceived(new(fixture.Context(), new("api", null, typeof(JwtBearerHandler)), bearer));
        foreach (string? kind in new[] { null, "ID", "Bearer" })
        {
            var context = new Microsoft.AspNetCore.Authentication.JwtBearer.TokenValidatedContext(fixture.Context(), new("api", null, typeof(JwtBearerHandler)), bearer)
            { Principal = kind is null ? null : new(new ClaimsIdentity([new("typ", kind)], "verified")) };
            await bearer.Events.OnTokenValidated(context); Assert.AreEqual(kind != "Bearer", context.Result?.Failure is not null);
        }
        var empty = new Microsoft.AspNetCore.Authentication.JwtBearer.TokenValidatedContext(fixture.Context(), new("api", null, typeof(JwtBearerHandler)), bearer) { Principal = new() };
        await bearer.Events.OnTokenValidated(empty); Assert.IsNotNull(empty.Result?.Failure);
        fixture.Tokens.Flags.Replace([]);
        await Assert.ThrowsAsync<InvalidOperationException>(() => bearer.Events.OnMessageReceived(new(fixture.Context(), new("api", null, typeof(JwtBearerHandler)), bearer)));
    }

    [TestMethod]
    public void WebHostRegistrationRejectsMissingDependenciesAndInvalidDevelopmentExceptions()
    {
        using var fixture = new HostTokenFixture(); var builder = new ServiceCollection().AddAuthentication(); var tickets = new Tickets(); var store = new RecordingLogoutStore();
        Assert.Throws<ArgumentNullException>(() => KeycloakWebAuthentication.AddKeycloakWebApp(null!, "x", fixture.Transport, OAuthClientAuthentication.Public("client"), tickets, store));
        Assert.Throws<ArgumentException>(() => builder.AddKeycloakWebApp(" ", fixture.Transport, OAuthClientAuthentication.Public("client"), tickets, store));
        Assert.Throws<ArgumentNullException>(() => builder.AddKeycloakWebApp("x", null!, OAuthClientAuthentication.Public("client"), tickets, store));
        Assert.Throws<ArgumentNullException>(() => builder.AddKeycloakWebApp("x", fixture.Transport, null!, tickets, store));
        Assert.Throws<ArgumentNullException>(() => builder.AddKeycloakWebApp("x", fixture.Transport, OAuthClientAuthentication.Public("client"), null!, store));
        Assert.Throws<ArgumentNullException>(() => builder.AddKeycloakWebApp("x", fixture.Transport, OAuthClientAuthentication.Public("client"), tickets, null!));
        Assert.Throws<ArgumentNullException>(() => KeycloakWebAuthentication.AddKeycloakBearer(null!, "x", fixture.Transport, "a"));
        Assert.Throws<ArgumentNullException>(() => builder.AddKeycloakBearer("x", null!, "a"));
        Assert.Throws<ArgumentException>(() => builder.AddKeycloakBearer("x", fixture.Transport, " "));
        KeycloakWebAuthentication.ValidateIssuer(new("http://127.0.0.1/"), true);
        Assert.Throws<ArgumentException>(() => KeycloakWebAuthentication.ValidateIssuer(new("ftp://127.0.0.1/"), true));
        Assert.Throws<ArgumentException>(() => KeycloakWebAuthentication.ValidateIssuer(new("http://127.0.0.1/"), false));
    }

    private static ClaimsPrincipal Principal(string variant = "valid")
    {
        if (variant == "empty") return new();
        var claims = new List<Claim>();
        if (variant != "no-sid") claims.Add(new("sid", "session"));
        if (variant != "no-sub") claims.Add(new("sub", "user"));
        if (variant != "no-iat") claims.Add(new("iat", variant switch
        { "bad-iat" => "not-a-time", "negative-iat" => "-1", "overflow-iat" => "253402300800", _ => DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture) }));
        return new(new ClaimsIdentity(claims, "verified"));
    }
    private sealed class EventsFixture : IDisposable
    {
        internal readonly HostTokenFixture Tokens;
        internal readonly RecordingLogoutStore Logout = new();
        internal readonly AuthenticationService Authentication = new();
        internal readonly ServiceProvider Provider;
        internal readonly AuthenticationScheme Scheme = new("app", null, typeof(OpenIdConnectHandler));
        internal OpenIdConnectOptions Options => Provider.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>().Get("app");
        internal EventsFixture(OidcAssuranceRequirement? assurance = null, bool development = false, bool asynchronous = false)
        {
            Tokens = new(asynchronous); Logout.Asynchronous = asynchronous; Authentication.Asynchronous = asynchronous;
            var services = new ServiceCollection(); services.AddLogging(); services.AddDataProtection();
            services.AddAuthentication().AddKeycloakWebApp("app", Tokens.Transport, OAuthClientAuthentication.Public("client"), new Tickets(), Logout,
                development ? "/callback" : default, development ? "/signed-out" : default, development, assurance)
                .AddKeycloakBearer("api", Tokens.Transport, "resource");
            services.AddSingleton<IAuthenticationService>(Authentication); Provider = services.BuildServiceProvider();
        }
        internal DefaultHttpContext Context() => new() { RequestServices = Provider };
        public void Dispose() { Provider.Dispose(); Tokens.Dispose(); }
    }
    private sealed class AuthenticationService : IAuthenticationService
    {
        internal ClaimsPrincipal? Principal = WebAuthenticationEventTests.Principal(); internal int SignOuts; internal bool Asynchronous;
        public async Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string? scheme)
        { if (Asynchronous) await Task.Delay(5); return Principal is null ? AuthenticateResult.NoResult() : AuthenticateResult.Success(new(Principal, scheme!)); }
        public Task SignOutAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) { SignOuts++; return Task.CompletedTask; }
        public Task ChallengeAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => throw new AssertFailedException();
        public Task ForbidAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => throw new AssertFailedException();
        public Task SignInAsync(HttpContext context, string? scheme, ClaimsPrincipal principal, AuthenticationProperties? properties) => throw new AssertFailedException();
    }
    private sealed class Tickets : ITicketStore
    {
        public Task<string> StoreAsync(AuthenticationTicket ticket) => throw new AssertFailedException();
        public Task RenewAsync(string key, AuthenticationTicket ticket) => throw new AssertFailedException();
        public Task<AuthenticationTicket?> RetrieveAsync(string key) => throw new AssertFailedException();
        public Task RemoveAsync(string key) => throw new AssertFailedException();
    }
}

