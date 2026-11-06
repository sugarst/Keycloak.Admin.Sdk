using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;
using Keycloak.Admin.Sdk.Capabilities;
using Keycloak.Admin.Sdk.Hosting;
using Keycloak.Admin.Sdk.Protocols;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

[TestClass]
public sealed class WebAuthenticationTests
{
    [TestMethod]
    public async Task CustomCodeRedemptionCannotBypassSignedIdTokenNonceBinding()
    {
        using var handler = new Handler(); using var http = new HttpClient(handler); using var rsa = RSA.Create(2048);
        var flags = new KeycloakFeatureSnapshotGate(new Dictionary<string, bool> { ["KeycloakSdk.Protocols"] = true, ["KeycloakSdk.Protocols.Oidc"] = true, ["KeycloakSdk.Protocols.BrowserOidc"] = true });
        var transport = new ProtocolTransport(http, new("https://identity.invalid/"), "realm", flags);
        var services = new ServiceCollection(); services.AddLogging(); services.AddDataProtection();
        services.AddAuthentication().AddKeycloakWebApp("app", transport, OAuthClientAuthentication.Public("client"), new Tickets(), new InMemoryKeycloakLogoutStore());
        using var provider = services.BuildServiceProvider(); var options = provider.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>().Get("app");
        string nonce = options.ProtocolValidator.GenerateNonce();
        foreach (string variant in new[] { "valid", "missing-cookie", "wrong-cookie", "unsigned", "missing-response", "access-substitution" })
        {
            var now = DateTimeOffset.UtcNow;
            var jwt = new JwtSecurityTokenHandler().CreateJwtSecurityToken(issuer: transport.Issuer.AbsoluteUri, audience: "client",
                subject: new ClaimsIdentity([new("sub", "user"), new("sid", "session"), new("nonce", nonce), new("typ", variant == "access-substitution" ? "Bearer" : "ID")]), issuedAt: now.UtcDateTime, expires: now.AddMinutes(5).UtcDateTime,
                signingCredentials: variant == "unsigned" ? null : new(new RsaSecurityKey(rsa), "RS256"));
            string encoded = new JwtSecurityTokenHandler().WriteToken(jwt); var signed = new JwtSecurityToken(encoded);
            var principal = new ClaimsPrincipal(new ClaimsIdentity(signed.Claims, "verified-token-handler"));
            var context = new TokenValidatedContext(new Microsoft.AspNetCore.Http.DefaultHttpContext { RequestServices = provider },
                new AuthenticationScheme("app", "app", typeof(OpenIdConnectHandler)), options, principal, new AuthenticationProperties())
            { SecurityToken = signed, ProtocolMessage = new OpenIdConnectMessage { Code = "code" },
                TokenEndpointResponse = variant == "missing-response" ? null : new OpenIdConnectMessage { IdToken = encoded, AccessToken = "access", TokenType = "Bearer" },
                Nonce = variant == "missing-cookie" ? null : variant == "wrong-cookie" ? "other" : nonce };
            await options.Events.OnTokenValidated(context);
            Assert.AreEqual(variant != "valid", context.Result?.Failure is not null, variant);
        }
        Assert.AreEqual(0, handler.Sends);
    }
    [TestMethod]
    public async Task LogoutMarkersAreAtomicIdempotentIssuerScopedAndSessionScoped()
    {
        var now = DateTimeOffset.UtcNow; var clock = new Clock(now); var store = new InMemoryKeycloakLogoutStore(2, clock);
        await Task.WhenAll(Enumerable.Range(0, 20).Select(i => store.RevokeAsync("issuer-a", "event", "sid-a", "user", now, now.AddHours(8), default).AsTask()));
        Assert.IsTrue(await store.IsRevokedAsync("issuer-a", "sid-a", "user", now, default));
        Assert.IsFalse(await store.IsRevokedAsync("issuer-b", "sid-a", "user", now, default));
        Assert.IsFalse(await store.IsRevokedAsync("issuer-a", "sid-b", "user", now, default));
        await store.RevokeAsync("issuer-a", "subject-event", null, "user", now, now.AddHours(8), default);
        Assert.IsTrue(await store.IsRevokedAsync("issuer-a", "sid-b", "user", now.AddSeconds(-1), default));
        Assert.IsFalse(await store.IsRevokedAsync("issuer-a", "sid-c", "user", now.AddSeconds(1), default));
        await Assert.ThrowsAsync<InvalidOperationException>(() => store.RevokeAsync("issuer-a", "third", "third-sid", "user", now, now.AddHours(8), default).AsTask());
        clock.Now = now.AddHours(9);
        Assert.IsFalse(await store.IsRevokedAsync("issuer-a", "sid-a", "user", now, default));
        await store.RevokeAsync("issuer-a", "new", "new-sid", "user", clock.Now, clock.Now.AddHours(8), default);
    }
    [TestMethod]
    public async Task LogoutStoreRejectsInvalidInputAndCancellationWithoutChangingExistingRevocation()
    {
        var now = DateTimeOffset.UtcNow; var store = new InMemoryKeycloakLogoutStore();
        await store.RevokeAsync("issuer", "event", " ", "user", now, now.AddHours(1), default);
        Assert.IsTrue(await store.IsRevokedAsync("issuer", "sid", "user", now, default));
        Assert.Throws<ArgumentOutOfRangeException>(() => new InMemoryKeycloakLogoutStore(0));
        Assert.Throws<ArgumentException>(() => store.RevokeAsync("issuer", "event", null, null, now, now.AddHours(1), default));
        Assert.Throws<ArgumentException>(() => store.RevokeAsync("", "event", "sid", "user", now, now.AddHours(1), default));
        Assert.Throws<ArgumentException>(() => store.RevokeAsync("issuer", "", "sid", "user", now, now.AddHours(1), default));
        Assert.Throws<ArgumentOutOfRangeException>(() => store.RevokeAsync("issuer", "event", "sid", "user", now, now.AddHours(-1), default));
        using var cancellation = new CancellationTokenSource(); cancellation.Cancel();
        Assert.Throws<OperationCanceledException>(() => store.RevokeAsync("issuer", "event", "sid", "user", now, now.AddHours(1), cancellation.Token));
        Assert.Throws<OperationCanceledException>(() => store.IsRevokedAsync("issuer", "sid", "user", now, cancellation.Token));
    }
    [TestMethod]
    public async Task OidcConfigurationCannotNavigateUntrustedMetadataAndTheHostCanCloseItBeforeAnyRequest()
    {
        using var handler = new Handler(); using var http = new HttpClient(handler); var flags = new KeycloakFeatureSnapshotGate(new Dictionary<string, bool>
            { ["KeycloakSdk.Protocols"] = true, ["KeycloakSdk.Protocols.Oidc"] = true, ["KeycloakSdk.Protocols.BrowserOidc"] = true });
        var transport = new ProtocolTransport(http, new("https://identity.invalid/"), "realm", flags);
        var services = new ServiceCollection(); services.AddLogging(); services.AddDataProtection();
        services.AddAuthentication().AddKeycloakWebApp("app", transport, OAuthClientAuthentication.SecretBasic("client", _ => throw new AssertFailedException("Configuration must not retrieve a client secret.")), new Tickets(), new InMemoryKeycloakLogoutStore());
        using var provider = services.BuildServiceProvider(); var options = provider.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>().Get("app");
        var configuration = await options.ConfigurationManager!.GetConfigurationAsync(default);
        Assert.AreEqual("https://identity.invalid/realms/realm/protocol/openid-connect/token", configuration.TokenEndpoint);
        Assert.IsFalse(configuration.AuthorizationEndpoint.Contains("attacker", StringComparison.Ordinal)); Assert.AreEqual(1, handler.Sends);
        flags.Replace([]);
        await Assert.ThrowsAsync<InvalidOperationException>(() => options.ConfigurationManager.GetConfigurationAsync(default)); Assert.AreEqual(1, handler.Sends);
    }
    [TestMethod]
    public void HostRejectsInsecureAuthoritiesAndMcpDiscoveryDoesNotGrantToolPermissions()
    {
        using var http = new HttpClient(); var remote = new ProtocolTransport(http, new("http://identity.invalid/"), "r");
        var auth = new ServiceCollection().AddAuthentication();
        Assert.Throws<ArgumentException>(() => auth.AddKeycloakWebApp("app", remote, OAuthClientAuthentication.Public("client"), new Tickets(), new InMemoryKeycloakLogoutStore(), allowLoopbackHttp: true));
        Assert.Throws<ArgumentException>(() => auth.AddKeycloakBearer("api", remote, "resource"));
        var secure = new ProtocolTransport(http, new("https://identity.invalid/"), "r");
        var resource = new KeycloakProtectedResource(secure, new("https://api.invalid/mcp/team"), ["tools:read"]);
        Assert.AreEqual("https://api.invalid/.well-known/oauth-protected-resource/mcp/team", resource.MetadataUri.AbsoluteUri);
        Assert.IsFalse(KeycloakProtectedResource.HasScope(new ClaimsPrincipal(new ClaimsIdentity([new("scope", "tools:read")])), "tools:read"));
        var identity = new ClaimsPrincipal(new ClaimsIdentity([new("scope", "openid tools:read")], "verified"));
        Assert.IsTrue(KeycloakProtectedResource.HasScope(identity, "tools:read")); Assert.IsFalse(KeycloakProtectedResource.HasScope(identity, "tools:write"));
        foreach (string scope in new[] { "", "has space", "has\"quote", "has\\slash", "new\nline", "非ASCII" })
            Assert.Throws<ArgumentException>(() => new KeycloakProtectedResource(secure, new("https://api.invalid/mcp"), [scope]));
        foreach (string uri in new[] { "https://u:p@api.invalid/mcp", "https://api.invalid/mcp?query", "https://api.invalid/mcp#fragment", "http://api.invalid/mcp" })
            Assert.Throws<ArgumentException>(() => new KeycloakProtectedResource(secure, new(uri), []));
    }
    private sealed class Clock(DateTimeOffset now) : TimeProvider { internal DateTimeOffset Now = now; public override DateTimeOffset GetUtcNow() => Now; }
    private sealed class Handler : HttpMessageHandler
    {
        internal int Sends;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        { cancellationToken.ThrowIfCancellationRequested(); Sends++; Assert.IsTrue(request.RequestUri!.AbsolutePath.EndsWith("/certs", StringComparison.Ordinal)); return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{\"keys\":[]}") }); }
    }
    private sealed class Tickets : ITicketStore
    {
        public Task<string> StoreAsync(AuthenticationTicket ticket) => throw new AssertFailedException(); public Task RenewAsync(string key, AuthenticationTicket ticket) => throw new AssertFailedException();
        public Task<AuthenticationTicket?> RetrieveAsync(string key) => throw new AssertFailedException(); public Task RemoveAsync(string key) => throw new AssertFailedException();
    }
}
