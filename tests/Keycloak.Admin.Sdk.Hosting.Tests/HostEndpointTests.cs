using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Keycloak.Admin.Sdk.Capabilities;
using Keycloak.Admin.Sdk.Hosting;
using Keycloak.Admin.Sdk.Protocols;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualStudio.TestTools.UnitTesting;

[TestClass]
public sealed class HostEndpointTests
{
    [TestMethod]
    public async Task BackchannelLogoutValidatesSignedSubjectsAndCommitsBeforeAcknowledgingRetry()
    {
        using var fixture = new HostTokenFixture();
        await using var app = WebApplication.CreateBuilder().Build();
        var store = new RecordingLogoutStore();
        app.MapKeycloakBackchannelLogout("/logout", fixture.Transport, "client", store);
        foreach (string kind in new[] { "sid", "sub", "numeric-sid" })
        {
            var payload = fixture.Payload();
            if (kind != "sid") payload.Remove("sid");
            if (kind != "sub") payload.Remove("sub");
            if (kind == "numeric-sid") { payload["sid"] = 7; payload["sub"] = "user"; }
            string body = "logout_token=" + Uri.EscapeDataString(fixture.Sign(payload));
            var context = Context(app, body);
            await Endpoint(app, "/logout")(context);
            Assert.AreEqual(200, context.Response.StatusCode);
            Assert.AreEqual("no-store", context.Response.Headers.CacheControl.ToString());
            Assert.AreEqual(kind == "sid" ? "session" : null, store.Session);
            Assert.AreEqual(kind == "sid" ? null : "user", store.Subject);
            Assert.IsTrue(store.RetainUntil > DateTimeOffset.UtcNow.AddHours(8));
        }
        string retry = "logout_token=" + Uri.EscapeDataString(fixture.Sign(fixture.Payload()));
        store.Fail = true;
        await Assert.ThrowsAsync<IOException>(() => Endpoint(app, "/logout")(Context(app, retry)));
        store.Fail = false;
        await Endpoint(app, "/logout")(Context(app, retry));
        Assert.AreEqual(4, store.Commits);
    }

    [TestMethod]
    public async Task BackchannelLogoutRejectsMalformedOversizedForgedAndClosedRequests()
    {
        using var fixture = new HostTokenFixture();
        await using var app = WebApplication.CreateBuilder().Build();
        var store = new RecordingLogoutStore();
        app.MapKeycloakBackchannelLogout("/logout", fixture.Transport, "client", store, TimeProvider.System);
        foreach (string body in new[] { "", "other=x", "logout_token=", "logout_token=x&logout_token=y", "logout_token=x&other=y", "logout_token=invalid", new string('a', 65537) })
        {
            var context = Context(app, body);
            await Endpoint(app, "/logout")(context);
            Assert.AreEqual(400, context.Response.StatusCode, body[..Math.Min(50, body.Length)]);
        }
        foreach (var context in new[] { Context(app, "x", "text/plain"), Context(app, "x", length: 65537) })
        { await Endpoint(app, "/logout")(context); Assert.AreEqual(400, context.Response.StatusCode); }
        var invalid = fixture.Payload(); invalid["iss"] = "https://attacker.invalid";
        var forged = Context(app, "logout_token=" + Uri.EscapeDataString(fixture.Sign(invalid)));
        await Endpoint(app, "/logout")(forged); Assert.AreEqual(400, forged.Response.StatusCode);
        fixture.Flags.Replace([]);
        await Assert.ThrowsAsync<InvalidOperationException>(() => Endpoint(app, "/logout")(Context(app, "logout_token=x")));
        Assert.AreEqual(0, store.Commits);
        Assert.Throws<ArgumentNullException>(() => KeycloakHostEndpoints.MapKeycloakBackchannelLogout(null!, "/x", fixture.Transport, "c", store));
        Assert.Throws<ArgumentNullException>(() => app.MapKeycloakBackchannelLogout("/x", null!, "c", store));
        Assert.Throws<ArgumentNullException>(() => app.MapKeycloakBackchannelLogout("/x", fixture.Transport, "c", null!));
    }

    [TestMethod]
    public async Task ProtectedResourceMetadataIsExactGatedAndDoesNotAuthorizeAnAnonymousPrincipal()
    {
        using var fixture = new HostTokenFixture();
        await using var app = WebApplication.CreateBuilder().Build();
        foreach (var scopes in new[] { Array.Empty<string>(), new[] { "read", "read", "write" } })
        {
            string suffix = scopes.Length == 0 ? "empty" : "tools";
            var resource = new KeycloakProtectedResource(fixture.Transport, new("https://api.invalid/" + suffix), scopes);
            resource.MapMetadata(app);
            var context = Context(app, "");
            await Endpoint(app, resource.MetadataUri.AbsolutePath)(context);
            using var json = JsonDocument.Parse(((MemoryStream)context.Response.Body).ToArray());
            Assert.AreEqual(resource.Resource.AbsoluteUri, json.RootElement.GetProperty("resource").GetString());
            Assert.AreEqual(scopes.Distinct().Count(), json.RootElement.GetProperty("scopes_supported").GetArrayLength());
            Assert.AreEqual(fixture.Transport.Issuer.AbsoluteUri, json.RootElement.GetProperty("authorization_servers")[0].GetString());
            Assert.AreEqual("application/json", context.Response.ContentType);
            Assert.AreEqual("no-store", context.Response.Headers.CacheControl.ToString());
            Assert.AreEqual("Bearer resource_metadata=\"" + resource.MetadataUri.AbsoluteUri + "\"", resource.Challenge);
        }
        fixture.Flags.Replace([]);
        await Assert.ThrowsAsync<InvalidOperationException>(() => Endpoint(app, "/.well-known/oauth-protected-resource/tools")(Context(app, "")));
        Assert.IsFalse(KeycloakProtectedResource.HasScope(new ClaimsPrincipal(), "read"));
        Assert.Throws<ArgumentNullException>(() => KeycloakProtectedResource.HasScope(null!, "read"));
        Assert.Throws<ArgumentException>(() => KeycloakProtectedResource.HasScope(new(), " "));
        Assert.Throws<ArgumentNullException>(() => new KeycloakProtectedResource(null!, new("https://api.invalid"), []));
        Assert.Throws<ArgumentNullException>(() => new KeycloakProtectedResource(fixture.Transport, null!, []));
        Assert.Throws<ArgumentNullException>(() => new KeycloakProtectedResource(fixture.Transport, new("https://api.invalid"), null!));
        Assert.Throws<ArgumentException>(() => new KeycloakProtectedResource(fixture.Transport, new("relative", UriKind.Relative), []));
        Assert.Throws<ArgumentNullException>(() => new KeycloakProtectedResource(fixture.Transport, new("https://api.invalid"), []).MapMetadata(null!));
    }

    private static RequestDelegate Endpoint(WebApplication app, string pattern) => ((IEndpointRouteBuilder)app).DataSources.SelectMany(s => s.Endpoints)
        .OfType<RouteEndpoint>().Single(e => e.RoutePattern.RawText == pattern).RequestDelegate!;
    private static DefaultHttpContext Context(WebApplication app, string body, string type = "application/x-www-form-urlencoded", long? length = null)
    {
        var context = new DefaultHttpContext { RequestServices = app.Services };
        context.Request.ContentType = type; context.Request.ContentLength = length;
        context.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes(body)); context.Response.Body = new MemoryStream();
        return context;
    }
}

internal sealed class HostTokenFixture : IDisposable
{
    internal readonly RSA Key = RSA.Create(2048);
    internal readonly KeycloakFeatureSnapshotGate Flags = new(new Dictionary<string, bool>
    { ["KeycloakSdk.Protocols"] = true, ["KeycloakSdk.Protocols.Oidc"] = true, ["KeycloakSdk.Protocols.BrowserOidc"] = true,
      ["KeycloakSdk.Protocols.OidcAssurance"] = true, ["KeycloakSdk.Protocols.BrowserOidcAssurance"] = true,
      ["KeycloakSdk.Protocols.IdentityBrokerLogin"] = true, ["KeycloakSdk.Protocols.Authentication"] = true,
      ["KeycloakSdk.Protocols.AuthenticationUpdateEmail"] = true });
    internal readonly HttpClient Http;
    internal readonly ProtocolTransport Transport;
    internal Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>>? Respond;
    internal int Sends;
    internal HostTokenFixture(bool asynchronous = false)
    {
        Http = new(new Handler(this)); Transport = new(Http, new("https://identity.invalid/"), "realm", asynchronous ? new AsyncGate(Flags) : Flags);
    }
    internal JsonObject Payload() => new() { ["iss"] = Transport.Issuer.AbsoluteUri, ["aud"] = "client", ["sub"] = "user", ["sid"] = "session",
        ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), ["exp"] = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds(), ["jti"] = Guid.NewGuid().ToString(),
        ["events"] = new JsonObject { ["http://schemas.openid.net/event/backchannel-logout"] = new JsonObject() } };
    internal string Sign(JsonObject payload)
    {
        string data = Base64UrlEncoder.Encode("{\"alg\":\"RS256\",\"kid\":\"key\",\"typ\":\"JWT\"}") + "." + Base64UrlEncoder.Encode(payload.ToJsonString());
        return data + "." + Base64UrlEncoder.Encode(Key.SignData(Encoding.UTF8.GetBytes(data), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }
    private sealed class Handler(HostTokenFixture owner) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested(); owner.Sends++;
            if (owner.Respond is not null) return owner.Respond(request, ct);
            Assert.IsTrue(request.RequestUri!.AbsolutePath.EndsWith("/certs", StringComparison.Ordinal));
            var key = owner.Key.ExportParameters(false);
            string jwks = new JsonObject { ["keys"] = new JsonArray(new JsonObject { ["kty"] = "RSA", ["kid"] = "key", ["alg"] = "RS256", ["use"] = "sig",
                ["n"] = Base64UrlEncoder.Encode(key.Modulus), ["e"] = Base64UrlEncoder.Encode(key.Exponent) }) }.ToJsonString();
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(jwks) });
        }
    }
    public void Dispose() { Http.Dispose(); Key.Dispose(); }
    private sealed class AsyncGate(KeycloakFeatureSnapshotGate flags) : IKeycloakFeatureGate
    {
        public async ValueTask<bool> IsEnabledAsync(string feature, CancellationToken ct = default)
        { await Task.Delay(5, ct); return await flags.IsEnabledAsync(feature, ct); }
    }
}

internal sealed class RecordingLogoutStore : IKeycloakLogoutStore
{
    internal bool Fail, Revoked, Asynchronous;
    internal int Commits;
    internal string? Session, Subject;
    internal DateTimeOffset RetainUntil;
    public ValueTask RevokeAsync(string issuer, string id, string? session, string? subject, DateTimeOffset issued, DateTimeOffset retain, CancellationToken ct)
    { ct.ThrowIfCancellationRequested(); if (Fail) throw new IOException("Durable store unavailable"); Commits++; Session = session; Subject = subject; RetainUntil = retain; return ValueTask.CompletedTask; }
    public ValueTask<bool> IsRevokedAsync(string issuer, string session, string subject, DateTimeOffset authenticated, CancellationToken ct)
    { ct.ThrowIfCancellationRequested(); return Asynchronous ? ReadAsync(ct) : ValueTask.FromResult(Revoked); }
    private async ValueTask<bool> ReadAsync(CancellationToken ct) { await Task.Delay(5, ct); return Revoked; }
}
