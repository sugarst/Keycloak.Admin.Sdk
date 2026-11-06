using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Keycloak.Admin.Sdk.Capabilities;
using Keycloak.Admin.Sdk.Protocols;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualStudio.TestTools.UnitTesting;

[TestClass]
public sealed class CibaTests
{
    [TestMethod]
    public async Task RequestOptionsKeepHintsSignaturesClientNotificationsAndCallbackCredentialsDistinct()
    {
        using var handler = new Handler(); using var http = new HttpClient(handler); var client = new OidcClient(new(http, new("https://identity.invalid/"), "r")); var auth = OAuthClientAuthentication.Public("client");
        await client.RequestBackchannelAuthenticationAsync(auth, new CibaAuthenticationRequest { LoginHint = "user+", BindingMessage = "ABCD", AcrValues = "high", ClientNotificationToken = "notification-secret", RequestedExpirySeconds = 60 }, "openid");
        StringAssert.Contains(handler.Body, "login_hint=user%2B"); StringAssert.Contains(handler.Body, "binding_message=ABCD"); StringAssert.Contains(handler.Body, "requested_expiry=60");
        StringAssert.Contains(handler.Body, "client_notification_token=notification-secret"); StringAssert.Contains(handler.Body, "acr_values=high");
        await client.RequestBackchannelAuthenticationAsync(auth, new CibaAuthenticationRequest { IdTokenHint = "id-token" }); StringAssert.Contains(handler.Body, "id_token_hint=id-token");
        await client.RequestBackchannelAuthenticationAsync(auth, new CibaAuthenticationRequest { LoginHintToken = "signed-hint" }); StringAssert.Contains(handler.Body, "login_hint_token=signed-hint");
        await client.RequestBackchannelAuthenticationAsync(auth, new CibaAuthenticationRequest { SignedRequest = "signed-request" }); StringAssert.Contains(handler.Body, "request=signed-request");
        Assert.IsFalse(handler.Body.Contains("scope", StringComparison.Ordinal));
        foreach (var result in new[] { CibaAuthenticationResult.Approved, CibaAuthenticationResult.Denied, CibaAuthenticationResult.Cancelled })
        {
            await client.CompleteBackchannelAuthenticationAsync("channel-credential", result);
            Assert.AreEqual("/realms/r/protocol/openid-connect/ext/ciba/auth/callback", handler.Path); Assert.AreEqual("Bearer channel-credential", handler.Authorization);
            using var document = JsonDocument.Parse(handler.Body); Assert.IsTrue(new[] { "SUCCEED", "UNAUTHORIZED", "CANCELLED" }.Contains(document.RootElement.GetProperty("status").GetString()));
        }
        foreach (var invalid in new CibaAuthenticationRequest[] { new(), new() { LoginHint = "user", IdTokenHint = "token" }, new() { LoginHint = " " }, new() { SignedRequest = " " },
            new() { LoginHint = "u", RequestedExpirySeconds = 0 }, new() { LoginHint = "u", RequestedExpirySeconds = 86401 }, new() { SignedRequest = "s", LoginHint = "u" },
            new() { SignedRequest = "s", BindingMessage = "m" }, new() { SignedRequest = "s", AcrValues = "v" }, new() { SignedRequest = "s", ClientNotificationToken = "n" }, new() { SignedRequest = "s", RequestedExpirySeconds = 1 } })
            Assert.Throws<ArgumentException>(() => client.RequestBackchannelAuthenticationAsync(auth, invalid));
        Assert.Throws<ArgumentException>(() => client.RequestBackchannelAuthenticationAsync(auth, new CibaAuthenticationRequest { SignedRequest = "s" }, "openid"));
        Assert.Throws<ArgumentNullException>(() => client.RequestBackchannelAuthenticationAsync(auth, (CibaAuthenticationRequest)null!));
        Assert.Throws<ArgumentException>(() => client.CompleteBackchannelAuthenticationAsync("", CibaAuthenticationResult.Approved));
        Assert.Throws<ArgumentOutOfRangeException>(() => client.CompleteBackchannelAuthenticationAsync("credential", (CibaAuthenticationResult)42));
    }

    [TestMethod]
    public async Task PingNotificationsBindBearerSecretRequestExpiryReplayAndBothHostGates()
    {
        using var handler = new Handler(); using var http = new HttpClient(handler); var transport = new ProtocolTransport(http, new("https://identity.invalid/"), "r");
        var lease = OAuthPollingLease.FromCibaResponse(new(HttpStatusCode.OK, Json("""{"auth_req_id":"request","expires_in":120}""")));
        string secret = CibaPingNotificationValidator.CreateNotificationToken(); var validator = new CibaPingNotificationValidator(transport, lease, secret, new InMemoryDpopReplayStore(), TimeProvider.System);
        foreach (var (auth, body) in new[] { ("Basic x", """{"auth_req_id":"request"}"""), ("Bearer", "{}"), ("Bearer wrong-secret", "{}"), ("not a header\r\n", "{}"),
            ("Bearer " + secret, "[]"), ("Bearer " + secret, "{}"), ("Bearer " + secret, """{"auth_req_id":42}"""), ("Bearer " + secret, """{"auth_req_id":"other"}"""), ("Bearer " + secret, """{"auth_req_id":"request","auth_req_id":"request"}""") })
            await Assert.ThrowsAsync<InvalidDataException>(() => validator.ValidateAsync(auth, Json(body)));
        await validator.ValidateAsync("Bearer " + secret, Json("""{"auth_req_id":"request"}""")); Assert.AreEqual(0, handler.Sends);
        await Assert.ThrowsAsync<InvalidDataException>(() => validator.ValidateAsync("Bearer " + secret, Json("""{"auth_req_id":"request"}""")));
        var future = new Clock(lease.ExpiresAt.AddSeconds(1));
        await Assert.ThrowsAsync<InvalidDataException>(() => new CibaPingNotificationValidator(transport, lease, secret, new InMemoryDpopReplayStore(), future).ValidateAsync("Bearer " + secret, Json("{}")));
        Assert.Throws<ArgumentNullException>(() => new CibaPingNotificationValidator(null!, lease, secret, new InMemoryDpopReplayStore()));
        Assert.Throws<ArgumentNullException>(() => new CibaPingNotificationValidator(transport, null!, secret, new InMemoryDpopReplayStore()));
        Assert.Throws<ArgumentNullException>(() => new CibaPingNotificationValidator(transport, lease, null!, new InMemoryDpopReplayStore()));
        Assert.Throws<ArgumentNullException>(() => new CibaPingNotificationValidator(transport, lease, secret, null!));
        foreach (string invalid in new[] { "short", new string('a', 1025), new string('a', 25) + " ", new string('a', 25) + "中" })
            Assert.Throws<ArgumentException>(() => new CibaPingNotificationValidator(transport, lease, invalid, new InMemoryDpopReplayStore()));
        using var cancel = new CancellationTokenSource(); cancel.Cancel(); await Assert.ThrowsAsync<OperationCanceledException>(() => validator.ValidateAsync("Bearer " + secret, Json("{}"), cancel.Token));
        var onlyCiba = new KeycloakFeatureSnapshotGate(new Dictionary<string, bool> { ["KeycloakSdk.Protocols"] = true, ["KeycloakSdk.Protocols.OidcCiba"] = true });
        await Assert.ThrowsAsync<InvalidOperationException>(() => new CibaPingNotificationValidator(new(http, new("https://identity.invalid/"), "r", onlyCiba), lease, secret, new InMemoryDpopReplayStore()).ValidateAsync("Bearer " + secret, Json("{}")));
    }

    [TestMethod]
    public async Task SignedCibaRequestPinsTheClientRealmAndNumericExpiryWithoutNestingAnUntrustedRequest()
    {
        using var http = new HttpClient(); var oidc = new OidcClient(new(http, new("https://identity.invalid/"), "r")); using var key = RSA.Create(2048); var signing = new SigningCredentials(new RsaSecurityKey(key), "RS256");
        var signer = new CibaRequestSigner("client", oidc, signing, TimeProvider.System);
        _ = new CibaRequestSigner("client", oidc, signing);
        string encoded = await signer.CreateAsync(new() { LoginHint = "user", RequestedExpirySeconds = 30 }, "openid"); var token = new JsonWebToken(encoded);
        Assert.AreEqual("client", token.Issuer); Assert.AreEqual(oidc.Issuer.AbsoluteUri, token.Audiences.Single());
        Assert.AreEqual(30, token.GetClaim("requested_expiry").Value is { } expiry ? int.Parse(expiry, System.Globalization.CultureInfo.InvariantCulture) : 0);
        Assert.IsTrue((await new JsonWebTokenHandler().ValidateTokenAsync(encoded, new TokenValidationParameters { ValidIssuer = "client", ValidAudience = oidc.Issuer.AbsoluteUri, IssuerSigningKey = signing.Key })).IsValid);
        await signer.CreateAsync(new() { LoginHint = "user" }, "openid");
        Assert.Throws<ArgumentException>(() => new CibaRequestSigner("", oidc, signing)); Assert.Throws<ArgumentNullException>(() => new CibaRequestSigner("c", null!, signing)); Assert.Throws<ArgumentNullException>(() => new CibaRequestSigner("c", oidc, null!));
        Assert.Throws<ArgumentException>(() => new CibaRequestSigner("c", oidc, new(new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(32)), "HS256")));
        Assert.Throws<ArgumentNullException>(() => signer.CreateAsync(null!, "openid")); Assert.Throws<ArgumentException>(() => signer.CreateAsync(new() { LoginHint = "u" }, ""));
        Assert.Throws<ArgumentException>(() => signer.CreateAsync(new() { SignedRequest = "nested" }, "openid"));
        using var cancel = new CancellationTokenSource(); cancel.Cancel(); await Assert.ThrowsAsync<OperationCanceledException>(() => signer.CreateAsync(new() { LoginHint = "u" }, "openid", cancel.Token).AsTask());
    }
    private static JsonElement Json(string value) { using var document = JsonDocument.Parse(value); return document.RootElement.Clone(); }
    private sealed class Clock(DateTimeOffset now) : TimeProvider { public override DateTimeOffset GetUtcNow() => now; }
    private sealed class Handler : HttpMessageHandler
    {
        internal string Body = "", Path = "", Authorization = ""; internal int Sends;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        { cancellationToken.ThrowIfCancellationRequested(); Sends++; Body = request.Content is null ? "" : await request.Content.ReadAsStringAsync(cancellationToken); Path = request.RequestUri!.AbsolutePath; Authorization = request.Headers.Authorization?.ToString() ?? ""; return new(HttpStatusCode.OK) { Content = new StringContent("{}") }; }
    }
}
