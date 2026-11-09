using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Keycloak.Admin.Sdk.Capabilities;
using Keycloak.Admin.Sdk.Protocols;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualStudio.TestTools.UnitTesting;

[TestClass]
public sealed class SignalAndBrokerTests
{
    private const string Verification = "https://schemas.openid.net/secevent/ssf/event-type/verification";
    [TestMethod]
    public async Task BrokerSeparatesTheUserTokenFromClientAuthenticationAndPinsEveryProviderPath()
    {
        using var handler = new Handler(); using var http = new HttpClient(handler);
        var transport = new ProtocolTransport(http, new("https://identity.invalid/"), "r"); var broker = new IdentityBrokerClient(transport);
        await broker.GetTokenLegacyAsync("provider/id", "user"); Assert.AreEqual("GET", handler.Method); Assert.AreEqual("Bearer user", handler.Authorization);
        Assert.AreEqual("/realms/r/broker/provider%2Fid/token", handler.Path);
        await broker.GetTokenAsync("provider", OAuthClientAuthentication.SecretPost("client", _ => ValueTask.FromResult("secret")), "user+");
        Assert.AreEqual("POST", handler.Method); Assert.IsNull(handler.Authorization);
        StringAssert.Contains(handler.Body, "token=user%2B"); StringAssert.Contains(handler.Body, "client_secret=secret");
        var uri = broker.CreateLegacyLinkUri("provider", "client", "session", new("https://app.invalid/callback"), "nonce");
        StringAssert.Contains(uri.Query, "hash=" + Base64UrlEncoder.Encode(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes("noncesessionclientprovider"))));
        Assert.Throws<ArgumentException>(() => broker.CreateLegacyLinkUri("provider", "", "s", new("https://app.invalid"), "n"));
        Assert.Throws<ArgumentException>(() => broker.CreateLegacyLinkUri("provider", "c", "", new("https://app.invalid"), "n"));
        Assert.Throws<ArgumentException>(() => broker.CreateLegacyLinkUri("provider", "c", "s", new("https://app.invalid"), ""));
        Assert.Throws<ArgumentException>(() => broker.GetTokenLegacyAsync("p", "")); Assert.Throws<ArgumentException>(() => broker.GetTokenAsync("p", OAuthClientAuthentication.Public("c"), ""));
        Assert.Throws<ArgumentNullException>(() => broker.GetTokenAsync("p", null!, "u")); Assert.Throws<ArgumentNullException>(() => new IdentityBrokerClient(null!));
        var disabled = new IdentityBrokerClient(new(http, new("https://identity.invalid/"), "r", new KeycloakFeatureSnapshotGate([])));
        int before = handler.Sends;
        await Assert.ThrowsAsync<InvalidOperationException>(() => disabled.GetTokenAsync("p", OAuthClientAuthentication.SecretPost("c", _ => throw new AssertFailedException("No credentials before gate")), "u"));
        Assert.AreEqual(before, handler.Sends);
    }

    [TestMethod]
    public async Task SsfContractsUseCollectionQueryIdsAndNeverTrustDeliveryUrlsForAuthentication()
    {
        using var handler = new Handler(); using var http = new HttpClient(handler); var client = new SsfClient(new(http, new("https://identity.invalid/"), "r"));
        var json = JsonDocument.Parse("{}").RootElement;
        await client.DiscoverAsync(); Assert.IsNull(handler.Authorization); Assert.AreEqual("/realms/r/.well-known/ssf-configuration", handler.Path);
        await client.CreateStreamAsync(json, "receiver"); Assert.AreEqual("POST", handler.Method); Assert.AreEqual("/realms/r/ssf/transmitter/streams", handler.Path);
        await client.GetStreamsAsync("receiver"); Assert.AreEqual("", handler.Query);
        await client.GetStreamAsync("stream/id", "receiver"); Assert.AreEqual("?stream_id=stream%2Fid", handler.Query);
        await client.UpdateStreamAsync(json, "receiver"); Assert.AreEqual("PATCH", handler.Method);
        await client.ReplaceStreamAsync(json, "receiver"); Assert.AreEqual("PUT", handler.Method);
        await client.GetStatusAsync("stream", "receiver"); Assert.AreEqual("/realms/r/ssf/transmitter/streams/status", handler.Path);
        await client.UpdateStatusAsync(json, "receiver"); Assert.AreEqual("POST", handler.Method);
        await client.VerifyAsync(json, "receiver"); Assert.AreEqual("/realms/r/ssf/transmitter/verify", handler.Path);
        await client.AddSubjectAsync(json, "receiver"); Assert.AreEqual("/realms/r/ssf/transmitter/subjects/add", handler.Path);
        await client.RemoveSubjectAsync(json, "receiver"); Assert.AreEqual("/realms/r/ssf/transmitter/subjects/remove", handler.Path);
        await client.PollAsync("client/id", "stream/id", json, "receiver"); Assert.AreEqual("/realms/r/ssf/transmitter/receivers/client%2Fid/streams/stream%2Fid/poll", handler.Path);
        Assert.AreEqual("Bearer receiver", handler.Authorization); Assert.AreEqual("application/json", handler.Media);
        await client.DeleteStreamAsync("stream", "receiver"); Assert.AreEqual("DELETE", handler.Method); Assert.AreEqual("?stream_id=stream", handler.Query);
        Assert.Throws<ArgumentNullException>(() => new SsfClient(null!)); Assert.Throws<ArgumentException>(() => client.GetStreamAsync("", "t"));
        Assert.Throws<ArgumentException>(() => client.GetStreamsAsync(""));
    }

    [TestMethod]
    public async Task SsfSameMethodPollUpdatesPreserveOnlyTheTransmitterEndpointFromAnAuthorizedRead()
    {
        using var handler = new Handler(); using var http = new HttpClient(handler); var client = new SsfClient(new(http, new("https://identity.invalid/"), "r"));
        const string endpoint = "https://identity.invalid/realms/r/ssf/transmitter/receivers/client/streams/id/poll";
        JsonElement Json(string value) => JsonDocument.Parse(value).RootElement;
        handler.Response = "{\"delivery\":{\"method\":\"urn:ietf:rfc:8936\",\"endpoint_url\":\"" + endpoint + "\"}}";
        await client.ReplaceStreamAsync(Json("""{"stream_id":"id","description":"new","delivery":{"method":"urn:ietf:rfc:8936"}}"""), "receiver");
        Assert.AreEqual(2, handler.Sends); Assert.AreEqual("PUT", handler.Method); StringAssert.Contains(handler.Body, endpoint);
        await client.UpdateStreamAsync(Json("""{"stream_id":"id","delivery":{"method":"urn:ietf:rfc:8936"}}"""), "receiver"); Assert.AreEqual("PATCH", handler.Method);
        foreach (string payload in new[] { "[]", "{}", """{"delivery":[]}""", """{"delivery":{}}""", """{"delivery":{"method":42}}""",
            """{"delivery":{"method":"urn:ietf:rfc:8935"}}""", """{"delivery":{"method":"urn:ietf:rfc:8936","endpoint_url":"explicit"}}""" })
        { int before = handler.Sends; await client.ReplaceStreamAsync(Json(payload), "receiver"); Assert.AreEqual(before + 1, handler.Sends); }
        foreach (string id in new[] { "", "null", "42", "\" \"" })
        {
            string field = id.Length == 0 ? "" : "\"stream_id\":" + id + ",";
            await Assert.ThrowsAsync<ArgumentException>(() => client.ReplaceStreamAsync(Json("{" + field + "\"delivery\":{\"method\":\"urn:ietf:rfc:8936\"}}"), "receiver"));
        }
        foreach (string invalid in new[] { "null", "\"https://attacker.invalid/streams/id/poll\"", "\"https://identity.invalid/realms/r/ssf/transmitter/receivers/client/streams/other/poll\"" })
        {
            handler.Response = "{\"delivery\":{\"method\":\"urn:ietf:rfc:8936\",\"endpoint_url\":" + invalid + "}}";
            await Assert.ThrowsAsync<InvalidDataException>(() => client.ReplaceStreamAsync(Json("""{"stream_id":"id","delivery":{"method":"urn:ietf:rfc:8936"}}"""), "receiver"));
        }
        handler.Response = "";
        await Assert.ThrowsAsync<InvalidDataException>(() => client.ReplaceStreamAsync(Json("""{"stream_id":"id","delivery":{"method":"urn:ietf:rfc:8936"}}"""), "receiver"));
        handler.Response = """{"delivery":{"method":"urn:ietf:rfc:8935"}}""";
        await client.ReplaceStreamAsync(Json("""{"stream_id":"id","delivery":{"method":"urn:ietf:rfc:8936"}}"""), "receiver"); Assert.IsFalse(handler.Body.Contains("endpoint_url", StringComparison.Ordinal));
        handler.Response = "{\"delivery\":{\"method\":\"https://schemas.openid.net/secevent/risc/delivery-method/poll\",\"endpoint_url\":\"" + endpoint + "\"}}";
        await client.ReplaceStreamAsync(Json("""{"stream_id":"id","delivery":{"method":"https://schemas.openid.net/secevent/risc/delivery-method/poll"}}"""), "receiver"); StringAssert.Contains(handler.Body, endpoint);
    }

    [TestMethod]
    public async Task SecurityEventsRequireTrustedSignaturesAudienceTimeSubscriptionAndAtomicReplayProtection()
    {
        using var fixture = new EventFixture(); var replay = new InMemoryDpopReplayStore();
        var validator = new SecurityEventTokenValidator(fixture.Oidc, "receiver", [Verification], replay);
        string credential = fixture.Token(); var token = await validator.ValidateAsync(credential);
        Assert.AreEqual("state", token.Events.GetProperty(Verification).GetProperty("state").GetString()); Assert.IsTrue(token.Id.Length > 0);
        Assert.IsFalse(token.ToString()!.Contains(credential, StringComparison.Ordinal));
        await Assert.ThrowsAsync<InvalidDataException>(() => validator.ValidateAsync(credential));
        foreach (var mutate in new Action<Dictionary<string, object>>[] { c => c.Remove("iat"), c => c["iat"] = "wrong", c => c["iat"] = 1.2, c => c["iat"] = 0L,
            c => c["iat"] = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds(), c => c.Remove("jti"), c => c["jti"] = 42, c => c["jti"] = " ", c => c["jti"] = new string('x', 257),
            c => c.Remove("events"), c => c["events"] = new JsonArray(), c => c["events"] = new JsonObject(), c => c["events"] = new JsonObject { ["unknown"] = new JsonObject() },
            c => c["events"] = new JsonObject { [Verification] = 42 } })
            await Assert.ThrowsAsync<InvalidDataException>(() => validator.ValidateAsync(fixture.Token(mutate: mutate)));
        foreach (string invalid in new[] { "malformed", fixture.Token(audience: "other"), fixture.Token(issuer: "https://attacker.invalid"), fixture.Token(type: "JWT"), fixture.Token(wrongKey: true), fixture.Token(algorithm: "RS384") })
            await Assert.ThrowsAsync<InvalidDataException>(() => validator.ValidateAsync(invalid));
        await new SecurityEventTokenValidator(fixture.Oidc, "receiver", [Verification], replay, allowedAlgorithms: ["RS384"]).ValidateAsync(fixture.Token(algorithm: "RS384"));
        fixture.Handler.Response = ""; await Assert.ThrowsAsync<InvalidDataException>(() => validator.ValidateAsync(fixture.Token()));
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel(); await Assert.ThrowsAsync<OperationCanceledException>(() => validator.ValidateAsync(credential, cancelled.Token));
    }

    [TestMethod]
    public async Task ProcessingCommitsIdempotentBusinessEffectsBeforeAcknowledgementAndAllowsStorageRetry()
    {
        using var fixture = new EventFixture(); var inbox = new TestInbox { FailNext = true };
        var processor = new SecurityEventProcessor(fixture.Transport, "receiver", [Verification], inbox);
        string token = fixture.Token(mutate: c => c["jti"] = "delivery");
        await Assert.ThrowsAsync<IOException>(() => processor.ProcessAsync(token));
        Assert.AreEqual(0, inbox.Effects);
        await processor.ProcessAsync(token, "delivery"); await processor.ProcessAsync(token);
        Assert.AreEqual(1, inbox.Effects); Assert.IsTrue(inbox.Last!.RetainUntil > DateTimeOffset.UtcNow.AddMinutes(5));
        Assert.AreEqual(43, inbox.Last.ReceiptKey.Length); Assert.AreEqual("delivery", inbox.Last.Token.Id);
        await Assert.ThrowsAsync<InvalidDataException>(() => processor.ProcessAsync(token, "different-key"));
        var response = new ProtocolResponse(HttpStatusCode.OK, Json("{\"sets\":{\"delivery\":" + JsonValue.Create(token)!.ToJsonString() + "}}"));
        CollectionAssert.AreEqual(new[] { "delivery" }, (await processor.ProcessPollResponseAsync(response)).ToArray());
        Assert.AreEqual(1, inbox.Effects);
        Assert.AreEqual(0, (await processor.ProcessPollResponseAsync(new(HttpStatusCode.OK, Json("{\"sets\":{}}")))).Count);
        foreach (string invalid in new[] { "{}", "[]", "{\"sets\":[]}", "{\"sets\":{\"delivery\":42}}", "{\"sets\":{\"a\":\"x\",\"a\":\"x\"}}",
            new JsonObject { ["sets"] = new JsonObject(Enumerable.Range(0, 1001).Select(i => KeyValuePair.Create<string, JsonNode?>("id" + i, JsonValue.Create("x")))) }.ToJsonString() })
            await Assert.ThrowsAsync<InvalidDataException>(() => processor.ProcessPollResponseAsync(new(HttpStatusCode.OK, Json(invalid))));
        await Assert.ThrowsAsync<InvalidDataException>(() => processor.ProcessPollResponseAsync(new(HttpStatusCode.NoContent, null)));
        await Assert.ThrowsAsync<ArgumentNullException>(() => processor.ProcessPollResponseAsync(null!));
        Assert.Throws<ArgumentNullException>(() => new SecurityEventProcessor(null!, "receiver", [Verification], inbox));
        Assert.Throws<ArgumentNullException>(() => new SecurityEventProcessor(fixture.Transport, "receiver", [Verification], null!));
        var explicitOptions = new SecurityEventProcessor(fixture.Transport, "receiver", [Verification], inbox, TimeSpan.FromMinutes(1), TimeProvider.System, ["RS256"]);
        await explicitOptions.ProcessAsync(fixture.Token());
        using var cancel = new CancellationTokenSource(); cancel.Cancel(); int sent = fixture.Handler.Sends;
        await Assert.ThrowsAsync<OperationCanceledException>(() => processor.ProcessAsync(token, cancellationToken: cancel.Token));
        Assert.AreEqual(sent, fixture.Handler.Sends);
    }

    private sealed class TestInbox : ISecurityEventInbox
    {
        private readonly HashSet<string> receipts = []; internal int Effects; internal bool FailNext; internal SecurityEventDelivery? Last;
        public ValueTask ApplyOnceAsync(SecurityEventDelivery delivery, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested(); if (FailNext) { FailNext = false; throw new IOException("simulated storage failure"); }
            if (receipts.Add(delivery.ReceiptKey)) Effects++; Last = delivery; return ValueTask.CompletedTask;
        }
    }
    private static JsonElement Json(string value) { using var document = JsonDocument.Parse(value); return document.RootElement.Clone(); }

    [TestMethod]
    public async Task LogoutTokensCannotBeSubstitutedForSecurityEventsOrUnrelatedUserSessions()
    {
        using var fixture = new EventFixture(); const string logout = "http://schemas.openid.net/event/backchannel-logout";
        var validator = new OidcLogoutTokenValidator(fixture.Oidc, "receiver", new InMemoryDpopReplayStore(), TimeSpan.FromMinutes(3), TimeProvider.System, ["RS256"]);
        Action<Dictionary<string, object>> valid = c => { c["events"] = new JsonObject { [logout] = new JsonObject() }; c["sid"] = "session"; };
        string credential = fixture.Token(type: "JWT", mutate: valid);
        var result = await validator.ValidateAsync(credential); Assert.AreEqual("session", result.Claims.GetProperty("sid").GetString());
        await Assert.ThrowsAsync<InvalidDataException>(() => validator.ValidateAsync(credential));
        await validator.ValidateAsync(fixture.Token(type: "logout+jwt", mutate: c => { valid(c); c.Remove("sid"); c["sub"] = "user"; }));
        foreach (Action<Dictionary<string, object>> invalid in new Action<Dictionary<string, object>>[] { c => { valid(c); c["nonce"] = "not-allowed"; }, c => { valid(c); c.Remove("sid"); },
            c => { valid(c); c["sub"] = 42; c["sid"] = 42; }, c => { valid(c); c["sub"] = " "; c["sid"] = " "; }, c => c["events"] = new JsonObject { [Verification] = new JsonObject() },
            c => { valid(c); c["events"] = new JsonObject { [logout] = 42 }; } })
            await Assert.ThrowsAsync<InvalidDataException>(() => validator.ValidateAsync(fixture.Token(type: "JWT", mutate: invalid)));
        Assert.Throws<ArgumentNullException>(() => new SecurityEventTokenValidator(fixture.Oidc, "r", null!, new InMemoryDpopReplayStore()));
        foreach (string[] types in new[] { Array.Empty<string>(), new[] { " " } }) Assert.Throws<ArgumentException>(() => new SecurityEventTokenValidator(fixture.Oidc, "r", types, new InMemoryDpopReplayStore()));
        Assert.Throws<ArgumentNullException>(() => new OidcLogoutTokenValidator(null!, "r", new InMemoryDpopReplayStore()));
        Assert.Throws<ArgumentException>(() => new OidcLogoutTokenValidator(fixture.Oidc, "", new InMemoryDpopReplayStore()));
        Assert.Throws<ArgumentNullException>(() => new OidcLogoutTokenValidator(fixture.Oidc, "r", null!));
        foreach (TimeSpan age in new[] { TimeSpan.Zero, TimeSpan.FromDays(2) }) Assert.Throws<ArgumentOutOfRangeException>(() => new OidcLogoutTokenValidator(fixture.Oidc, "r", new InMemoryDpopReplayStore(), age));
        foreach (string[] algorithms in new[] { Array.Empty<string>(), new[] { "HS256" } }) Assert.Throws<ArgumentException>(() => new OidcLogoutTokenValidator(fixture.Oidc, "r", new InMemoryDpopReplayStore(), allowedAlgorithms: algorithms));
    }

    private sealed class EventFixture : IDisposable
    {
        private readonly RSA key = RSA.Create(2048), other = RSA.Create(2048); internal readonly Handler Handler = new(); private readonly HttpClient http; internal readonly OidcClient Oidc; internal readonly ProtocolTransport Transport;
        internal EventFixture()
        {
            http = new(Handler); Transport = new(http, new("https://identity.invalid/"), "r"); Oidc = new(Transport); var p = key.ExportParameters(false);
            Handler.Response = new JsonObject { ["keys"] = new JsonArray(new JsonObject { ["kty"] = "RSA", ["e"] = Base64UrlEncoder.Encode(p.Exponent), ["n"] = Base64UrlEncoder.Encode(p.Modulus) }) }.ToJsonString();
        }
        internal string Token(string audience = "receiver", string? issuer = null, string type = "secevent+jwt", bool wrongKey = false, string algorithm = "RS256", Action<Dictionary<string, object>>? mutate = null)
        {
            var claims = new Dictionary<string, object> { ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), ["jti"] = Guid.NewGuid().ToString("N"),
                ["events"] = JsonDocument.Parse(new JsonObject { [Verification] = new JsonObject { ["state"] = "state" } }.ToJsonString()).RootElement };
            mutate?.Invoke(claims);
            // JsonNode serialization deliberately uses explicit JsonElement to exercise NativeAOT-safe payload contracts.
            foreach (string name in claims.Keys.ToArray()) if (claims[name] is JsonNode node) claims[name] = JsonDocument.Parse(node.ToJsonString()).RootElement;
            return new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(new SecurityTokenDescriptor { Issuer = issuer ?? Oidc.Issuer.AbsoluteUri,
                Audience = audience, TokenType = type, SigningCredentials = new(new RsaSecurityKey(wrongKey ? other : key), algorithm), Claims = claims });
        }
        public void Dispose() { http.Dispose(); key.Dispose(); other.Dispose(); }
    }
    private sealed class Handler : HttpMessageHandler
    {
        internal int Sends; internal string Method = "", Path = "", Query = "", Body = "", Media = "", Response = "{}"; internal string? Authorization;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested(); Sends++; Method = request.Method.Method; Path = request.RequestUri!.AbsolutePath; Query = request.RequestUri.Query;
            Authorization = request.Headers.Authorization?.ToString(); Media = request.Content?.Headers.ContentType?.MediaType ?? "";
            Body = request.Content is null ? "" : await request.Content.ReadAsStringAsync(cancellationToken);
            return new(HttpStatusCode.OK) { Content = new StringContent(Response) };
        }
    }
}
