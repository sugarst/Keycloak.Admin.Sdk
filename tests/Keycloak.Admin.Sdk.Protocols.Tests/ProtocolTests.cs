using System.Net;
using System.Text;
using System.Text.Json;
using Keycloak.Admin.Sdk.Capabilities;
using Keycloak.Admin.Sdk.Protocols;
using Microsoft.VisualStudio.TestTools.UnitTesting;

[TestClass]
public sealed class ProtocolTests
{
    [TestMethod]
    public void AuthorizationUsesRfc7636PkceVectorAndEscapesValues()
    {
        using var http = new HttpClient();
        var client = new OidcClient(new(http, new Uri("https://identity.invalid/context/"), "realm +"));
        var uri = client.CreateAuthorizationUri("client &", new Uri("https://app.invalid/callback"), "state/secret", "nonce+", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
        StringAssert.Contains(uri.AbsoluteUri, "/context/realms/realm%20%2B/protocol/openid-connect/auth?");
        StringAssert.Contains(uri.Query, "code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
        StringAssert.Contains(uri.Query, "client_id=client%20%26");
        StringAssert.Contains(uri.Query, "state=state%2Fsecret");
        Assert.AreNotEqual(OidcClient.CreateVerifier(), OidcClient.CreateVerifier());
        Assert.Throws<ArgumentException>(() => client.CreateAuthorizationUri("c", new Uri("https://app.invalid/#fragment"), "s", "n", new string('a', 43)));
        Assert.Throws<ArgumentException>(() => client.CreateAuthorizationUri("c", new Uri("https://app.invalid/"), "s", "n", "short"));
    }

    [TestMethod]
    public async Task AuthenticationAndFormParametersFollowOAuthEncoding()
    {
        using var handler = new Handler(); using var http = new HttpClient(handler);
        var client = new OidcClient(new(http, new Uri("https://identity.invalid/"), "realm"));
        handler.Check = request =>
        {
            Assert.AreEqual("Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes("client%3A+%2B:s%3A+%2B%26")), request.Headers.Authorization!.ToString());
            Assert.AreEqual("application/x-www-form-urlencoded", request.Content!.Headers.ContentType!.MediaType);
        };
        await client.ClientCredentialsAsync(OAuthClientAuthentication.SecretBasic("client: +", _ => ValueTask.FromResult("s: +&")), "openid email");
        StringAssert.Contains(handler.Body, "grant_type=client_credentials");
        StringAssert.Contains(handler.Body, "scope=openid+email");
        Assert.IsFalse(handler.Body.Contains("client_secret", StringComparison.Ordinal));
        handler.Check = request => Assert.IsNull(request.Headers.Authorization);
        await client.ClientCredentialsAsync(OAuthClientAuthentication.SecretPost("client", _ => ValueTask.FromResult("secret+")));
        StringAssert.Contains(handler.Body, "client_secret=secret%2B");
        await client.ClientCredentialsAsync(OAuthClientAuthentication.JwtAssertion("client", _ => ValueTask.FromResult("signed.assertion")));
        StringAssert.Contains(handler.Body, "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer");
        StringAssert.Contains(handler.Body, "client_assertion=signed.assertion");
    }

    [TestMethod]
    public async Task GrantRequestsRemainDistinctAndNeverUseAdminEndpoints()
    {
        using var handler = new Handler(); using var http = new HttpClient(handler);
        var client = new OidcClient(new(http, new Uri("https://identity.invalid/"), "r"));
        var auth = OAuthClientAuthentication.Public("client");
        await client.RedeemCodeAsync(auth, "code+", new Uri("https://app.invalid/cb"), new string('v', 43));
        StringAssert.Contains(handler.Body, "grant_type=authorization_code");
        StringAssert.Contains(handler.Body, "code=code%2B");
        await client.RefreshAsync(auth, "refresh+", "scope");
        StringAssert.Contains(handler.Body, "refresh_token=refresh%2B");
        await client.ExchangeAsync(auth, "subject+", "api", "scope");
        StringAssert.Contains(handler.Body, "subject_token=subject%2B");
        StringAssert.Contains(handler.Body, "audience=api");
        Assert.IsFalse(handler.Body.Contains("client_secret", StringComparison.Ordinal));
        await client.ExchangeAsync(auth, "subject");
        Assert.IsFalse(handler.Body.Contains("audience", StringComparison.Ordinal));
        await client.JwtGrantAsync(auth, "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.grant.assertion");
        StringAssert.Contains(handler.Body, "assertion=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.grant.assertion");
        await client.RequestDeviceCodeAsync(auth);
        Assert.AreEqual("/realms/r/protocol/openid-connect/auth/device", handler.Path);
        await client.RedeemDeviceCodeAsync(auth, "device-code");
        StringAssert.Contains(handler.Body, "device_code=device-code");
        await client.RequestBackchannelAuthenticationAsync(auth, "user");
        Assert.AreEqual("/realms/r/protocol/openid-connect/ext/ciba/auth", handler.Path);
        await client.RedeemBackchannelAuthenticationAsync(auth, "request-id");
        StringAssert.Contains(handler.Body, "auth_req_id=request-id");
        await client.IntrospectAsync(auth, "token");
        Assert.AreEqual("/realms/r/protocol/openid-connect/token/introspect", handler.Path);
        await client.RevokeAsync(auth, "token");
        Assert.AreEqual("/realms/r/protocol/openid-connect/revoke", handler.Path);
        Assert.AreEqual(11, handler.Sends);
    }

    [TestMethod]
    public async Task DiscoveryAndUserInfoDoNotParseOrTrustJwtClaims()
    {
        using var handler = new Handler(); using var http = new HttpClient(handler);
        var client = new OidcClient(new(http, new Uri("https://identity.invalid/"), "r"));
        var discovery = await client.DiscoverAsync();
        Assert.AreEqual("/realms/r/.well-known/openid-configuration", handler.Path);
        Assert.AreEqual("test", discovery.Json!.Value.GetProperty("value").GetString());
        await client.GetSigningKeysAsync();
        Assert.AreEqual("/realms/r/protocol/openid-connect/certs", handler.Path);
        handler.Check = request => Assert.AreEqual("Bearer user-token", request.Headers.Authorization!.ToString());
        await client.GetUserInfoAsync("user-token");
        Assert.AreEqual("/realms/r/protocol/openid-connect/userinfo", handler.Path);
        // The detached JSON remains valid after the HTTP response has been disposed.
        Assert.AreEqual("test", discovery.Json.Value.GetProperty("value").GetString());
    }

    [TestMethod]
    public async Task AccountAndResourceClientsPreserveRealmUserAndExtensionPayloads()
    {
        using var handler = new Handler(); using var http = new HttpClient(handler);
        var transport = new ProtocolTransport(http, new Uri("https://identity.invalid/"), "r");
        using var payload = JsonDocument.Parse("""{"schemas":["custom:extension"],"custom:extension":{"active":false}}""");
        var account = new AccountClient(transport);
        handler.Check = request => Assert.AreEqual("Bearer user-token", request.Headers.Authorization!.ToString());
        await account.GetProfileAsync("user-token"); Assert.AreEqual("/realms/r/account/", handler.Path);
        await account.UpdateProfileAsync("user-token", payload.RootElement); Assert.AreEqual("POST", handler.Method);
        await account.GetSessionsAsync("user-token"); Assert.IsTrue(handler.Path.EndsWith("/sessions", StringComparison.Ordinal));
        await account.GetApplicationsAsync("user-token");
        await account.GetCredentialsAsync("user-token");
        await account.GetLinkedAccountsAsync("user-token");
        foreach (var resource in new[] { RealmResourceClient.ScimUsers(transport), RealmResourceClient.ScimGroups(transport), RealmResourceClient.UmaResources(transport), RealmResourceClient.ClientRegistration(transport) })
        {
            await resource.CreateAsync(payload.RootElement, "user-token");
            StringAssert.Contains(handler.Body, "\"active\":false");
            await resource.GetAsync("id/+", "user-token"); StringAssert.Contains(handler.Path, "/id%2F%2B");
            await resource.ReplaceAsync("id", payload.RootElement, "user-token"); Assert.AreEqual("PUT", handler.Method);
            await resource.DeleteAsync("id", "user-token"); Assert.AreEqual("DELETE", handler.Method);
        }
        var scim = RealmResourceClient.ScimUsers(transport);
        await scim.ListAsync("user-token", [new("filter", "userName eq \"a+b\"")]);
        StringAssert.Contains(handler.Query, "filter=userName%20eq%20%22a%2Bb%22");
        await scim.PatchAsync("id", payload.RootElement, "user-token"); Assert.AreEqual("PATCH", handler.Method);
        await Assert.ThrowsAsync<NotSupportedException>(() => RealmResourceClient.UmaResources(transport).PatchAsync("id", payload.RootElement, "user-token"));
        await Assert.ThrowsAsync<NotSupportedException>(() => RealmResourceClient.ClientRegistration(transport).ListAsync("user-token"));
    }

    [TestMethod]
    public async Task HostDenialAndCancellationHappenBeforeCredentialsAndTransport()
    {
        using var handler = new Handler(); using var http = new HttpClient(handler);
        var flags = new KeycloakFeatureSnapshotGate(new Dictionary<string, bool>());
        var client = new OidcClient(new(http, new Uri("https://identity.invalid/"), "r", flags));
        int credentials = 0;
        var auth = OAuthClientAuthentication.SecretPost("c", _ => { credentials++; return ValueTask.FromResult("s"); });
        await Assert.ThrowsAsync<InvalidOperationException>(() => client.ClientCredentialsAsync(auth));
        flags.Replace(new Dictionary<string, bool> { ["KeycloakSdk.Protocols"] = true });
        await Assert.ThrowsAsync<InvalidOperationException>(() => client.ClientCredentialsAsync(auth));
        Assert.AreEqual(0, credentials); Assert.AreEqual(0, handler.Sends);
        flags.Replace(new Dictionary<string, bool> { ["KeycloakSdk.Protocols"] = true, ["KeycloakSdk.Protocols.Oidc"] = true });
        using var cancellation = new CancellationTokenSource(); cancellation.Cancel();
        await Assert.ThrowsAsync<OperationCanceledException>(() => client.ClientCredentialsAsync(auth, cancellationToken: cancellation.Token));
        await client.ClientCredentialsAsync(auth);
        Assert.AreEqual(1, credentials); Assert.AreEqual(1, handler.Sends);
    }

    [TestMethod]
    public async Task SnapshotReloadCannotCombineTwoIndividuallyDeniedGenerations()
    {
        using var handler = new Handler(); using var http = new HttpClient(handler);
        var first = new Dictionary<string, bool> { ["KeycloakSdk.Protocols"] = true, ["KeycloakSdk.Protocols.Oidc"] = false };
        var second = new Dictionary<string, bool> { ["KeycloakSdk.Protocols"] = false, ["KeycloakSdk.Protocols.Oidc"] = true };
        var flags = new KeycloakFeatureSnapshotGate(first);
        var client = new OidcClient(new(http, new Uri("https://identity.invalid/"), "r", flags));
        var producer = Task.Run(() => { for (int i = 0; i < 3000; i++) { flags.Replace(i % 2 == 0 ? first : second); Thread.Yield(); } });
        for (int i = 0; i < 1000; i++) await Assert.ThrowsAsync<InvalidOperationException>(() => client.DiscoverAsync());
        await producer;
        Assert.AreEqual(0, handler.Sends);
    }

    [TestMethod]
    public async Task CustomHostGateEvaluatesMasterBeforeFeatureAndPropagatesErrors()
    {
        using var handler = new Handler(); using var http = new HttpClient(handler);
        var gate = new Gate();
        var client = new OidcClient(new(http, new Uri("https://identity.invalid/"), "r", gate));
        await Assert.ThrowsAsync<InvalidOperationException>(() => client.DiscoverAsync());
        Assert.AreEqual(1, gate.Calls);
        gate.Master = true;
        await Assert.ThrowsAsync<InvalidOperationException>(() => client.DiscoverAsync());
        Assert.AreEqual(3, gate.Calls);
        gate.Feature = true;
        await client.DiscoverAsync(); Assert.AreEqual(1, handler.Sends);
        gate.Fail = true;
        await Assert.ThrowsAsync<IOException>(() => client.DiscoverAsync()); Assert.AreEqual(1, handler.Sends);
    }

    private sealed class Gate : IKeycloakFeatureGate
    {
        public bool Master, Feature, Fail; public int Calls;
        public ValueTask<bool> IsEnabledAsync(string featureId, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested(); Calls++;
            if (Fail) throw new IOException("Gate failure");
            return ValueTask.FromResult(featureId == "KeycloakSdk.Protocols" ? Master : Feature);
        }
    }

    [TestMethod]
    public async Task ErrorBodiesAndTokensDoNotEscapeAndRequestsAreNotRetried()
    {
        using var handler = new Handler { Status = HttpStatusCode.Unauthorized, Response = "token-secret-and-PII" }; using var http = new HttpClient(handler);
        var client = new OidcClient(new(http, new Uri("https://identity.invalid/"), "r"));
        var error = await Assert.ThrowsAsync<KeycloakProtocolException>(() => client.ExchangeAsync(OAuthClientAuthentication.Public("c"), "subject-secret"));
        Assert.AreEqual(HttpStatusCode.Unauthorized, error.StatusCode);
        Assert.IsFalse(error.ToString().Contains("secret", StringComparison.Ordinal));
        Assert.AreEqual(1, handler.Sends);
        handler.Status = HttpStatusCode.NoContent;
        Assert.IsNull((await client.RevokeAsync(OAuthClientAuthentication.Public("c"), "t")).Json);
        handler.Status = HttpStatusCode.OK; handler.Response = "";
        Assert.IsNull((await client.RevokeAsync(OAuthClientAuthentication.Public("c"), "t")).Json);
        handler.Response = "malformed";
        await Assert.ThrowsAsync<JsonException>(() => client.DiscoverAsync());
    }

    [TestMethod]
    public async Task BoundaryValidationDisposalAndCancellationAreFailClosed()
    {
        using var handler = new Handler(); using var http = new HttpClient(handler);
        var transport = new ProtocolTransport(http, new Uri("http://identity.invalid/"), "r");
        foreach (string path in new[] { "", " ", "/path", "a\\b", "a?secret", "a#fragment", "a/.", "a/..", "a/%2e", "a/%2e%2e", "https://other.invalid/path" })
            Assert.Throws<ArgumentException>(() => transport.Target(path));
        Assert.Throws<ArgumentNullException>(() => new ProtocolTransport(null!, new Uri("https://identity.invalid/"), "r"));
        Assert.Throws<ArgumentNullException>(() => new ProtocolTransport(http, null!, "r"));
        Assert.Throws<ArgumentException>(() => new ProtocolTransport(http, new Uri("relative", UriKind.Relative), "r"));
        Assert.Throws<ArgumentException>(() => new ProtocolTransport(http, new Uri("https://identity.invalid/"), "."));
        Assert.Throws<ArgumentNullException>(() => new OidcClient(null!));
        Assert.Throws<ArgumentNullException>(() => new AccountClient(null!));
        Assert.Throws<ArgumentNullException>(() => RealmResourceClient.ScimUsers(null!));
        Assert.Throws<ArgumentNullException>(() => OAuthClientAuthentication.SecretBasic("c", null!));
        Assert.Throws<ArgumentNullException>(() => OAuthClientAuthentication.JwtAssertion("c", null!));
        var oidc = new OidcClient(transport);
        foreach (string verifier in new[] { null!, new string('v', 129), new string('v', 42), new string('v', 42) + "!" })
            Assert.Throws<ArgumentException>(() => oidc.CreateAuthorizationUri("c", new Uri("https://app.invalid/"), "s", "n", verifier));
        foreach (var redirect in new Uri[] { null!, new("relative", UriKind.Relative), new("https://user:secret@app.invalid/") })
            Assert.Throws<ArgumentException>(() => oidc.CreateAuthorizationUri("c", redirect, "s", "n", new string('v', 43)));
        oidc.CreateAuthorizationUri("c", new Uri("https://app.invalid/"), "s", "n", new string('v', 39) + "-._~");
        await RealmResourceClient.ScimUsers(transport).ListAsync("t", []);
        await RealmResourceClient.ClientRegistration(transport).CreateAsync(JsonDocument.Parse("{}").RootElement);
        Assert.Throws<ArgumentException>(() => oidc.GetUserInfoAsync(" "));
        Assert.Throws<ArgumentException>(() => new AccountClient(transport).GetProfileAsync(" "));
        Assert.Throws<ArgumentException>(() => new AccountClient(transport).UpdateProfileAsync(" ", default));
        var emptySecret = OAuthClientAuthentication.SecretPost("c", _ => ValueTask.FromResult(""));
        await Assert.ThrowsAsync<ArgumentException>(() => oidc.ClientCredentialsAsync(emptySecret));
        using var cancellation = new CancellationTokenSource();
        var cancelling = OAuthClientAuthentication.SecretPost("c", _ => { cancellation.Cancel(); return ValueTask.FromResult("s"); });
        int count = handler.Sends;
        await Assert.ThrowsAsync<OperationCanceledException>(() => oidc.ClientCredentialsAsync(cancelling, cancellationToken: cancellation.Token));
        Assert.AreEqual(count, handler.Sends);
    }

    [TestMethod]
    public void ServerAndIdentityValidationRejectsAmbiguousInputs()
    {
        using var http = new HttpClient();
        foreach (string uri in new[] { "file:///tmp", "https://user:secret@identity.invalid/", "https://identity.invalid/?query", "https://identity.invalid/#fragment" })
            Assert.Throws<ArgumentException>(() => new ProtocolTransport(http, new Uri(uri), "r"));
        Assert.Throws<ArgumentException>(() => new ProtocolTransport(http, new Uri("https://identity.invalid/"), ".."));
        Assert.Throws<ArgumentException>(() => OAuthClientAuthentication.Public(" "));
        Assert.Throws<ArgumentNullException>(() => OAuthClientAuthentication.SecretPost("c", null!));
    }

    private sealed class Handler : HttpMessageHandler
    {
        public int Sends; public string Path = "", Method = "", Body = "", Query = "";
        public Action<HttpRequestMessage>? Check;
        public HttpStatusCode Status = HttpStatusCode.OK;
        public string Response = """{"value":"test"}""";
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested(); Sends++;
            Path = request.RequestUri!.AbsolutePath; Query = request.RequestUri.Query; Method = request.Method.Method;
            Body = request.Content is null ? "" : await request.Content.ReadAsStringAsync(cancellationToken);
            Check?.Invoke(request);
            return new(Status) { Content = new StringContent(Response) };
        }
    }
}
