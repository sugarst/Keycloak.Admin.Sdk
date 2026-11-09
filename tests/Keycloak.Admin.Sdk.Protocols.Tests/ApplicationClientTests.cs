using System.Net;
using System.Text.Json;
using Keycloak.Admin.Sdk.Protocols;
using Microsoft.VisualStudio.TestTools.UnitTesting;

[TestClass]
public sealed class ApplicationClientTests
{
    [TestMethod]
    public async Task AdvancedOidcFlowsKeepActorLegacyParAndLogoutParametersDistinct()
    {
        using var handler = new Handler(); using var http = new HttpClient(handler);
        var oidc = new OidcClient(new(http, new("https://identity.invalid"), "r")); var auth = OAuthClientAuthentication.Public("app");
        await oidc.ExchangeDelegatedAsync(auth, "subject", "actor", "api", "openid");
        StringAssert.Contains(handler.Body, "actor_token=actor"); StringAssert.Contains(handler.Body, "subject_token=subject");
        StringAssert.Contains(handler.Body, "audience=api"); await oidc.ExchangeDelegatedAsync(auth, "subject", "actor");
        Assert.IsFalse(handler.Body.Contains("audience", StringComparison.Ordinal));
        Assert.Throws<ArgumentException>(() => oidc.ExchangeDelegatedAsync(auth, "", "actor"));
        Assert.Throws<ArgumentException>(() => oidc.ExchangeDelegatedAsync(auth, "subject", ""));
        await oidc.ExchangeLegacyAsync(auth, "external", "broker", "target-broker", "target-user", "api");
        StringAssert.Contains(handler.Body, "requested_issuer=target-broker"); StringAssert.Contains(handler.Body, "requested_subject=target-user");
        await oidc.ExchangeLegacyAsync(auth, "external", "broker"); Assert.IsFalse(handler.Body.Contains("requested_", StringComparison.Ordinal));
        Assert.Throws<ArgumentException>(() => oidc.ExchangeLegacyAsync(auth, "", "broker"));
        Assert.Throws<ArgumentException>(() => oidc.ExchangeLegacyAsync(auth, "token", ""));
        await oidc.ExchangeLegacyAsync(auth, "internal", requestedTokenType: TokenExchangeRequestedTokenType.RefreshToken);
        Assert.IsFalse(handler.Body.Contains("subject_issuer", StringComparison.Ordinal)); StringAssert.Contains(handler.Body, "refresh_token");
        await oidc.ExchangeLegacyAsync(auth, "internal", requestedTokenType: TokenExchangeRequestedTokenType.Saml2); StringAssert.Contains(handler.Body, "saml2");
        int credentialReads = 0;
        var onlyLegacy = new Keycloak.Admin.Sdk.Capabilities.KeycloakFeatureSnapshotGate(new Dictionary<string, bool> { ["KeycloakSdk.Protocols"] = true,
            ["KeycloakSdk.Protocols.Oidc"] = true, ["KeycloakSdk.Protocols.OidcLegacyExchange"] = true });
        var closedSaml = new OidcClient(new(http, new("https://identity.invalid"), "r", onlyLegacy));
        await Assert.ThrowsAsync<InvalidOperationException>(() => closedSaml.ExchangeLegacyAsync(OAuthClientAuthentication.SecretPost("app", _ => { credentialReads++; return ValueTask.FromResult("secret"); }), "internal", requestedTokenType: TokenExchangeRequestedTokenType.Saml2));
        Assert.AreEqual(0, credentialReads);
        await oidc.ExchangeLegacyAsync(auth, "internal", requestedTokenType: TokenExchangeRequestedTokenType.AccessToken);
        Assert.Throws<ArgumentOutOfRangeException>(() => oidc.ExchangeLegacyAsync(auth, "internal", requestedTokenType: TokenExchangeRequestedTokenType.IdToken));
        await oidc.ExchangeAsync(auth, "internal", requestedTokenType: TokenExchangeRequestedTokenType.IdToken); StringAssert.Contains(handler.Body, "id_token");
        await oidc.ExchangeAsync(auth, "internal", requestedTokenType: TokenExchangeRequestedTokenType.RefreshToken); StringAssert.Contains(handler.Body, "refresh_token");
        Assert.Throws<ArgumentOutOfRangeException>(() => oidc.ExchangeAsync(auth, "internal", requestedTokenType: TokenExchangeRequestedTokenType.Saml2));
        Assert.Throws<ArgumentOutOfRangeException>(() => oidc.ExchangeAsync(auth, "internal", requestedTokenType: (TokenExchangeRequestedTokenType)999));
        await oidc.ImpersonateLegacyAsync(auth, "target", "api"); StringAssert.Contains(handler.Body, "requested_subject=target"); StringAssert.Contains(handler.Body, "audience=api");
        Assert.IsFalse(handler.Body.Contains("subject_token", StringComparison.Ordinal));
        await oidc.ImpersonateLegacyAsync(auth, "target"); Assert.IsFalse(handler.Body.Contains("audience", StringComparison.Ordinal));
        Assert.Throws<ArgumentException>(() => oidc.ImpersonateLegacyAsync(auth, ""));
        await oidc.ExchangeLegacyAsync(auth, "external", "idp", subjectTokenType: TokenExchangeSubjectTokenType.IdToken); StringAssert.Contains(handler.Body, "id_token");
        await oidc.ExchangeLegacyAsync(auth, "external", "idp", subjectTokenType: TokenExchangeSubjectTokenType.Jwt); StringAssert.Contains(handler.Body, "jwt");
        Assert.Throws<ArgumentOutOfRangeException>(() => oidc.ExchangeLegacyAsync(auth, "external", subjectTokenType: (TokenExchangeSubjectTokenType)999));
        var transaction = new OidcLoginTransaction(oidc, "app", new("https://app.invalid/callback"));
        await oidc.PushAuthorizationAsync(auth, transaction.AuthorizationUri);
        Assert.AreEqual("/realms/r/protocol/openid-connect/ext/par/request", handler.Path);
        StringAssert.Contains(handler.Body, "client_id=app"); StringAssert.Contains(handler.Body, "code_challenge_method=S256");
        foreach (string suffix in new[] { "?client_id=other", "?a=1", "?client_id=app&bad", "?client_id=app&client_id=app", "?client_id=app#fragment" })
            await Assert.ThrowsAsync<ArgumentException>(() => oidc.PushAuthorizationAsync(auth, new("https://identity.invalid/realms/r/protocol/openid-connect/auth" + suffix)));
        await Assert.ThrowsAsync<ArgumentException>(() => oidc.PushAuthorizationAsync(auth, new("https://attacker.invalid/auth?client_id=app")));
        var pushed = oidc.CreatePushedAuthorizationUri("app", Response("""{"request_uri":"urn:request:123","expires_in":60}"""));
        StringAssert.Contains(pushed.Query, "request_uri=urn%3Arequest%3A123");
        foreach (string json in new[] { """{"request_uri":"","expires_in":60}""", """{"request_uri":"urn:request:x","expires_in":0}""" })
            Assert.Throws<InvalidDataException>(() => oidc.CreatePushedAuthorizationUri("app", Response(json)));
        Assert.Throws<InvalidDataException>(() => oidc.CreatePushedAuthorizationUri("app", new(HttpStatusCode.OK, null)));
        await oidc.LogoutAsync(auth, "refresh"); Assert.AreEqual("/realms/r/protocol/openid-connect/logout", handler.Path);
        StringAssert.Contains(handler.Body, "refresh_token=refresh");
        Assert.Throws<ArgumentException>(() => oidc.LogoutAsync(auth, ""));
        var logout = oidc.CreateLogoutUri("app", "id.jwt", new("https://app.invalid/signed-out"), "state");
        StringAssert.Contains(logout.Query, "id_token_hint=id.jwt"); StringAssert.Contains(logout.Query, "state=state");
    }

    [TestMethod]
    public async Task AccountSelfServiceOperationsUseOnlyTheCurrentUserTokenAndCorrectPayloads()
    {
        using var handler = new Handler(); using var http = new HttpClient(handler);
        var account = new AccountClient(new(http, new("https://identity.invalid"), "r"));
        await account.GetProfileAsync("user", [new("userProfileMetadata", "false")]); Assert.AreEqual("?userProfileMetadata=false", handler.Query);
        await account.GetApplicationsAsync("user", [new("name", "app")]); Assert.AreEqual("?name=app", handler.Query);
        await account.GetCredentialsAsync("user", [new("type", "otp")]); Assert.AreEqual("?type=otp", handler.Query);
        await account.GetLinkedAccountsAsync("user", [new("linked", "true")]); Assert.AreEqual("?linked=true", handler.Query);
        await account.GetOrganizationsAsync("user"); Assert.AreEqual("/realms/r/account/organizations", handler.Path);
        await account.GetGroupsAsync("user"); Assert.AreEqual("/realms/r/account/groups", handler.Path);
        await account.GetDevicesAsync("user"); Assert.AreEqual("/realms/r/account/sessions/devices", handler.Path);
        await account.GetSupportedLocalesAsync("user"); Assert.AreEqual("/realms/r/account/supportedLocales", handler.Path);
        await account.GetConsentAsync("app/a", "user"); Assert.AreEqual("/realms/r/account/applications/app%2Fa/consent", handler.Path);
        await account.UpdateConsentAsync("app", JsonDocument.Parse("""{"grantedScopes":[]}""").RootElement, "user");
        Assert.AreEqual("PUT", handler.Method); StringAssert.Contains(handler.Body, "grantedScopes");
        await account.RevokeConsentAsync("app", "user"); Assert.AreEqual("DELETE", handler.Method);
        await account.RevokeApplicationSessionsAsync("app", "user"); Assert.AreEqual("/realms/r/account/applications/app/sessions", handler.Path);
        await account.DeleteSessionAsync("session", "user"); Assert.AreEqual("/realms/r/account/sessions/session", handler.Path);
        await account.DeleteSessionsAsync(false, "user"); Assert.AreEqual("?current=false", handler.Query);
        await account.DeleteSessionsAsync(true, "user"); Assert.AreEqual("?current=true", handler.Query);
        Assert.Throws<ArgumentException>(() => account.DeleteSessionsAsync(true, ""));
        await account.UnlinkAccountAsync("broker", "user"); Assert.AreEqual("/realms/r/account/linked-accounts/broker", handler.Path);
        await account.SetCredentialLabelAsync("credential", "quoted \"label\"", "user");
        Assert.AreEqual("quoted \"label\"", JsonDocument.Parse(handler.Body).RootElement.GetString());
        Assert.AreEqual("/realms/r/account/credentials/credential/label", handler.Path);
        await account.DeleteCredentialAsync("credential", "user"); Assert.AreEqual("DELETE", handler.Method);
        Assert.AreEqual("Bearer user", handler.Authorization);
        Assert.Throws<ArgumentException>(() => account.DeleteCredentialAsync("credential", ""));
    }

    [TestMethod]
    public async Task ScimDiscoveryAndAuthZenDenialsRemainProtocolSpecific()
    {
        using var handler = new Handler(); using var http = new HttpClient(handler);
        var transport = new ProtocolTransport(http, new("https://identity.invalid"), "r"); var scim = new ScimClient(transport);
        await scim.GetServiceProviderConfigurationAsync("pat"); Assert.AreEqual("/realms/r/scim/v2/ServiceProviderConfig", handler.Path);
        await scim.GetSchemasAsync("pat"); Assert.AreEqual("/realms/r/scim/v2/Schemas", handler.Path);
        await scim.GetSchemaAsync("urn:extension", "pat"); StringAssert.Contains(handler.Path, "urn%3Aextension");
        await scim.GetResourceTypesAsync("pat"); Assert.AreEqual("/realms/r/scim/v2/ResourceTypes", handler.Path);
        handler.Response = """{"Resources":[{"id":"Other"},{"id":"User","endpoint":"/Users"}]}""";
        Assert.AreEqual("/Users", (await scim.GetResourceTypeAsync("User", "pat")).Json!.Value.GetProperty("endpoint").GetString());
        Assert.AreEqual("/realms/r/scim/v2/ResourceTypes", handler.Path);
        Assert.AreEqual(HttpStatusCode.NotFound, (await Assert.ThrowsAsync<KeycloakProtocolException>(() => scim.GetResourceTypeAsync("Missing", "pat"))).StatusCode);
        handler.Response = "";
        await Assert.ThrowsAsync<InvalidDataException>(() => scim.GetResourceTypeAsync("User", "pat"));
        handler.Response = "{}";
        var users = RealmResourceClient.ScimUsers(transport);
        await users.GetAsync("id", "pat", [new("attributes", "userName")]); Assert.AreEqual("?attributes=userName", handler.Query);
        await users.SearchAsync(JsonDocument.Parse("""{"filter":"userName pr"}""").RootElement, "pat"); Assert.AreEqual("/realms/r/scim/v2/Users/.search", handler.Path);
        Assert.Throws<NotSupportedException>(() => RealmResourceClient.UmaResources(transport).SearchAsync(default, "pat"));
        Assert.Throws<ArgumentException>(() => scim.GetSchemasAsync(""));
        Assert.Throws<ArgumentNullException>(() => new ScimClient(null!));
        var authzen = new AuthZenClient(transport);
        await authzen.DiscoverAsync(); Assert.AreEqual("/realms/r/.well-known/authzen-configuration", handler.Path);
        handler.Response = """{"decision":false}""";
        Assert.IsFalse(await authzen.EvaluateAsync(JsonDocument.Parse("{}").RootElement, "service"));
        Assert.AreEqual("/realms/r/authzen/access/v1/evaluation", handler.Path);
        handler.Response = """{"decision":true}""";
        Assert.IsTrue(await authzen.EvaluateAsync(JsonDocument.Parse("{}").RootElement, "service"));
        await authzen.EvaluateBatchAsync(JsonDocument.Parse("""{"evaluations":[]}""").RootElement, "service");
        Assert.AreEqual("/realms/r/authzen/access/v1/evaluations", handler.Path);
        handler.Response = "";
        await Assert.ThrowsAsync<InvalidDataException>(() => authzen.EvaluateAsync(JsonDocument.Parse("{}").RootElement, "service"));
        Assert.Throws<ArgumentException>(() => authzen.EvaluateBatchAsync(default, ""));
        Assert.Throws<ArgumentNullException>(() => new AuthZenClient(null!));
    }

    private static ProtocolResponse Response(string json) { using var document = JsonDocument.Parse(json); return new(HttpStatusCode.OK, document.RootElement.Clone()); }
    private sealed class Handler : HttpMessageHandler
    {
        internal string Path = "", Query = "", Method = "", Body = "", Authorization = "", Response = "{}";
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Path = request.RequestUri!.AbsolutePath; Query = request.RequestUri.Query; Method = request.Method.Method;
            Body = request.Content is null ? "" : await request.Content.ReadAsStringAsync(cancellationToken); Authorization = request.Headers.Authorization?.ToString() ?? "";
            return new(HttpStatusCode.OK) { Content = new StringContent(Response) };
        }
    }
}
