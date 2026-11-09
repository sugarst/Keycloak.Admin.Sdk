using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Keycloak.Admin.Sdk.Capabilities;
using Keycloak.Admin.Sdk.Protocols;
using Microsoft.VisualStudio.TestTools.UnitTesting;

[TestClass]
public sealed class CimdTests
{
    [TestMethod]
    public async Task MetadataGatesBeforeBrowserInitiationAndBeforeReadingAClientAssertion()
    {
        using var handler = new Handler(); using var http = new HttpClient(handler); var flags = new KeycloakFeatureSnapshotGate(new Dictionary<string, bool>
        { ["KeycloakSdk.Protocols"] = true, ["KeycloakSdk.Protocols.Oidc"] = true });
        var oidc = new OidcClient(new(http, new("https://identity.invalid/"), "r", flags));
        var metadata = CimdClientMetadata.Create(new("https://client.invalid/metadata.json"), "Test", [new("https://client.invalid/cb")], new("https://client.invalid/jwks")); int reads = 0;
        var client = metadata.CreateAuthentication(_ => { reads++; return ValueTask.FromResult("assertion"); });
        await Assert.ThrowsAsync<InvalidOperationException>(() => OidcLoginTransaction.StartAsync(oidc, client, new("https://client.invalid/cb")));
        await Assert.ThrowsAsync<InvalidOperationException>(() => oidc.ClientCredentialsAsync(client)); Assert.AreEqual(0, reads); Assert.AreEqual(0, handler.Sends);
        flags.Replace(new Dictionary<string, bool> { ["KeycloakSdk.Protocols"] = true, ["KeycloakSdk.Protocols.Oidc"] = true, ["KeycloakSdk.Protocols.OidcClientMetadata"] = true });
        await OidcLoginTransaction.StartAsync(oidc, client, new("https://client.invalid/cb")); Assert.AreEqual(0, reads);
        await oidc.ClientCredentialsAsync(client); StringAssert.Contains(handler.Body, "client_assertion=assertion"); Assert.AreEqual(1, reads);
        var publicMetadata = CimdClientMetadata.Create(new("https://client.invalid/public.json"), "Public", [new("custom-app:/callback")]);
        await oidc.ClientCredentialsAsync(publicMetadata.CreateAuthentication()); Assert.IsFalse(handler.Body.Contains("client_assertion", StringComparison.Ordinal));
        Assert.Throws<ArgumentNullException>(() => OAuthClientAuthentication.ClientMetadata(null!));
        Assert.Throws<ArgumentException>(() => metadata.CreateAuthentication()); Assert.Throws<ArgumentException>(() => publicMetadata.CreateAuthentication(_ => ValueTask.FromResult("secret")));
        foreach (string method in new[] { "tls_client_auth", "self_signed_tls_client_auth" })
        {
            var document = Base(); document["token_endpoint_auth_method"] = method;
            var tls = new CimdClientMetadata(Element(document));
            await Assert.ThrowsAsync<InvalidOperationException>(() => oidc.ClientCredentialsAsync(tls.CreateAuthentication()));
        }
        var dev = CimdClientMetadata.Create(new("http://127.0.0.1/metadata.json"), "Dev", [new("http://localhost/cb")], allowLoopbackHttp: true);
        Assert.AreEqual("none", dev.AuthenticationMethod);
        using var disposed = JsonDocument.Parse(Base().ToJsonString()); var retained = new CimdClientMetadata(disposed.RootElement); disposed.Dispose(); Assert.AreEqual("https://client.invalid/metadata.json", retained.ToJson().GetProperty("client_id").GetString());
    }
    [TestMethod]
    public void PublicMetadataRejectsCredentialsAmbiguousIdentityInvalidEndpointsAndUnboundedDocuments()
    {
        foreach (Action<JsonObject> corrupt in new Action<JsonObject>[] {
            d => d.Remove("client_id"), d => d["client_id"] = 42, d => d["client_id"] = " ", d => d["client_id"] = "relative", d => d["client_id"] = "https://user:secret@client.invalid/metadata", d => d["client_id"] = "https://client.invalid/metadata#f", d => d["client_id"] = "https://client.invalid/metadata?q", d => d["client_id"] = "http://client.invalid/metadata",
            d => d["client_secret"] = "secret", d => d["client_secret_expires_at"] = 0, d => d["registration_access_token"] = "secret", d => d["large"] = new string('x', 65536),
            d => d.Remove("redirect_uris"), d => d["redirect_uris"] = "wrong", d => d["redirect_uris"] = new JsonArray(), d => d["redirect_uris"] = new JsonArray(Enumerable.Range(0,33).Select(i => (JsonNode)JsonValue.Create("https://client.invalid/" + i)!).ToArray()),
            d => d["redirect_uris"] = new JsonArray(42), d => d["redirect_uris"] = new JsonArray("relative"), d => d["redirect_uris"] = new JsonArray("https://user:secret@client.invalid/cb"), d => d["redirect_uris"] = new JsonArray("https://client.invalid/cb#f"), d => d["redirect_uris"] = new JsonArray("https://client.invalid/*"),
            d => d["token_endpoint_auth_method"] = 42, d => d["token_endpoint_auth_method"] = "client_secret_basic", d => d["token_endpoint_auth_method"] = "private_key_jwt",
            d => { d["jwks_uri"] = "http://remote.invalid/keys"; }, d => { d["jwks_uri"] = "https://client.invalid/keys"; d["jwks"] = new JsonObject(); }
        })
        { var document = Base(); corrupt(document); var error = Assert.Throws<ArgumentException>(() => new CimdClientMetadata(Element(document))); Assert.IsFalse(error.ToString().Contains("user:secret", StringComparison.Ordinal)); }
        Assert.Throws<ArgumentException>(() => new CimdClientMetadata(Element(JsonNode.Parse("[]")!)));
        Assert.Throws<ArgumentException>(() => new CimdClientMetadata(JsonDocument.Parse("""{"client_id":"a","client_id":"b"}""").RootElement));
        var nonlocal = Base(); nonlocal["client_id"] = "http://remote.invalid/doc"; Assert.Throws<ArgumentException>(() => new CimdClientMetadata(Element(nonlocal), true));
        nonlocal["client_id"] = "file:///metadata"; Assert.Throws<ArgumentException>(() => new CimdClientMetadata(Element(nonlocal), true));
        Assert.Throws<ArgumentNullException>(() => CimdClientMetadata.Create(null!, "n", [])); Assert.Throws<ArgumentException>(() => CimdClientMetadata.Create(new("https://c.invalid/md"), "", []));
        Assert.Throws<ArgumentNullException>(() => CimdClientMetadata.Create(new("https://c.invalid/md"), "n", null!));
        Assert.Throws<ArgumentNullException>(() => CimdClientMetadata.Create(new("https://c.invalid/md"), "n", [null!]));
        Assert.Throws<ArgumentException>(() => CimdClientMetadata.Create(new("relative", UriKind.Relative), "n", []));
        Assert.Throws<ArgumentException>(() => CimdClientMetadata.Create(new("https://c.invalid/md"), "n", [new("https://c.invalid/cb")], new("relative", UriKind.Relative)));
    }
    [TestMethod]
    public void InlineMetadataJwksNeverPublishesPrivateOrSymmetricKeyMaterial()
    {
        foreach (string keyType in new[] { "RSA", "EC", "OKP" })
        { var document = Base(); document["token_endpoint_auth_method"] = "private_key_jwt"; document["jwks"] = new JsonObject { ["keys"] = new JsonArray(new JsonObject { ["kty"] = keyType }) }; Assert.AreEqual("private_key_jwt", new CimdClientMetadata(Element(document)).AuthenticationMethod); }
        foreach (JsonNode invalid in new JsonNode[] { JsonValue.Create("wrong")!, new JsonObject(), new JsonObject { ["keys"] = "wrong" }, new JsonObject { ["keys"] = new JsonArray() }, new JsonObject { ["keys"] = new JsonArray(Enumerable.Range(0,33).Select(_ => (JsonNode)new JsonObject { ["kty"] = "RSA" }).ToArray()) },
            new JsonObject { ["keys"] = new JsonArray(42) }, new JsonObject { ["keys"] = new JsonArray(new JsonObject()) }, new JsonObject { ["keys"] = new JsonArray(new JsonObject { ["kty"] = "oct", ["k"] = "secret" }) } })
        { var document = Base(); document["jwks"] = invalid; Assert.Throws<ArgumentException>(() => new CimdClientMetadata(Element(document))); }
        foreach (string privateField in new[] { "k", "d", "p", "q", "dp", "dq", "qi", "oth" })
        { var document = Base(); document["jwks"] = new JsonObject { ["keys"] = new JsonArray(new JsonObject { ["kty"] = "RSA", [privateField] = "secret" }) }; Assert.Throws<ArgumentException>(() => new CimdClientMetadata(Element(document))); }
        var duplicate = JsonDocument.Parse("""{"client_id":"https://client.invalid/md","redirect_uris":["https://client.invalid/cb"],"jwks":{"keys":[{"kty":"RSA","kid":"a","kid":"b"}]}}""");
        using (duplicate) Assert.Throws<ArgumentException>(() => new CimdClientMetadata(duplicate.RootElement));
    }
    private static JsonObject Base() => new() { ["client_id"] = "https://client.invalid/metadata.json", ["redirect_uris"] = new JsonArray("https://client.invalid/cb") };
    private static JsonElement Element(JsonNode value) { using var document = JsonDocument.Parse(value.ToJsonString()); return document.RootElement.Clone(); }
    private sealed class Handler : HttpMessageHandler
    {
        internal int Sends; internal string Body = "";
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        { Sends++; Body = await request.Content!.ReadAsStringAsync(cancellationToken); return new(HttpStatusCode.OK) { Content = new StringContent("{}") }; }
    }
}
