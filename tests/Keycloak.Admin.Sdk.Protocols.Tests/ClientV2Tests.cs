using System.Net;
using System.Text.Json;
using Keycloak.Admin.Sdk.Protocols;
using Microsoft.VisualStudio.TestTools.UnitTesting;

[TestClass]
public sealed class ClientV2Tests
{
    [TestMethod]
    public async Task ClientV2UsesServerScopedPathsAndMergePatchWithoutMixingManagementCredentials()
    {
        using var handler = new Handler(); using var http = new HttpClient(handler);
        var client = new ClientAdminV2Client(new(http, new("https://identity.invalid/context/"), "r +"));
        var body = JsonDocument.Parse("""{"clientId":"app","protocol":"openid-connect"}""").RootElement;
        await client.ListAsync("admin", [new("q", "clientId eq \"app\""), new("limit", "1")]);
        Assert.AreEqual("/context/admin/api/r%20%2B/clients/v2", handler.Path); StringAssert.Contains(handler.Query, "limit=1");
        await client.CreateAsync(body, "admin"); Assert.AreEqual("POST", handler.Method); Assert.AreEqual("Bearer admin", handler.Authorization);
        await client.GetAsync("client/id", "admin"); Assert.AreEqual("/context/admin/api/r%20%2B/clients/v2/client%2Fid", handler.Path);
        await client.UpsertAsync("app", body, "admin"); Assert.AreEqual("PUT", handler.Method); Assert.AreEqual("application/json", handler.ContentType);
        await client.PatchAsync("app", body, "admin"); Assert.AreEqual("PATCH", handler.Method); Assert.AreEqual("application/merge-patch+json", handler.ContentType);
        await client.DeleteAsync("app", "admin"); Assert.AreEqual("DELETE", handler.Method);
        Assert.Throws<ArgumentException>(() => client.ListAsync("")); Assert.Throws<ArgumentNullException>(() => new ClientAdminV2Client(null!));
        var metadata = new RuntimeOpenApiClient(new(http, new("https://management.invalid:9000/context/"), "r"));
        await metadata.GetAsync(); Assert.AreEqual("management.invalid", handler.Host); Assert.AreEqual("/context/openapi", handler.Path); Assert.AreEqual("", handler.Authorization);
        Assert.Throws<ArgumentNullException>(() => new RuntimeOpenApiClient(null!));
    }
    private sealed class Handler : HttpMessageHandler
    {
        internal string Path = "", Query = "", Host = "", Method = "", Authorization = "", ContentType = "";
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested(); Path = request.RequestUri!.AbsolutePath; Query = request.RequestUri.Query; Host = request.RequestUri.Host;
            Method = request.Method.Method; Authorization = request.Headers.Authorization?.ToString() ?? ""; ContentType = request.Content?.Headers.ContentType?.MediaType ?? "";
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{}") });
        }
    }
}
