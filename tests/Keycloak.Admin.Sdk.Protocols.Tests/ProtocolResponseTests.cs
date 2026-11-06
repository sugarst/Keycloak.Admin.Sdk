using System.Net;
using System.Text.Json;
using Keycloak.Admin.Sdk.Protocols;
using Microsoft.VisualStudio.TestTools.UnitTesting;

[TestClass]
public sealed class ProtocolResponseTests
{
    [TestMethod]
    public async Task ResponsesPreservePaginationAndContentHeadersWithoutRenderingCredentials()
    {
        using var http = new HttpClient(new Handler()); var oidc = new OidcClient(new(http, new("https://identity.invalid/"), "r"));
        var response = await oidc.DiscoverAsync();
        StringAssert.Contains(response.Headers["link"][0], "rel=\"next\"");
        Assert.AreEqual("application/json; charset=utf-8", response.Headers["content-type"][0]);
        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        Assert.AreEqual("access-secret", response.Json!.Value.GetProperty("access_token").GetString());
        Assert.IsFalse(response.ToString()!.Contains("access-secret", StringComparison.Ordinal));
        string[] source = ["first"];
        var copy = new ProtocolResponse(HttpStatusCode.OK, null, [new("Link", source), new("link", ["second"])]);
        source[0] = "changed";
        CollectionAssert.AreEqual(new[] { "first", "second" }, copy.Headers["LINK"].ToArray());
        Assert.AreEqual(0, new ProtocolResponse(HttpStatusCode.NoContent, null).Headers.Count);
    }
    private sealed class Handler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("""{"access_token":"access-secret"}""", System.Text.Encoding.UTF8, "application/json") };
            response.Headers.TryAddWithoutValidation("Link", "<https://identity.invalid/next>; rel=\"next\"");
            return Task.FromResult(response);
        }
    }
}
