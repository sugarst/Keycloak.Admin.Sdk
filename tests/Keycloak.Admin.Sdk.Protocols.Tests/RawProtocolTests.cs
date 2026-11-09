using System.Net;
using System.Security.Cryptography;
using System.Text;
using Keycloak.Admin.Sdk.Capabilities;
using Keycloak.Admin.Sdk.Protocols;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.VisualStudio.TestTools.UnitTesting;

[TestClass]
public sealed class RawProtocolTests
{
    [TestMethod]
    public async Task RawResponsesRequireExplicitMediaTypeAndEnforceBoundsBeforeParsing()
    {
        using var handler = new Handler(); using var http = new HttpClient(handler); var transport = new ProtocolTransport(http, new("https://issuer.invalid"), "r");
        Task<ProtocolResponse> Send(string? media) => transport.SendAsync(HttpMethod.Get, "resource", "raw-test", "KeycloakSdk.Protocols.Wallet", null, null, null, null, default, responseMediaType: media);
        await Assert.ThrowsAsync<ArgumentException>(() => Send("text/html")); Assert.AreEqual(0, handler.Calls);
        handler.Media = "text/html"; await Assert.ThrowsAsync<InvalidDataException>(() => Send("application/jwt"));
        handler.NoMedia = true; await Assert.ThrowsAsync<InvalidDataException>(() => Send("application/jwt")); handler.NoMedia = false;
        foreach (var (media, size) in new[] { ("application/jwt", 65537), ("image/png", 1024 * 1024 + 1), ("application/json", 16 * 1024 * 1024 + 1) })
        { handler.Media = media; handler.Body = new string('x', size); await Assert.ThrowsAsync<InvalidDataException>(() => Send(media == "application/json" ? null : media)); }
        handler.Media = "image/png"; handler.Body = "";
        var empty = await Send("image/png"); Assert.AreEqual(0, empty.RawBody.Length); Assert.IsNull(empty.Json);
        handler.Status = HttpStatusCode.NoContent; Assert.AreEqual(HttpStatusCode.NoContent, (await Send("image/png")).StatusCode);
        handler.Status = HttpStatusCode.OK; handler.Media = "application/json"; handler.Body = "{}";
        Assert.AreEqual(System.Text.Json.JsonValueKind.Object, (await Send(null)).Json!.Value.ValueKind);
        byte[] source = [1, 2, 3]; var copy = new ProtocolResponse(HttpStatusCode.OK, null, rawBody: source, bodyMediaType: "image/png"); source[0] = 99;
        Assert.AreEqual((byte)1, copy.RawBody.Span[0]); Assert.IsFalse(copy.ToString()!.Contains("99", StringComparison.Ordinal));
    }
    [TestMethod]
    public async Task WalletNonceDpopIsIndependentlyGatedEvenWithoutAnAccessToken()
    {
        using var signing = ECDsa.Create(ECCurve.NamedCurves.nistP256); using var handler = new Handler(); using var http = new HttpClient(handler);
        var flags = new Dictionary<string, bool> { ["KeycloakSdk.Protocols"] = true, ["KeycloakSdk.Protocols.Wallet"] = true, ["KeycloakSdk.Protocols.Dpop"] = true };
        var gate = new KeycloakFeatureSnapshotGate(flags); var key = DpopProofKey.FromEcdsa(signing);
        var transport = new ProtocolTransport(http, new("https://issuer.invalid"), "r", gate, key);
        await new Oid4vcIssuerClient(transport).RequestNonceAsync(); Assert.IsNotNull(handler.Proof); Assert.IsNull(handler.Authorization);
        var proof = new JsonWebToken(handler.Proof); Assert.AreEqual("POST", proof.GetPayloadValue<string>("htm")); Assert.IsFalse(proof.TryGetPayloadValue<string>("ath", out _));
        flags["KeycloakSdk.Protocols.Dpop"] = false; gate.Replace(flags); int before = handler.Calls;
        await Assert.ThrowsAsync<InvalidOperationException>(() => new Oid4vcIssuerClient(transport).RequestNonceAsync()); Assert.AreEqual(before, handler.Calls);
    }
    private sealed class Handler : HttpMessageHandler
    {
        internal string Body = "{}", Media = "application/json"; internal bool NoMedia; internal HttpStatusCode Status = HttpStatusCode.OK; internal int Calls; internal string? Proof, Authorization;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested(); Calls++; Proof = request.Headers.TryGetValues("DPoP", out var values) ? values.Single() : null; Authorization = request.Headers.Authorization?.ToString();
            var response = new HttpResponseMessage(Status) { Content = new StringContent(Body, Encoding.UTF8, Media) }; if (NoMedia) response.Content.Headers.ContentType = null;
            return Task.FromResult(response);
        }
    }
}
