using System.Net;
using System.Text;
using Keycloak.Admin.Sdk.Capabilities;
using Keycloak.Admin.Sdk.Protocols;
using Microsoft.VisualStudio.TestTools.UnitTesting;

[TestClass]
public sealed class DockerTests
{
    [TestMethod]
    public async Task RegistryChallengesCannotExfiltrateCredentialsToAnUnpinnedRealm()
    {
        using var handler = new Handler(); using var http = new HttpClient(handler); var transport = new ProtocolTransport(http, new("https://identity.invalid/"), "r");
        var client = new DockerRegistryClient(transport); int credentials = 0;
        ValueTask<NetworkCredential> Credential(CancellationToken ct) { ct.ThrowIfCancellationRequested(); credentials++; return ValueTask.FromResult(new NetworkCredential("user", "p:secret")); }
        const string endpoint = "https://identity.invalid/realms/r/protocol/docker-v2/auth";
        await client.AuthenticateChallengeAsync("Bearer realm=\"" + endpoint + "\",service=\"registry\",scope=\"repository:a:pull,push\"", Credential);
        Assert.AreEqual("Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes("user:p:secret")), handler.Authorization);
        StringAssert.Contains(handler.Query, "scope=repository%3Aa%3Apull%2Cpush");
        await client.AuthenticateChallengeAsync("Bearer realm=\"" + endpoint + "\",service=\"registry\"", Credential);
        Assert.IsFalse(handler.Query.Contains("scope", StringComparison.Ordinal));
        int before = handler.Sends;
        foreach (string challenge in new[] { new string('a', 8193), "Bearer\r\nX-Other: value", "Bearer\n", "not a header\"", "Basic realm=\"x\"", "Bearer", "Bearer x", "Bearer realm=\"" + endpoint + "\",realm=\"duplicate\"", "Bearer service=\"registry\"", "Bearer realm=\"https://attacker.invalid/auth\",service=\"registry\"", "Bearer realm=\"" + endpoint + "\"", "Bearer realm=\"" + endpoint + "\",service=\"\"", "Bearer realm=\"" + endpoint + "\",service=\"registry\"," })
            Assert.Throws<ArgumentException>(() => client.AuthenticateChallengeAsync(challenge, Credential));
        Assert.AreEqual(before, handler.Sends); Assert.AreEqual(2, credentials);
        Assert.Throws<ArgumentException>(() => client.RequestTokenAsync("", [], Credential));
        Assert.Throws<ArgumentNullException>(() => client.RequestTokenAsync("registry", null!, Credential));
        Assert.Throws<ArgumentNullException>(() => client.RequestTokenAsync("registry", [], null!));
        Assert.Throws<ArgumentException>(() => client.RequestTokenAsync("registry", [""], Credential));
        await Assert.ThrowsAsync<ArgumentException>(() => client.RequestTokenAsync("registry", [], _ => ValueTask.FromResult(new NetworkCredential("bad:name", "p"))));
        await Assert.ThrowsAsync<ArgumentException>(() => client.RequestTokenAsync("registry", [], _ => ValueTask.FromResult(new NetworkCredential("", "p"))));
        await Assert.ThrowsAsync<ArgumentNullException>(() => client.RequestTokenAsync("registry", [], _ => ValueTask.FromResult<NetworkCredential>(null!)));
        Assert.AreEqual(before, handler.Sends);
        using var cancel = new CancellationTokenSource();
        await Assert.ThrowsAsync<OperationCanceledException>(() => client.RequestTokenAsync("registry", [], _ => { cancel.Cancel(); return Credential(CancellationToken.None); }, cancel.Token));
        Assert.AreEqual(before, handler.Sends);
        var closed = new DockerRegistryClient(new(http, new("https://identity.invalid/"), "r", new KeycloakFeatureSnapshotGate([])));
        await Assert.ThrowsAsync<InvalidOperationException>(() => closed.RequestTokenAsync("registry", [], Credential)); Assert.AreEqual(before, handler.Sends);
        Assert.Throws<ArgumentNullException>(() => new DockerRegistryClient(null!));
    }
    private sealed class Handler : HttpMessageHandler
    {
        internal int Sends; internal string Authorization = "", Query = "";
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested(); Sends++; Authorization = request.Headers.Authorization!.ToString(); Query = request.RequestUri!.Query;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{}") });
        }
    }
}
