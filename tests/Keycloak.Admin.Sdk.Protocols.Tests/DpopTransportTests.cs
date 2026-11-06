using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Keycloak.Admin.Sdk.Capabilities;
using Keycloak.Admin.Sdk.Protocols;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualStudio.TestTools.UnitTesting;

[TestClass]
public sealed class DpopTransportTests
{
    [TestMethod]
    public async Task ProofsBindCredentialsAndNoncesWithoutRetryingChallengedRequests()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256); var proofKey = DpopProofKey.FromEcdsa(key);
        using var handler = new Handler(); using var http = new HttpClient(handler);
        var oidc = new OidcClient(new(http, new("https://identity.invalid/"), "r", proofKey: proofKey));
        handler.Nonces = ["first"];
        await oidc.PasswordGrantAsync(OAuthClientAuthentication.Public("public"), "user+", "password+", "123456", "openid");
        Assert.IsNull(handler.Authorization); Assert.IsFalse(handler.Proof!.Value.TryGetProperty("ath", out _));
        StringAssert.Contains(handler.Body, "username=user%2B"); StringAssert.Contains(handler.Body, "password=password%2B"); StringAssert.Contains(handler.Body, "totp=123456");
        handler.Nonces = [];
        await oidc.GetUserInfoAsync("access-token");
        Assert.AreEqual("DPoP access-token", handler.Authorization); Assert.AreEqual("first", handler.Proof!.Value.GetProperty("nonce").GetString());
        Assert.AreEqual("GET", handler.Proof.Value.GetProperty("htm").GetString());
        Assert.AreEqual("https://identity.invalid/realms/r/protocol/openid-connect/userinfo", handler.Proof.Value.GetProperty("htu").GetString());
        Assert.AreEqual(Base64UrlEncoder.Encode(SHA256.HashData(System.Text.Encoding.ASCII.GetBytes("access-token"))), handler.Proof.Value.GetProperty("ath").GetString());
        handler.Status = HttpStatusCode.BadRequest; handler.BodyResponse = """{"error":"use_dpop_nonce","error_description":"private"}"""; handler.Nonces = ["next-secret-nonce"];
        int before = handler.Sends;
        var error = await Assert.ThrowsAsync<KeycloakProtocolException>(() => oidc.RefreshAsync(OAuthClientAuthentication.SecretBasic("confidential", _ => ValueTask.FromResult("secret")), "refresh"));
        Assert.AreEqual(before + 1, handler.Sends); Assert.AreEqual(OAuthError.UseDpopNonce, error.Error); Assert.AreEqual("next-secret-nonce", error.DpopNonce);
        Assert.IsFalse(error.ToString().Contains("next-secret-nonce", StringComparison.Ordinal));
        Assert.IsTrue(handler.Authorization!.StartsWith("Basic ", StringComparison.Ordinal));
        Assert.IsFalse(handler.Proof!.Value.TryGetProperty("ath", out _));
        handler.Status = HttpStatusCode.OK; handler.BodyResponse = "{}"; handler.Nonces = [];
        await oidc.RefreshAsync(OAuthClientAuthentication.Public("public"), "refresh");
        Assert.AreEqual("next-secret-nonce", handler.Proof!.Value.GetProperty("nonce").GetString());
        foreach (string[] nonces in new[] { new[] { "one", "two" }, new[] { "invalid nonce" } })
        { handler.Nonces = nonces; await Assert.ThrowsAsync<InvalidDataException>(() => oidc.GetUserInfoAsync("access-token")); }
        handler.Nonces = []; await oidc.DiscoverAsync(); Assert.IsNull(handler.Proof);
        await new RuntimeOpenApiClient(new(http, new("https://identity.invalid/"), "r", proofKey: proofKey)).GetAsync(); Assert.IsNull(handler.Proof);
        foreach (string identifier in new[] { "invalid_dpop_proof", "invalid_token" })
        {
            handler.Status = HttpStatusCode.Unauthorized; handler.BodyResponse = "{\"error\":\"" + identifier + "\"}";
            Assert.AreNotEqual(OAuthError.Unknown, (await Assert.ThrowsAsync<KeycloakProtocolException>(() => oidc.GetUserInfoAsync("token"))).Error);
        }
        Assert.Throws<ArgumentException>(() => oidc.PasswordGrantAsync(OAuthClientAuthentication.Public("c"), "", "p"));
        Assert.Throws<ArgumentException>(() => oidc.PasswordGrantAsync(OAuthClientAuthentication.Public("c"), "u", ""));
        Assert.Throws<ArgumentException>(() => oidc.PasswordGrantAsync(OAuthClientAuthentication.Public("c"), "u", "p", ""));
    }

    [TestMethod]
    public async Task ProofOfPossessionGateClosesBeforeCredentialsAndUsesTheSameHostSnapshot()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256); var proof = DpopProofKey.FromEcdsa(key);
        using var handler = new Handler(); using var http = new HttpClient(handler); int credentials = 0;
        var flags = new KeycloakFeatureSnapshotGate([]);
        var transport = new ProtocolTransport(http, new("https://identity.invalid/"), "r", flags, proof);
        var client = new OidcClient(transport);
        var auth = OAuthClientAuthentication.SecretPost("c", _ => { credentials++; return ValueTask.FromResult("secret"); });
        foreach (var entries in new Dictionary<string, bool>[] { new() { ["KeycloakSdk.Protocols"] = true }, new() { ["KeycloakSdk.Protocols"] = true, ["KeycloakSdk.Protocols.Oidc"] = true } })
        { flags.Replace(entries); await Assert.ThrowsAsync<InvalidOperationException>(() => client.ClientCredentialsAsync(auth)); }
        Assert.AreEqual(0, credentials); Assert.AreEqual(0, handler.Sends);
        flags.Replace(new Dictionary<string, bool> { ["KeycloakSdk.Protocols"] = true, ["KeycloakSdk.Protocols.Oidc"] = true, ["KeycloakSdk.Protocols.Dpop"] = true });
        await client.ClientCredentialsAsync(auth); Assert.AreEqual(1, handler.Sends);
        var gate = new Gate(); client = new(new(http, new("https://identity.invalid/"), "r", gate, proof));
        await client.PasswordGrantAsync(OAuthClientAuthentication.Public("c"), "u", "p");
        CollectionAssert.AreEqual(new[] { "KeycloakSdk.Protocols", "KeycloakSdk.Protocols.Oidc", "KeycloakSdk.Protocols.Dpop" }, gate.Seen.ToArray());
        gate.Closed = true; await Assert.ThrowsAsync<InvalidOperationException>(() => client.ClientCredentialsAsync(auth));
        using var cancel = new CancellationTokenSource(); cancel.Cancel();
        await Assert.ThrowsAsync<OperationCanceledException>(() => client.ClientCredentialsAsync(auth, cancellationToken: cancel.Token));
        Assert.AreEqual(1, credentials); Assert.AreEqual(2, handler.Sends);
        var plain = new OidcClient(new(http, new("https://identity.invalid/"), "r", new Gate()));
        await plain.ClientCredentialsAsync(auth); Assert.IsNull(handler.Proof);
        var split = new KeycloakFeatureSnapshotGate(new Dictionary<string, bool> { ["KeycloakSdk.Protocols"] = true, ["KeycloakSdk.Protocols.Oidc"] = true });
        var independentlyGated = new OidcClient(new(http, new("https://identity.invalid/"), "r", split));
        await independentlyGated.ClientCredentialsAsync(OAuthClientAuthentication.Public("c"));
        int sent = handler.Sends;
        await Assert.ThrowsAsync<InvalidOperationException>(() => independentlyGated.ExchangeDelegatedAsync(auth, "subject", "actor"));
        await Assert.ThrowsAsync<InvalidOperationException>(() => independentlyGated.ClientCredentialsAsync(auth, resources: [new("https://api.invalid/")]));
        Assert.AreEqual(sent, handler.Sends);
        split.Replace(new Dictionary<string, bool> { ["KeycloakSdk.Protocols"] = true, ["KeycloakSdk.Protocols.OidcDelegation"] = true });
        await Assert.ThrowsAsync<InvalidOperationException>(() => independentlyGated.ExchangeDelegatedAsync(auth, "subject", "actor"));
    }
    private sealed class Gate : IKeycloakFeatureGate
    {
        internal readonly List<string> Seen = []; internal bool Closed;
        public ValueTask<bool> IsEnabledAsync(string feature, CancellationToken cancellationToken = default)
        { cancellationToken.ThrowIfCancellationRequested(); Seen.Add(feature); return ValueTask.FromResult(!Closed || feature != "KeycloakSdk.Protocols.Dpop"); }
    }
    private sealed class Handler : HttpMessageHandler
    {
        internal int Sends; internal string? Authorization; internal string Body = "", BodyResponse = "{}";
        internal JsonElement? Proof; internal string[] Nonces = []; internal HttpStatusCode Status = HttpStatusCode.OK;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested(); Sends++; Authorization = request.Headers.Authorization?.ToString();
            Body = request.Content is null ? "" : await request.Content.ReadAsStringAsync(cancellationToken); Proof = null;
            if (request.Headers.TryGetValues("DPoP", out var values))
            {
                using var document = JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(values.Single().Split('.')[1])); Proof = document.RootElement.Clone();
            }
            var response = new HttpResponseMessage(Status) { Content = new StringContent(BodyResponse) };
            if (Nonces.Length != 0) response.Headers.TryAddWithoutValidation("DPoP-Nonce", Nonces);
            return response;
        }
    }
}
