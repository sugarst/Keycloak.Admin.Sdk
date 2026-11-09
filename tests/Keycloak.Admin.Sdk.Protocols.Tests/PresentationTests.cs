using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Keycloak.Admin.Sdk.Protocols;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualStudio.TestTools.UnitTesting;

[TestClass]
public sealed class PresentationTests
{
    [TestMethod]
    public async Task PinnedVerifierRequestsAndBothDeliveryModesPreserveConsentAndHolderBinding()
    {
        using var f = new Fixture();
        foreach (bool encrypted in new[] { false, true })
        foreach (bool crossDevice in new[] { false, true })
        {
            var request = await f.RequestAsync(encrypted, crossDevice); int before = f.Handler.Calls;
            Assert.AreEqual(f.Id, request.ClientId); Assert.AreEqual("nonce", request.Nonce); Assert.AreEqual("state", request.State);
            Assert.AreEqual("dc+sd-jwt", request.DcqlQuery.GetProperty("credentials")[0].GetProperty("format").GetString());
            await Assert.ThrowsAsync<InvalidDataException>(() => f.Client.PresentAsync(request, f.Credential, [], f.Holder, "identity")); Assert.AreEqual(before, f.Handler.Calls);
            f.Handler.Media = "application/json"; f.Handler.Response = "{}";
            await f.Client.PresentAsync(request, f.Credential, [f.Disclosure], f.Holder, "identity");
            Assert.AreEqual("POST", f.Handler.Method); Assert.AreEqual(crossDevice ? "?flow=cross_device" : "", f.Handler.Target!.Query);
            var form = Parse(f.Handler.Body!); Assert.AreEqual(1, form.Count - (encrypted ? 0 : 1));
            if (encrypted)
            {
                string[] parts = form["response"].Split('.'); Assert.AreEqual("", parts[1]);
                using var header = JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(parts[0])); var epk = new JsonWebKey(header.RootElement.GetProperty("epk").GetRawText());
                Assert.IsFalse(header.RootElement.GetProperty("epk").TryGetProperty("d", out _));
                var exchange = new EcdhKeyExchangeProvider(new ECDsaSecurityKey(f.EncryptionKey), epk, "ECDH-ES", "A256GCM"); byte[] key = ((SymmetricSecurityKey)exchange.GenerateKdf("", "")).Key;
                try
                {
                    byte[] ciphertext = Base64UrlEncoder.DecodeBytes(parts[3]), plaintext = new byte[ciphertext.Length];
                    using var aes = new AesGcm(key, 16); aes.Decrypt(Base64UrlEncoder.DecodeBytes(parts[2]), ciphertext, Base64UrlEncoder.DecodeBytes(parts[4]), plaintext, Encoding.ASCII.GetBytes(parts[0]));
                    var content = Json(Encoding.UTF8.GetString(plaintext)); Assert.AreEqual("state", content.GetProperty("state").GetString());
                    Assert.IsTrue(content.GetProperty("vp_token").GetProperty("identity")[0].GetString()!.Contains(f.Disclosure, StringComparison.Ordinal));
                }
                finally { CryptographicOperations.ZeroMemory(key); }
            }
            else Assert.AreEqual("state", form["state"]);
            await Assert.ThrowsAsync<InvalidDataException>(() => f.Client.PresentAsync(request, f.Credential, [f.Disclosure], f.Holder, "identity"));
        }
        f.Handler.Response = "{\"status\":\"pending\"}"; f.Handler.Media = "application/json";
        Assert.AreEqual("pending", (await f.Client.GetStatusAsync("state")).Json!.Value.GetProperty("status").GetString());
        Assert.AreEqual("?state=state", f.Handler.Target!.Query);
        Assert.Throws<ArgumentException>(() => new Oid4vpClient(f.Transport, "verifier", "untrusted"));
        Assert.Throws<ArgumentException>(() => new Oid4vpClient(f.Transport, "verifier", "x509_hash:short"));
        Assert.Throws<ArgumentNullException>(() => new Oid4vpClient(null!, "verifier", f.Id));
        Assert.IsNotNull(new Oid4vpClient(f.Transport, "verifier", f.Id));
        await Assert.ThrowsAsync<ArgumentException>(() => f.Client.GetRequestAsync(new("relative", UriKind.Relative)));
    }

    [TestMethod]
    public async Task RequestTamperingAndForeignDestinationsNeverYieldTrustedPresentationRequests()
    {
        using var f = new Fixture();
        foreach (Action<JsonObject> corrupt in new Action<JsonObject>[]
        {
            n => n["iss"] = "foreign", n => n["aud"] = "foreign", n => n["client_id"] = "foreign", n => n["response_uri"] = "https://attacker.invalid",
            n => n["response_type"] = "code", n => n["response_mode"] = "other", n => n.Remove("iat"), n => n["iat"] = "1", n => n["iat"] = 1.25,
            n => n["iat"] = DateTimeOffset.UtcNow.AddMinutes(1).ToUnixTimeSeconds(), n => n["exp"] = DateTimeOffset.UtcNow.AddMinutes(31).ToUnixTimeSeconds(),
            n => n["exp"] = DateTimeOffset.UtcNow.AddSeconds(-5).ToUnixTimeSeconds(),
            n => { n["iat"] = DateTimeOffset.UtcNow.AddSeconds(20).ToUnixTimeSeconds(); n["exp"] = DateTimeOffset.UtcNow.AddSeconds(10).ToUnixTimeSeconds(); }
        })
        {
            var payload = f.RequestClaims(false, false); corrupt(payload); f.Serve(f.Sign(payload));
            await Assert.ThrowsAsync<InvalidDataException>(() => f.Client.GetRequestAsync(f.RequestUri));
        }
        foreach (string type in new[] { "JWT", "" })
        { f.Serve(f.Sign(f.RequestClaims(false, false), type)); await Assert.ThrowsAsync<InvalidDataException>(() => f.Client.GetRequestAsync(f.RequestUri)); }
        foreach (JsonNode? certificate in new JsonNode?[] { null, JsonValue.Create(1), new JsonArray(), new JsonArray(Enumerable.Repeat<JsonNode>(JsonValue.Create("certificate")!, 9).Select(n => n.DeepClone()).ToArray()) })
        {
            f.Serve(f.Sign(f.RequestClaims(false, false), certificate: certificate, includeCertificate: certificate is not null));
            await Assert.ThrowsAsync<InvalidDataException>(() => f.Client.GetRequestAsync(f.RequestUri));
        }
        using var other = new Fixture(); f.Serve(other.Sign(other.RequestClaims(false, false)));
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Client.GetRequestAsync(f.RequestUri));
        using var rsa = RSA.Create(2048);
        using var rsaCertificate = new CertificateRequest("CN=RSA Verifier", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSelfSigned(f.Clock.Now.AddHours(-1), f.Clock.Now.AddHours(1));
        var rsaVerifier = new Oid4vpClient(f.Transport, "verifier", "x509_hash:" + Base64UrlEncoder.Encode(SHA256.HashData(rsaCertificate.RawData)));
        f.Serve(f.Sign(f.RequestClaims(false, false), certificate: new JsonArray(Convert.ToBase64String(rsaCertificate.RawData))));
        await Assert.ThrowsAsync<InvalidDataException>(() => rsaVerifier.GetRequestAsync(f.RequestUri));
        f.Serve(f.Sign(f.RequestClaims(false, false))); f.Clock.Now += TimeSpan.FromHours(2);
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Client.GetRequestAsync(f.RequestUri)); f.Clock.Now -= TimeSpan.FromHours(4);
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Client.GetRequestAsync(f.RequestUri));
        foreach (string invalid in new[] { "relative", "https://foreign.invalid/request", f.RequestUri.AbsoluteUri + "#fragment", f.RequestUri.AbsoluteUri + "?wrong=true", f.RequestUri.AbsoluteUri + "/nested" })
            await Assert.ThrowsAsync<ArgumentException>(() => f.Client.GetRequestAsync(new(invalid, UriKind.RelativeOrAbsolute)));
    }

    [TestMethod]
    public async Task ExpiredConsumedForeignAndUnsupportedEncryptedPresentationsFailClosed()
    {
        using var f = new Fixture(); var request = await f.RequestAsync();
        using var foreign = new Fixture();
        await Assert.ThrowsAsync<InvalidDataException>(() => foreign.Client.PresentAsync(request, f.Credential, [f.Disclosure], f.Holder, "identity"));
        f.Clock.Now += TimeSpan.FromMinutes(11); await Assert.ThrowsAsync<InvalidDataException>(() => f.Client.PresentAsync(request, f.Credential, [f.Disclosure], f.Holder, "identity"));
        f.Clock.Now -= TimeSpan.FromMinutes(11);
        foreach (Action<JsonObject> corrupt in new Action<JsonObject>[]
        {
            n => n["vp_formats_supported"]!["dc+sd-jwt"]!["sd-jwt_alg_values"] = new JsonArray(JsonValue.Create("RS256")),
            n => n["vp_formats_supported"]!["dc+sd-jwt"]!["kb-jwt_alg_values"] = new JsonArray(JsonValue.Create("RS256")),
            n => n["jwks"]!["keys"] = new JsonArray(), n => n["encrypted_response_enc_values_supported"] = new JsonArray(JsonValue.Create("A128GCM")),
            n => n["jwks"]!["keys"]![0]!["alg"] = "other", n => n["jwks"]!["keys"]![0]!["crv"] = "P-384", n => n["jwks"]!["keys"]![0]!["kid"] = "",
            n => n["jwks"]!["keys"]![0]!.AsObject().Remove("kid")
        })
        {
            var payload = f.RequestClaims(true, false); corrupt(payload["client_metadata"]!.AsObject()); f.Serve(f.Sign(payload));
            var invalid = await f.Client.GetRequestAsync(f.RequestUri); int before = f.Handler.Calls;
            await Assert.ThrowsAsync<InvalidDataException>(() => f.Client.PresentAsync(invalid, f.Credential, [f.Disclosure], f.Holder, "identity")); Assert.AreEqual(before, f.Handler.Calls);
        }
    }

    private static Dictionary<string, string> Parse(string form) => form.Split('&').Select(p => p.Split('=', 2)).ToDictionary(p => Uri.UnescapeDataString(p[0]), p => Uri.UnescapeDataString(p[1].Replace('+', ' ')));
    private static JsonElement Json(string text) { using var document = JsonDocument.Parse(text); return document.RootElement.Clone(); }
    private sealed class Clock : TimeProvider { internal DateTimeOffset Now = DateTimeOffset.UtcNow; public override DateTimeOffset GetUtcNow() => Now; }
    private sealed class Handler : HttpMessageHandler
    {
        internal string Response = "{}", Media = "application/json"; internal string? Body, Method; internal Uri? Target; internal int Calls;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        { ct.ThrowIfCancellationRequested(); Calls++; Target = request.RequestUri; Method = request.Method.Method; Body = request.Content is null ? null : await request.Content.ReadAsStringAsync(ct); return new(HttpStatusCode.OK) { Content = new StringContent(Response, Encoding.UTF8, Media) }; }
    }
    private sealed class Fixture : IDisposable
    {
        internal readonly ECDsa Key = ECDsa.Create(ECCurve.NamedCurves.nistP256), EncryptionKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        internal readonly X509Certificate2 Certificate; internal readonly Handler Handler = new(); internal readonly HttpClient Http; internal readonly ProtocolTransport Transport;
        internal readonly Oid4vpClient Client; internal readonly Clock Clock = new(); internal readonly Oid4vcProofKey Holder; internal readonly string Id, Disclosure; internal readonly VerifiedOid4vcCredential Credential;
        internal Uri RequestUri => new(Transport.Issuer.AbsoluteUri + "/broker/verifier/endpoint/request-object/handle");
        internal Fixture()
        {
            Certificate = new CertificateRequest("CN=Verifier", Key, HashAlgorithmName.SHA256).CreateSelfSigned(Clock.Now.AddHours(-1), Clock.Now.AddHours(1));
            Id = "x509_hash:" + Base64UrlEncoder.Encode(SHA256.HashData(Certificate.RawData)); Http = new(Handler); Transport = new(Http, new("https://issuer.invalid"), "r"); Client = new(Transport, "verifier", Id, Clock);
            Holder = Oid4vcProofKey.FromEcdsa(Key); Disclosure = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes("[\"salt\",\"email\",\"user@example.invalid\"]"));
            var claims = new JsonObject { ["iss"] = Transport.Issuer.AbsoluteUri, ["exp"] = DateTimeOffset.UtcNow.AddMinutes(10).ToUnixTimeSeconds(), ["vct"] = "credential-type", ["_sd"] = new JsonArray(JsonValue.Create(SdJwtDisclosures.Hash("sha-256", Disclosure))) };
            var signed = Json(claims.ToJsonString()); string jwt = new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(claims.ToJsonString(), new SigningCredentials(new ECDsaSecurityKey(Key), "ES256"), new Dictionary<string, object> { ["typ"] = "dc+sd-jwt" });
            Credential = new(jwt, signed, SdJwtDisclosures.Resolve(signed, [Disclosure]), "dc+sd-jwt", Holder.Thumbprint, [Disclosure]);
        }
        internal JsonObject RequestClaims(bool encrypted, bool crossDevice)
        {
            var p = EncryptionKey.ExportParameters(false);
            var metadata = new JsonObject { ["vp_formats_supported"] = new JsonObject { ["dc+sd-jwt"] = new JsonObject { ["sd-jwt_alg_values"] = new JsonArray(JsonValue.Create("ES256")), ["kb-jwt_alg_values"] = new JsonArray(JsonValue.Create("ES256")) } },
                ["jwks"] = new JsonObject { ["keys"] = new JsonArray(new JsonObject { ["kty"] = "EC", ["crv"] = "P-256", ["alg"] = "ECDH-ES", ["kid"] = "state", ["x"] = Base64UrlEncoder.Encode(p.Q.X), ["y"] = Base64UrlEncoder.Encode(p.Q.Y) }) },
                ["encrypted_response_enc_values_supported"] = new JsonArray(JsonValue.Create("A128GCM"), JsonValue.Create("A256GCM")) };
            return new() { ["iss"] = Id, ["aud"] = "https://self-issued.me/v2", ["iat"] = Clock.Now.ToUnixTimeSeconds(), ["exp"] = Clock.Now.AddMinutes(5).ToUnixTimeSeconds(),
                ["client_id"] = Id, ["nonce"] = "nonce", ["state"] = "state", ["response_type"] = "vp_token", ["response_mode"] = encrypted ? "direct_post.jwt" : "direct_post",
                ["response_uri"] = Transport.Issuer.AbsoluteUri + "/broker/verifier/endpoint" + (crossDevice ? "?flow=cross_device" : ""), ["client_metadata"] = metadata,
                ["dcql_query"] = new JsonObject { ["credentials"] = new JsonArray(new JsonObject { ["id"] = "identity", ["format"] = "dc+sd-jwt", ["meta"] = new JsonObject { ["vct_values"] = new JsonArray(JsonValue.Create("credential-type")) },
                    ["claims"] = new JsonArray(new JsonObject { ["path"] = new JsonArray(JsonValue.Create("email")) }) }) } };
        }
        internal string Sign(JsonObject claims, string type = "oauth-authz-req+jwt", JsonNode? certificate = null, bool includeCertificate = true)
        {
            var headers = new Dictionary<string, object> { ["typ"] = type };
            if (includeCertificate) headers["x5c"] = Json((certificate ?? new JsonArray(JsonValue.Create(Convert.ToBase64String(Certificate.RawData)))).ToJsonString());
            return new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(claims.ToJsonString(), new SigningCredentials(new ECDsaSecurityKey(Key), "ES256"), headers);
        }
        internal void Serve(string token) { Handler.Response = token; Handler.Media = "application/oauth-authz-req+jwt"; }
        internal Task<Oid4vpRequest> RequestAsync(bool encrypted = false, bool crossDevice = false)
        { Serve(Sign(RequestClaims(encrypted, crossDevice))); return Client.GetRequestAsync(new(RequestUri.AbsoluteUri + (crossDevice ? "?flow=cross_device" : ""))); }
        public void Dispose() { Http.Dispose(); Certificate.Dispose(); Key.Dispose(); EncryptionKey.Dispose(); }
    }
}
