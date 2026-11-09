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
public sealed class ProofOfPossessionTests
{
    private static readonly Uri Target = new("https://resource.invalid/document?ignored=query");

    [TestMethod]
    public async Task AccessValidationRejectsIdTokensUntrustedIssuersAudiencesLifetimesAndKeys()
    {
        using var fixture = new Fixture(); var validator = new KeycloakAccessTokenValidator(fixture.Oidc, "api");
        var token = await validator.ValidateAsync(fixture.Token());
        Assert.AreEqual("user", token.Subject); Assert.AreEqual(fixture.Oidc.Issuer.AbsoluteUri, token.Issuer);
        Assert.IsTrue(token.ExpiresAt > DateTimeOffset.UtcNow); Assert.AreEqual("Bearer", token.Claims.GetProperty("typ").GetString());
        Assert.IsFalse(token.ToString()!.Contains(token.Credential, StringComparison.Ordinal));
        foreach (string invalid in new[] { fixture.Token(type: "ID"), fixture.Token(missingType: true), fixture.Token(type: 42), fixture.Token(subject: ""), fixture.Token(audience: "other"),
            fixture.Token(issuer: "https://attacker.invalid"), fixture.Token(expirySeconds: -120), fixture.Token(wrongKey: true), fixture.Token(algorithm: "RS384"), "not-a-jwt" })
            await Assert.ThrowsAsync<InvalidDataException>(() => validator.ValidateAsync(invalid));
        await new KeycloakAccessTokenValidator(fixture.Oidc, "api", ["RS384"]).ValidateAsync(fixture.Token(algorithm: "RS384"));
        var encrypted = fixture.Token(encrypted: true);
        await Assert.ThrowsAsync<InvalidDataException>(() => validator.ValidateAsync(encrypted));
        var decrypted = await new KeycloakAccessTokenValidator(fixture.Oidc, "api", decryptionKeys: [new RsaSecurityKey(fixture.EncryptionKey)]).ValidateAsync(encrypted);
        Assert.AreEqual("user", decrypted.Subject);
        var jweValidator = new KeycloakAccessTokenValidator(fixture.Oidc, "api", decryptionKeys: [new RsaSecurityKey(fixture.EncryptionKey)]);
        await Assert.ThrowsAsync<InvalidDataException>(() => jweValidator.ValidateAsync(fixture.Token(encrypted: true, algorithm: "RS384")));
        await Assert.ThrowsAsync<InvalidDataException>(() => jweValidator.ValidateAsync(fixture.Token(encrypted: true, keyEncryption: "RSA1_5")));
        fixture.Handler.Response = "";
        await Assert.ThrowsAsync<InvalidDataException>(() => validator.ValidateAsync(fixture.Token()));
        Assert.Throws<ArgumentNullException>(() => new KeycloakAccessTokenValidator(null!, "api"));
        Assert.Throws<ArgumentException>(() => new KeycloakAccessTokenValidator(fixture.Oidc, ""));
        Assert.Throws<ArgumentException>(() => new KeycloakAccessTokenValidator(fixture.Oidc, "api", []));
        Assert.Throws<ArgumentException>(() => new KeycloakAccessTokenValidator(fixture.Oidc, "api", ["HS256"]));
        using var ct = new CancellationTokenSource(); ct.Cancel();
        await Assert.ThrowsAsync<OperationCanceledException>(() => validator.ValidateAsync(fixture.Token(), ct.Token));
    }

    [TestMethod]
    public async Task DpopRejectsReplaysAndBindsMethodUriHashKeyAndNonce()
    {
        using var fixture = new Fixture(); using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256); var signer = DpopProofKey.FromEcdsa(key);
        var access = await fixture.Access(signer.Thumbprint); var validator = new DpopRequestValidator(new InMemoryDpopReplayStore());
        string proof = signer.CreateProof(HttpMethod.Get, Target, access.Credential);
        await validator.ValidateAsync(proof, HttpMethod.Get, Target, access);
        Assert.AreEqual(DpopFailure.Replay, (await Assert.ThrowsAsync<DpopValidationException>(() => validator.ValidateAsync(proof, HttpMethod.Get, Target, access))).Reason);
        Assert.AreEqual(DpopFailure.RequestMismatch, (await Assert.ThrowsAsync<DpopValidationException>(() => validator.ValidateAsync(signer.CreateProof(HttpMethod.Post, Target, access.Credential), HttpMethod.Get, Target, access))).Reason);
        Assert.AreEqual(DpopFailure.RequestMismatch, (await Assert.ThrowsAsync<DpopValidationException>(() => validator.ValidateAsync(signer.CreateProof(HttpMethod.Get, new("https://resource.invalid/other"), access.Credential), HttpMethod.Get, Target, access))).Reason);
        Assert.AreEqual(DpopFailure.RequestMismatch, (await Assert.ThrowsAsync<DpopValidationException>(() => validator.ValidateAsync(signer.CreateProof(HttpMethod.Get, Target, "other-token"), HttpMethod.Get, Target, access))).Reason);
        using var otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256); var otherSigner = DpopProofKey.FromEcdsa(otherKey);
        Assert.AreEqual(DpopFailure.TokenBinding, (await Assert.ThrowsAsync<DpopValidationException>(() => validator.ValidateAsync(otherSigner.CreateProof(HttpMethod.Get, Target, access.Credential), HttpMethod.Get, Target, access))).Reason);
        foreach (JsonNode? confirmation in new JsonNode?[] { null, new JsonArray(), new JsonObject(), new JsonObject { ["jkt"] = 42 }, new JsonObject { ["jkt"] = "wrong" } })
        {
            var unbound = await new KeycloakAccessTokenValidator(fixture.Oidc, "api").ValidateAsync(fixture.Token(confirmation: confirmation));
            Assert.AreEqual(DpopFailure.TokenBinding, (await Assert.ThrowsAsync<DpopValidationException>(() => validator.ValidateAsync(proof, HttpMethod.Get, Target, unbound))).Reason);
        }
        var futureClock = new Clock(access.ExpiresAt.AddSeconds(1));
        Assert.AreEqual(DpopFailure.TokenBinding, (await Assert.ThrowsAsync<DpopValidationException>(() => new DpopRequestValidator(new InMemoryDpopReplayStore(), futureClock).ValidateAsync(proof, HttpMethod.Get, Target, access))).Reason);
        Assert.AreEqual(DpopFailure.NonceRequired, (await Assert.ThrowsAsync<DpopValidationException>(() => validator.ValidateAsync(signer.CreateProof(HttpMethod.Get, Target, access.Credential), HttpMethod.Get, Target, access, "nonce"))).Reason);
        signer.SetNonce(Target, "nonce");
        signer.CreateProof(HttpMethod.Get, new("http://resource.invalid/path"));
        await validator.ValidateAsync(signer.CreateProof(HttpMethod.Get, Target, access.Credential), HttpMethod.Get, Target, access, "nonce");
        Assert.AreEqual(DpopFailure.NonceRequired, (await Assert.ThrowsAsync<DpopValidationException>(() => validator.ValidateAsync(signer.CreateProof(HttpMethod.Get, Target, access.Credential), HttpMethod.Get, Target, access, "other"))).Reason);
        using var cancel = new CancellationTokenSource(); cancel.Cancel();
        await Assert.ThrowsAsync<OperationCanceledException>(() => validator.ValidateAsync(proof, HttpMethod.Get, Target, access, cancellationToken: cancel.Token));
        Assert.Throws<ArgumentNullException>(() => new DpopRequestValidator(null!));
    }

    [TestMethod]
    public async Task DpopMalformedAndTamperedProofsNeverPassAsIdentityOrRequests()
    {
        using var fixture = new Fixture(); using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256); var signer = DpopProofKey.FromEcdsa(key);
        var access = await fixture.Access(signer.Thumbprint); var validator = new DpopRequestValidator(new InMemoryDpopReplayStore());
        var jwk = HeaderJwk(signer.CreateProof(HttpMethod.Get, Target)); var signing = new SigningCredentials(new ECDsaSecurityKey(key), "ES256");
        var invalid = new List<string> { "malformed", Proof(signing, jwk, Claims(access.Credential), type: "JWT"), Proof(signing, null, Claims(access.Credential)),
            Proof(signing, jwk, Claims(access.Credential), critical: true), Proof(signing, JsonDocument.Parse("[]").RootElement, Claims(access.Credential)) };
        var privateJwk = JsonNode.Parse(jwk.GetRawText())!; privateJwk["d"] = "private-secret";
        invalid.Add(Proof(signing, Element(privateJwk), Claims(access.Credential)));
        var wrongCurve = JsonNode.Parse(jwk.GetRawText())!; wrongCurve["crv"] = "P-384";
        invalid.Add(Proof(signing, Element(wrongCurve), Claims(access.Credential)));
        foreach (Action<Dictionary<string, object>> mutate in new Action<Dictionary<string, object>>[]
        { c => c.Remove("iat"), c => c["iat"] = "wrong", c => c["iat"] = 1.5, c => c["iat"] = 0L, c => c["iat"] = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds(),
          c => c.Remove("jti"), c => c["jti"] = 42, c => c["jti"] = " ", c => c["jti"] = new string('a', 201) })
        { var claims = Claims(access.Credential); mutate(claims); invalid.Add(Proof(signing, jwk, claims)); }
        string[] segments = signer.CreateProof(HttpMethod.Get, Target, access.Credential).Split('.'); segments[2] = (segments[2][0] == 'A' ? "B" : "A") + segments[2][1..]; invalid.Add(string.Join('.', segments));
        foreach (string proof in invalid)
        {
            var error = await Assert.ThrowsAsync<DpopValidationException>(() => validator.ValidateAsync(proof, HttpMethod.Get, Target, access));
            Assert.AreEqual(DpopFailure.InvalidProof, error.Reason); Assert.IsFalse(error.ToString().Contains("private-secret", StringComparison.Ordinal));
        }
        foreach (Action<Dictionary<string, object>> mutate in new Action<Dictionary<string, object>>[] { c => c.Remove("htm"), c => c["htm"] = 42, c => c["htm"] = "POST",
            c => c.Remove("htu"), c => c["htu"] = 42, c => c["htu"] = "https://resource.invalid/other", c => c.Remove("ath"), c => c["ath"] = 42, c => c["ath"] = "wrong" })
        {
            var claims = Claims(access.Credential); mutate(claims);
            Assert.AreEqual(DpopFailure.RequestMismatch, (await Assert.ThrowsAsync<DpopValidationException>(() => validator.ValidateAsync(Proof(signing, jwk, claims), HttpMethod.Get, Target, access))).Reason);
        }
        var numericNonce = Claims(access.Credential); numericNonce["nonce"] = 42;
        Assert.AreEqual(DpopFailure.NonceRequired, (await Assert.ThrowsAsync<DpopValidationException>(() => validator.ValidateAsync(Proof(signing, jwk, numericNonce), HttpMethod.Get, Target, access, "nonce"))).Reason);
    }

    [TestMethod]
    public async Task RsaDpopAndAtomicBoundedReplayStorageHandleConcurrencyAndExpiry()
    {
        using var fixture = new Fixture(); using var key = RSA.Create(2048);
        var jwk = PublicRsa(key); var signer = new DpopProofKey(new(new RsaSecurityKey(key), "RS256"), jwk);
        var access = await fixture.Access(signer.Thumbprint);
        await new DpopRequestValidator(new InMemoryDpopReplayStore()).ValidateAsync(signer.CreateProof(HttpMethod.Get, Target, access.Credential), HttpMethod.Get, Target, access);
        foreach (string algorithm in new[] { "RS384", "RS512", "PS256", "PS384", "PS512" })
        {
            var proofKey = new DpopProofKey(new(new RsaSecurityKey(key), algorithm), jwk);
            await new DpopRequestValidator(new InMemoryDpopReplayStore()).ValidateAsync(proofKey.CreateProof(HttpMethod.Get, Target, access.Credential), HttpMethod.Get, Target, access);
        }
        foreach (var (curve, algorithm, name) in new[] { (ECCurve.NamedCurves.nistP384, "ES384", "P-384"), (ECCurve.NamedCurves.nistP521, "ES512", "P-521") })
        {
            using var ec = ECDsa.Create(curve); var p = ec.ExportParameters(false);
            var ecJwk = Element(new JsonObject { ["kty"] = "EC", ["crv"] = name, ["x"] = Base64UrlEncoder.Encode(p.Q.X), ["y"] = Base64UrlEncoder.Encode(p.Q.Y) });
            var proofKey = new DpopProofKey(new(new ECDsaSecurityKey(ec), algorithm), ecJwk); var ecAccess = await fixture.Access(proofKey.Thumbprint);
            await new DpopRequestValidator(new InMemoryDpopReplayStore()).ValidateAsync(proofKey.CreateProof(HttpMethod.Get, Target, ecAccess.Credential), HttpMethod.Get, Target, ecAccess);
        }
        using var weak = RSA.Create(1024); var weakJwk = PublicRsa(weak); string weakThumbprint = Base64UrlEncoder.Encode(new JsonWebKey(weakJwk.GetRawText()).ComputeJwkThumbprint());
        var weakAccess = await fixture.Access(weakThumbprint);
        Assert.AreEqual(DpopFailure.InvalidProof, (await Assert.ThrowsAsync<DpopValidationException>(() => new DpopRequestValidator(new InMemoryDpopReplayStore()).ValidateAsync(
            Proof(new(new RsaSecurityKey(key), "RS256"), weakJwk, Claims(weakAccess.Credential)), HttpMethod.Get, Target, weakAccess))).Reason);
        var wrongAlgorithm = Proof(new(new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(32)), "HS256"), jwk, Claims(access.Credential));
        Assert.AreEqual(DpopFailure.InvalidProof, (await Assert.ThrowsAsync<DpopValidationException>(() => new DpopRequestValidator(new InMemoryDpopReplayStore()).ValidateAsync(wrongAlgorithm, HttpMethod.Get, Target, access))).Reason);
        var clock = new Clock(DateTimeOffset.UtcNow); var replay = new InMemoryDpopReplayStore(2, clock);
        var results = await Task.WhenAll(Enumerable.Range(0, 32).Select(_ => Task.Run(async () => await replay.TryUseAsync("same", clock.GetUtcNow().AddMinutes(1)))));
        Assert.AreEqual(1, results.Count(r => r));
        Assert.IsTrue(await replay.TryUseAsync("second", clock.GetUtcNow().AddMinutes(1))); Assert.IsFalse(await replay.TryUseAsync("capacity", clock.GetUtcNow().AddMinutes(1)));
        clock.Now = clock.Now.AddMinutes(2); Assert.IsTrue(await replay.TryUseAsync("same", clock.GetUtcNow().AddMinutes(1)));
        Assert.IsFalse(await replay.TryUseAsync("expired", clock.GetUtcNow().AddMinutes(-1)));
        var sweeping = new InMemoryDpopReplayStore(100, clock);
        for (int i = 0; i < 65; i++) Assert.IsTrue(await sweeping.TryUseAsync(i.ToString(System.Globalization.CultureInfo.InvariantCulture), clock.GetUtcNow().AddMinutes(1)));
        var replacing = new InMemoryDpopReplayStore(100, clock); Assert.IsTrue(await replacing.TryUseAsync("replace", clock.Now.AddSeconds(1))); clock.Now = clock.Now.AddSeconds(2);
        Assert.IsTrue(await replacing.TryUseAsync("replace", clock.Now.AddMinutes(1)));
        Assert.Throws<ArgumentOutOfRangeException>(() => new InMemoryDpopReplayStore(0));
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        await Assert.ThrowsAsync<OperationCanceledException>(() => replay.TryUseAsync("cancelled", clock.Now.AddMinutes(1), cancelled.Token).AsTask());
    }

    [TestMethod]
    public async Task MutualTlsConfirmsTheAuthenticatedPeerCertificateAndRejectsMissingOrExpiredBindings()
    {
        using var fixture = new Fixture(); using var key = RSA.Create(2048);
        using var certificate = new CertificateRequest("CN=peer", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
        string hash = Base64UrlEncoder.Encode(certificate.GetCertHash(HashAlgorithmName.SHA256));
        foreach (var (cnf, expected) in new (JsonNode?, bool)[] { (new JsonObject { ["x5t#S256"] = hash }, true), (null, false), (new JsonArray(), false), (new JsonObject(), false),
            (new JsonObject { ["x5t#S256"] = 42 }, false), (new JsonObject { ["x5t#S256"] = "other" }, false) })
        {
            var token = await new KeycloakAccessTokenValidator(fixture.Oidc, "api").ValidateAsync(fixture.Token(confirmation: cnf));
            Assert.AreEqual(expected, MutualTlsTokenBinding.Matches(token, certificate));
        }
        var expired = await new KeycloakAccessTokenValidator(fixture.Oidc, "api").ValidateAsync(fixture.Token(confirmation: new JsonObject { ["x5t#S256"] = hash }, expirySeconds: -5));
        Assert.IsFalse(MutualTlsTokenBinding.Matches(expired, certificate));
        Assert.Throws<ArgumentNullException>(() => MutualTlsTokenBinding.Matches(null!, certificate));
        var valid = await fixture.Access("jkt"); Assert.Throws<ArgumentNullException>(() => MutualTlsTokenBinding.Matches(valid, null!));
    }

    [TestMethod]
    public void ProofKeysRejectPrivateSymmetricAndAmbiguousInputsAndKeepNoncesOriginBound()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256); var signer = DpopProofKey.FromEcdsa(key, new Clock(DateTimeOffset.UtcNow));
        var jwk = HeaderJwk(signer.CreateProof(HttpMethod.Get, Target));
        Assert.IsFalse(jwk.TryGetProperty("d", out _)); Assert.AreEqual("EC", jwk.GetProperty("kty").GetString());
        signer.SetNonce(Target, "nonce");
        using var payload = JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(signer.CreateProof(HttpMethod.Get, new("https://other.invalid/path")).Split('.')[1]));
        Assert.IsFalse(payload.RootElement.TryGetProperty("nonce", out _));
        foreach (string nonce in new[] { "", " ", new string('a', 1025), "non-ascii-中" }) Assert.Throws<ArgumentException>(() => signer.SetNonce(Target, nonce));
        Assert.Throws<ArgumentNullException>(() => signer.SetNonce(Target, null!));
        foreach (var uri in new Uri[] { new("relative", UriKind.Relative), new("file:///tmp"), new("https://user:secret@resource.invalid/"), new("https://resource.invalid/#fragment") })
            Assert.Throws<ArgumentException>(() => signer.CreateProof(HttpMethod.Get, uri));
        Assert.Throws<ArgumentNullException>(() => signer.CreateProof(null!, Target)); Assert.Throws<ArgumentNullException>(() => signer.CreateProof(HttpMethod.Get, null!));
        Assert.Throws<ArgumentException>(() => signer.CreateProof(HttpMethod.Get, Target, ""));
        Assert.Throws<ArgumentNullException>(() => DpopProofKey.FromEcdsa(null!));
        using var otherCurve = ECDsa.Create(ECCurve.NamedCurves.nistP384); Assert.Throws<ArgumentException>(() => DpopProofKey.FromEcdsa(otherCurve));
        Assert.Throws<ArgumentNullException>(() => new DpopProofKey(null!, jwk));
        Assert.Throws<ArgumentException>(() => new DpopProofKey(new(new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(32)), "HS256"), jwk));
        foreach (string json in new[] { "[]", """{"kty":"oct"}""", """{"kty":"EC","d":"private"}""" })
            Assert.Throws<ArgumentException>(() => new DpopProofKey(new(new ECDsaSecurityKey(key), "ES256"), JsonDocument.Parse(json).RootElement));
        foreach (string parameter in new[] { "d", "p", "q", "dp", "dq", "qi", "oth", "k" })
        {
            var privatePart = JsonNode.Parse(jwk.GetRawText())!; privatePart[parameter] = "private";
            Assert.Throws<ArgumentException>(() => new DpopProofKey(new(new ECDsaSecurityKey(key), "ES256"), Element(privatePart)));
        }
    }

    private static Dictionary<string, object> Claims(string access) => new() { ["jti"] = Guid.NewGuid().ToString("N"), ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
        ["htm"] = "GET", ["htu"] = Target.GetLeftPart(UriPartial.Path), ["ath"] = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(access))) };
    private static string Proof(SigningCredentials signing, JsonElement? jwk, Dictionary<string, object> claims, string type = "dpop+jwt", bool critical = false)
    {
        var headers = new Dictionary<string, object>(); if (jwk is not null) headers["jwk"] = jwk.Value; if (critical) headers["crit"] = new[] { "unknown" };
        return new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(new SecurityTokenDescriptor { SigningCredentials = signing, TokenType = type, Claims = claims, AdditionalHeaderClaims = headers });
    }
    private static JsonElement HeaderJwk(string proof) { using var doc = JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(proof.Split('.')[0])); return doc.RootElement.GetProperty("jwk").Clone(); }
    private static JsonElement Element(JsonNode value) { using var doc = JsonDocument.Parse(value.ToJsonString()); return doc.RootElement.Clone(); }
    private static JsonElement PublicRsa(RSA key) { var p = key.ExportParameters(false); return Element(new JsonObject { ["kty"] = "RSA", ["n"] = Base64UrlEncoder.Encode(p.Modulus), ["e"] = Base64UrlEncoder.Encode(p.Exponent) }); }
    private sealed class Clock(DateTimeOffset now) : TimeProvider { internal DateTimeOffset Now = now; public override DateTimeOffset GetUtcNow() => Now; }
    private sealed class Fixture : IDisposable
    {
        private readonly RSA signing = RSA.Create(2048), other = RSA.Create(2048); internal readonly RSA EncryptionKey = RSA.Create(2048);
        internal readonly Handler Handler = new(); private readonly HttpClient http; internal readonly OidcClient Oidc;
        internal Fixture() { http = new(Handler); Oidc = new(new(http, new("https://identity.invalid/"), "r")); Handler.Response = new JsonObject { ["keys"] = new JsonArray(JsonNode.Parse(PublicRsa(signing).GetRawText())) }.ToJsonString(); }
        internal string Token(object? type = null, JsonNode? confirmation = null, string audience = "api", string? issuer = null, string subject = "user", int expirySeconds = 300, bool wrongKey = false, string algorithm = "RS256", bool encrypted = false, bool missingType = false, string keyEncryption = SecurityAlgorithms.RsaOAEP)
        {
            // A null sentinel omits typ; callers requiring the default explicitly set Bearer via the convenience overload below.
            var claims = new Dictionary<string, object> { ["sub"] = subject }; if (!missingType) claims["typ"] = type ?? "Bearer"; if (confirmation is not null) claims["cnf"] = Element(confirmation);
            var now = DateTime.UtcNow;
            return new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(new SecurityTokenDescriptor { Issuer = issuer ?? Oidc.Issuer.AbsoluteUri, Audience = audience,
                IssuedAt = now.AddMinutes(-1), NotBefore = now.AddMinutes(-10), Expires = now.AddSeconds(expirySeconds), Claims = claims,
                SigningCredentials = new(new RsaSecurityKey(wrongKey ? other : signing), algorithm),
                EncryptingCredentials = encrypted ? new(new RsaSecurityKey(EncryptionKey), keyEncryption, SecurityAlgorithms.Aes128CbcHmacSha256) : null });
        }
        internal Task<VerifiedAccessToken> Access(string thumbprint) => new KeycloakAccessTokenValidator(Oidc, "api").ValidateAsync(Token(type: "DPoP", confirmation: new JsonObject { ["jkt"] = thumbprint }));
        public void Dispose() { http.Dispose(); signing.Dispose(); other.Dispose(); EncryptionKey.Dispose(); }
    }
    private sealed class Handler : HttpMessageHandler
    {
        internal string Response = "{}";
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        { cancellationToken.ThrowIfCancellationRequested(); return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(Response) }); }
    }
}

