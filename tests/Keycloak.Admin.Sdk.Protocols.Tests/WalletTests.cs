using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Keycloak.Admin.Sdk.Capabilities;
using Keycloak.Admin.Sdk.Protocols;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualStudio.TestTools.UnitTesting;

[TestClass]
public sealed class WalletTests
{
    [TestMethod]
    public async Task WalletBoundariesRejectNullTrustMismatchedAlgorithmsAndUnverifiedClaimSelections()
    {
        using var f = new Fixture();
        Assert.Throws<ArgumentNullException>(() => new Oid4vcIssuerClient(null!)); Assert.Throws<ArgumentNullException>(() => new Oid4vcAccountClient(null!)); Assert.Throws<ArgumentNullException>(() => new Oid4vcTokenClient(null!));
        var metadata = new Oid4vcIssuerMetadata(f.Issuer, Json(f.Metadata())); Assert.AreEqual(f.Issuer.AbsoluteUri, metadata.Document.GetProperty("credential_issuer").GetString());
        await Assert.ThrowsAsync<ArgumentException>(() => f.Wallet.GetOfferAsync(new("relative", UriKind.Relative)));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => f.Wallet.CreateOfferAsync("sd", "token", width: 801));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => f.Wallet.CreateOfferAsync("sd", "token", height: 0));
        using var holder = ECDsa.Create(ECCurve.NamedCurves.nistP256); var proof = Oid4vcProofKey.FromEcdsa(holder);
        var differentAlgorithm = JsonNode.Parse(proof.PublicJwk.GetRawText())!; differentAlgorithm["alg"] = "ES384";
        Assert.Throws<ArgumentException>(() => new Oid4vcProofKey(new(new ECDsaSecurityKey(holder), "ES256"), Json(differentAlgorithm.ToJsonString())));
        Assert.AreEqual("server-challenge", new JsonWebToken(proof.CreateClientAttestationProof(f.Issuer, "client", "server-challenge")).GetPayloadValue<string>("challenge"));
        const string parsedOnly = "eyJhbGciOiJub25lIn0.e30.";
        var jwtCredential = new VerifiedOid4vcCredential(parsedOnly, Json("{}"), Json("{}"), "jwt_vc_json", null, []);
        Assert.Throws<InvalidDataException>(() => jwtCredential.SelectClaims([]));
        var sdCredential = new VerifiedOid4vcCredential(parsedOnly, Json("{}"), Json("{}"), "dc+sd-jwt", null, []);
        Assert.Throws<InvalidDataException>(() => sdCredential.SelectClaims(["unknown"]));
        await Assert.ThrowsAsync<ArgumentException>(() => new Oid4vcCredentialValidator(new(f.Transport)).ValidateAsync("credential", new(new("https://foreign.invalid/realms/r"), "sd", f.Configuration("sd").Document), null));
        f.Handler.Body = "";
        await Assert.ThrowsAsync<InvalidDataException>(() => new Oid4vcCredentialValidator(new(f.Transport)).ValidateAsync("signed.credential.value", f.Configuration("jwt"), null));
        using var rsa = RSA.Create(2048); var key = new RsaSecurityKey(rsa); var request = new EncryptingCredentials(key, "RSA-OAEP", "A256GCM");
        Assert.Throws<InvalidDataException>(() => WalletEcdhJwe.Encrypt("{}", RsaJwk(rsa)));
        Assert.Throws<ArgumentException>(() => new Oid4vcCredentialEncryption(request, new ECDsaSecurityKey(holder), proof.PublicJwk));
        Assert.Throws<ArgumentException>(() => new Oid4vcCredentialEncryption(request, key, RsaJwk(rsa)));
        foreach (string cipher in new[] { "A128GCM", "A192GCM", "A256GCM", "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512" })
            Assert.IsNotNull(new Oid4vcCredentialEncryption(new(key, "RSA-OAEP", cipher), responseContentEncryption: cipher));
    }
    [TestMethod]
    public async Task MetadataAndOffersCannotRedirectCredentialsOrCrossRealmBoundaries()
    {
        using var f = new Fixture(); f.Handler.Body = f.Metadata();
        var metadata = await f.Wallet.GetIssuerMetadataAsync(); Assert.AreEqual("dc+sd-jwt", metadata.Configurations["sd"].Format);
        Assert.AreEqual("/.well-known/openid-credential-issuer/realms/r", f.Handler.Target!.AbsolutePath);
        Assert.AreEqual(f.Issuer, metadata.Issuer); Assert.AreEqual(3, metadata.Configurations.Count);
        await f.Wallet.GetJwtIssuerMetadataAsync(); Assert.AreEqual("/.well-known/jwt-vc-issuer/realms/r", f.Handler.Target.AbsolutePath);
        f.Handler.Media = "application/jwt"; f.Handler.Body = "signed.metadata";
        Assert.AreEqual("signed.metadata", Encoding.UTF8.GetString((await f.Wallet.GetSignedIssuerMetadataAsync()).RawBody.Span));
        f.Handler.Media = "application/json"; f.Handler.Body = "{}";
        await f.Wallet.RequestNonceAsync(); Assert.AreEqual("POST", f.Handler.Method);
        await f.Wallet.GetOfferAsync(new(f.Issuer.AbsoluteUri + "/protocol/oid4vc/credential-offer/opaque%2Bhandle"));
        Assert.IsNull(f.Handler.Authorization); StringAssert.EndsWith(f.Handler.Target.AbsoluteUri, "opaque%2Bhandle");
        foreach (string bad in new[] { "https://foreign.invalid/offer", f.Issuer.AbsoluteUri + "/protocol/oid4vc/credential-offer/x/y",
            f.Issuer.AbsoluteUri + "/protocol/oid4vc/credential-offer/x?query", f.Issuer.AbsoluteUri + "/protocol/oid4vc/credential-offer/x#fragment",
            f.Issuer.AbsoluteUri + "/protocol/oid4vc/credential-offer/%2e%2e" })
            await Assert.ThrowsAsync<ArgumentException>(() => f.Wallet.GetOfferAsync(new(bad)));
        foreach (Action<JsonObject> change in new Action<JsonObject>[] { n => n["credential_issuer"] = "https://foreign.invalid", n => n["credential_endpoint"] = "https://foreign.invalid",
            n => n["nonce_endpoint"] = "https://foreign.invalid", n => n["authorization_servers"] = new JsonArray(), n => n["authorization_servers"] = new JsonArray(JsonValue.Create("https://foreign.invalid")),
            n => n["authorization_servers"] = false, n => n["credential_configurations_supported"]!["sd"]!["format"] = "ldp_vc" })
        {
            var document = JsonNode.Parse(f.Metadata())!.AsObject(); change(document); f.Handler.Body = document.ToJsonString();
            await Assert.ThrowsAsync<InvalidDataException>(() => f.Wallet.GetIssuerMetadataAsync());
        }
        f.Handler.Body = ""; await Assert.ThrowsAsync<InvalidDataException>(() => f.Wallet.GetIssuerMetadataAsync());
        Assert.Throws<InvalidDataException>(() => new Oid4vcIssuerMetadata(f.Issuer, Json("[]")));
        Assert.Throws<InvalidDataException>(() => new Oid4vcIssuerMetadata(f.Issuer, Json("{\"credential_issuer\":\"x\",\"credential_issuer\":\"y\"}")));
        Assert.Throws<InvalidDataException>(() => WalletJson.String(Json("{}"), "missing"));
        Assert.Throws<InvalidDataException>(() => WalletJson.String(Json("{\"x\":1}"), "x"));
        foreach (string bad in new[] { "", " ", "control\n", new string('a', 2049) }) Assert.Throws<ArgumentException>(() => WalletJson.Text(bad));
        foreach (string bad in new[] { "", " ", "a b", new string('a', 65537), "é" }) Assert.Throws<ArgumentException>(() => WalletJson.Credential(bad));
    }

    [TestMethod]
    public async Task ExperimentalOffersAndMdocUseIndependentFlagsBeforeHttp()
    {
        using var f = new Fixture();
        await f.Wallet.CreateOfferAsync("sd", "token"); StringAssert.Contains(f.Handler.Target!.Query, "pre_authorized=false");
        await f.Wallet.CreateOfferAsync("sd", "token", true, "target", DateTimeOffset.FromUnixTimeSeconds(1234), Oid4vcOfferResponseType.UriWithQr, 800, 1);
        StringAssert.Contains(f.Handler.Target.Query, "target_user=target"); StringAssert.Contains(f.Handler.Target.Query, "expire=1234"); StringAssert.Contains(f.Handler.Target.Query, "type=uri_qr");
        f.Handler.Media = "image/png"; f.Handler.Body = "png";
        var png = await f.Wallet.CreateOfferAsync("sd", "token", responseType: Oid4vcOfferResponseType.Qr); Assert.AreEqual("image/png", png.BodyMediaType);
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => f.Wallet.CreateOfferAsync("sd", "t", width: 0));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => f.Wallet.CreateOfferAsync("sd", "t", height: 801));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => f.Wallet.CreateOfferAsync("sd", "t", responseType: (Oid4vcOfferResponseType)9));
        f.Handler.Media = "application/json"; f.Handler.Body = "{}";
        foreach (string name in new[] { "WalletOffers", "WalletPreAuthorized", "WalletMdoc" })
        {
            f.Flags["KeycloakSdk.Protocols." + name] = false; f.Gate.Replace(f.Flags); int before = f.Handler.Calls;
            if (name == "WalletMdoc") await Assert.ThrowsAsync<InvalidOperationException>(() => f.Wallet.RequestCredentialAsync(f.Configuration("mdoc"), "token"));
            else await Assert.ThrowsAsync<InvalidOperationException>(() => f.Wallet.CreateOfferAsync("sd", "token", true));
            Assert.AreEqual(before, f.Handler.Calls); f.Flags["KeycloakSdk.Protocols." + name] = true; f.Gate.Replace(f.Flags);
        }
        f.Flags["KeycloakSdk.Protocols.WalletPreAuthorized"] = false; f.Gate.Replace(f.Flags);
        await f.Wallet.CreateOfferAsync("sd", "token"); // An authorization-code offer does not require the pre-authorized feature.
        await f.Wallet.RequestCredentialAsync(f.Configuration("mdoc"), "token");
        await f.Wallet.RequestCredentialAsync(f.Configuration("sd"), "token", ["proof"], "credential-id");
        Assert.AreEqual("credential-id", Json(f.Handler.RequestBody!).GetProperty("credential_identifier").GetString());
        await f.Wallet.RequestCredentialAsync(f.Configuration("jwt"), "token", attestationProofs: Json("[\"key.attestation.jwt\"]"));
        Assert.AreEqual(1, Json(f.Handler.RequestBody!).GetProperty("proofs").GetProperty("attestation").GetArrayLength());
        await Assert.ThrowsAsync<ArgumentException>(() => f.Wallet.RequestCredentialAsync(new(new("https://other.invalid"), "x", Json("{\"format\":\"dc+sd-jwt\"}")), "t"));
        await Assert.ThrowsAsync<ArgumentException>(() => f.Wallet.RequestCredentialAsync(f.Configuration("sd"), "t", [], attestationProofs: Json("[]")));
        foreach (string[] bad in new[] { Array.Empty<string>(), Enumerable.Repeat("x", 101).ToArray() })
            await Assert.ThrowsAsync<ArgumentException>(() => f.Wallet.RequestCredentialAsync(f.Configuration("sd"), "t", bad));
        foreach (string bad in new[] { "{}", "[]", "[" + string.Join(',', Enumerable.Repeat("\"x\"", 101)) + "]" })
            await Assert.ThrowsAsync<ArgumentException>(() => f.Wallet.RequestCredentialAsync(f.Configuration("sd"), "t", attestationProofs: Json(bad)));
    }

    [TestMethod]
    public async Task CredentialGrantsAccountLifecycleAndAttestationRetainDistinctContracts()
    {
        using var f = new Fixture(); var tokens = new Oid4vcTokenClient(f.Transport); var client = OAuthClientAuthentication.Public("wallet");
        var details = Json("[{\"type\":\"openid_credential\",\"credential_configuration_id\":\"sd\"}]");
        await tokens.RedeemPreAuthorizedCodeAsync(client, "pre-code", "1234", details);
        var form = f.Handler.RequestBody!; StringAssert.Contains(form, "pre-authorized_code=pre-code"); StringAssert.Contains(form, "tx_code=1234"); StringAssert.Contains(form, "authorization_details=");
        await tokens.RedeemPreAuthorizedCodeAsync(client, "pre-code"); Assert.IsFalse(f.Handler.RequestBody!.Contains("tx_code", StringComparison.Ordinal));
        await tokens.RefreshCredentialTokenAsync(client, "refresh"); StringAssert.Contains(f.Handler.RequestBody!, "grant_type=refresh_token");
        int requested = 0;
        var attested = OAuthClientAuthentication.Attestation("wallet", (target, ct) => { ct.ThrowIfCancellationRequested(); Assert.AreEqual(f.Issuer.AbsoluteUri + "/protocol/openid-connect/token", target.AbsoluteUri); requested++; return ValueTask.FromResult(new OAuthClientAttestation("attestation", "proof")); });
        await tokens.RefreshCredentialTokenAsync(attested, "refresh"); Assert.AreEqual("attestation", f.Handler.Attestation); Assert.AreEqual("proof", f.Handler.AttestationProof);
        f.Flags["KeycloakSdk.Protocols.WalletAttestation"] = false; f.Gate.Replace(f.Flags);
        await Assert.ThrowsAsync<InvalidOperationException>(() => tokens.RefreshCredentialTokenAsync(attested, "refresh")); Assert.AreEqual(1, requested);
        var account = new Oid4vcAccountClient(f.Transport);
        await account.GetEntitlementsAsync("user"); Assert.AreEqual("/realms/r/account/verifiable-credentials", f.Handler.Target!.AbsolutePath);
        await account.RevokeEntitlementAsync("scope", "user"); Assert.AreEqual("DELETE", f.Handler.Method);
        await account.GetIssuedCredentialsAsync("user"); Assert.AreEqual("/realms/r/account/issued-verifiable-credentials", f.Handler.Target.AbsolutePath);
        await account.RevokeIssuedCredentialAsync("id", "user"); Assert.AreEqual("/realms/r/account/issued-verifiable-credentials/id", f.Handler.Target.AbsolutePath);
        Assert.IsFalse(new OAuthClientAttestation("sensitive", "secret").ToString()!.Contains("sensitive", StringComparison.Ordinal));
        Assert.Throws<ArgumentNullException>(() => OAuthClientAuthentication.Attestation("wallet", null!));
        Assert.IsTrue(OidcClient.AuthorizationFeatures("openid", new() { AuthorizationDetails = details }).Contains("KeycloakSdk.Protocols.Wallet", StringComparer.Ordinal));
        Assert.IsTrue(OidcClient.AuthorizationFeatures("openid", new() { IssuerState = "state" }).Contains("KeycloakSdk.Protocols.Wallet", StringComparer.Ordinal));
        Assert.AreEqual("issuer_state", new OidcAuthorizationOptions { IssuerState = "state" }.Parameters().Single().Key);
        foreach (string invalid in new[] { "{}", "[]", "[{},{}]", "[{\"type\":\"other\"}]", "[{\"type\":\"openid_credential\",\"large\":\"" + new string('a', 32768) + "\"}]" })
            Assert.Throws<ArgumentException>(() => new OidcAuthorizationOptions { AuthorizationDetails = Json(invalid) }.Parameters().ToArray());
    }

    [TestMethod]
    public async Task HolderProofUsesExactNonceIssuerAndFreshClientProofWithoutPrivateJwk()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256); var holder = Oid4vcProofKey.FromEcdsa(key);
        var proof = new JsonWebToken(holder.CreateIssuanceProof(new("https://issuer.invalid/realms/r"), "nonce", "wallet", "attestation.jwt"));
        Assert.AreEqual("openid4vci-proof+jwt", proof.Typ); Assert.AreEqual("wallet", proof.Issuer); Assert.AreEqual("nonce", proof.GetPayloadValue<string>("nonce"));
        Assert.IsFalse(proof.GetHeaderValue<JsonElement>("jwk").TryGetProperty("d", out _)); Assert.AreEqual("attestation.jwt", proof.GetHeaderValue<string>("key_attestation"));
        var result = await new JsonWebTokenHandler().ValidateTokenAsync(proof.EncodedToken, new TokenValidationParameters { IssuerSigningKey = new ECDsaSecurityKey(key), ValidateIssuer = false, ValidateAudience = false, ValidateLifetime = false });
        Assert.IsTrue(result.IsValid); Assert.AreEqual(holder.Thumbprint, Base64UrlEncoder.Encode(new ECDsaSecurityKey(key).ComputeJwkThumbprint()));
        var anonymous = new JsonWebToken(holder.CreateIssuanceProof(new("https://issuer.invalid/realms/r"), "nonce")); Assert.AreEqual("", anonymous.Issuer);
        var first = new JsonWebToken(holder.CreateClientAttestationProof(new("https://issuer.invalid/realms/r"), "wallet", "challenge"));
        var second = new JsonWebToken(holder.CreateClientAttestationProof(new("https://issuer.invalid/realms/r"), "wallet"));
        Assert.AreEqual("oauth-client-attestation-pop+jwt", first.Typ); Assert.AreNotEqual(first.Id, second.Id);
        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Assert.Throws<ArgumentException>(() => new Oid4vcProofKey(new(new ECDsaSecurityKey(other), "ES256"), holder.PublicJwk));
        Assert.Throws<ArgumentException>(() => new Oid4vcProofKey(new(new SymmetricSecurityKey(new byte[32]), "HS256"), holder.PublicJwk));
        using var wrongCurve = ECDsa.Create(ECCurve.NamedCurves.nistP384); Assert.Throws<ArgumentException>(() => Oid4vcProofKey.FromEcdsa(wrongCurve));
        foreach (string target in new[] { "https://issuer.invalid/", "https://issuer.invalid?x" }) Assert.Throws<ArgumentException>(() => holder.CreateIssuanceProof(new(target), "nonce"));
    }

    [TestMethod]
    public async Task RequestAndOptionalResponseEncryptionRejectAlgorithmDowngrades()
    {
        using var f = new Fixture(); using var rsa = RSA.Create(2048); using var attacker = RSA.Create(2048);
        var key = new RsaSecurityKey(rsa); var p = rsa.ExportParameters(false);
        var jwk = Json(new JsonObject { ["kty"] = "RSA", ["alg"] = "RSA-OAEP-256", ["n"] = Base64UrlEncoder.Encode(p.Modulus), ["e"] = Base64UrlEncoder.Encode(p.Exponent) }.ToJsonString());
        foreach (string algorithm in new[] { "RSA-OAEP", "RSA-OAEP-256" })
        {
            var encrypting = new EncryptingCredentials(key, algorithm, "A256GCM") { CryptoProviderFactory = new JweCryptoProviderFactory() };
            var requestOnly = new Oid4vcCredentialEncryption(encrypting);
            await f.Wallet.RequestCredentialAsync(f.Configuration("sd"), "access", encryption: requestOnly);
            var compact = new JsonWebToken(f.Handler.RequestBody!); Assert.IsTrue(compact.IsEncrypted);
            string decoded = WalletJwe.Decrypt(f.Handler.RequestBody!, compact, JweCryptoProviderFactory.DecryptionKey(key));
            Assert.AreEqual("sd", Json(decoded).GetProperty("credential_configuration_id").GetString());
            var advertised = JsonNode.Parse(jwk.GetRawText())!; advertised["alg"] = algorithm;
            var responseOnly = new Oid4vcCredentialEncryption(encrypting, responseDecryptionKey: key, responsePublicJwk: Json(advertised.ToJsonString()));
            f.Handler.Media = "application/jwt"; f.Handler.Body = WalletJwe.Encrypt("{\"credentials\":[]}", encrypting);
            var encrypted = await f.Wallet.RequestCredentialAsync(f.Configuration("sd"), "access", encryption: responseOnly);
            Assert.IsFalse(new JsonWebToken(f.Handler.Body).EncodedToken.Contains("credentials", StringComparison.Ordinal));
            string original = WalletJwe.Decrypt(f.Handler.RequestBody!, new(f.Handler.RequestBody!), JweCryptoProviderFactory.DecryptionKey(key));
            Assert.AreEqual("A256GCM", Json(original).GetProperty("credential_response_encryption").GetProperty("enc").GetString());
            Assert.AreEqual(0, responseOnly.DecryptResponse(encrypted).GetProperty("credentials").GetArrayLength());
            var attackerJwk = JsonNode.Parse(RsaJwk(attacker).GetRawText())!; attackerJwk["alg"] = algorithm;
            var wrong = new Oid4vcCredentialEncryption(encrypting, responseDecryptionKey: new RsaSecurityKey(attacker), responsePublicJwk: Json(attackerJwk.ToJsonString()));
            var error = Assert.Throws<InvalidDataException>(() => wrong.DecryptResponse(encrypted)); Assert.IsNull(error.InnerException);
            f.Handler.Media = "application/json"; f.Handler.Body = "{}";
        }
        Assert.Throws<ArgumentNullException>(() => new Oid4vcCredentialEncryption(null!));
        Assert.Throws<ArgumentException>(() => new Oid4vcCredentialEncryption(new(key, "RSA-OAEP", "A256GCM"), responseDecryptionKey: key));
        Assert.Throws<ArgumentException>(() => new Oid4vcCredentialEncryption(new(key, "RSA1_5", "A256GCM")));
        Assert.Throws<ArgumentException>(() => new Oid4vcCredentialEncryption(new(key, "RSA-OAEP", "unsupported")));
        Assert.Throws<ArgumentException>(() => new Oid4vcCredentialEncryption(new(key, "RSA-OAEP", "A256GCM"), responseDecryptionKey: key, responsePublicJwk: RsaJwk(attacker)));
        var encryption = new Oid4vcCredentialEncryption(new(key, "RSA-OAEP", "A256GCM"), responseDecryptionKey: key, responsePublicJwk: jwk);
        foreach (var invalid in new[] { new ProtocolResponse(HttpStatusCode.OK, null), Raw(""), Raw("not-a-jwe"), Raw(new string('x', 65537)) })
            Assert.Throws<InvalidDataException>(() => encryption.DecryptResponse(invalid));
        foreach (string cipher in new[] { "A128GCM", "A256GCM" })
        {
            var token = WalletJwe.Encrypt("not-json", new(key, "RSA-OAEP", cipher));
            Assert.Throws<InvalidDataException>(() => encryption.DecryptResponse(Raw(token)));
        }
        foreach (string zip in new[] { "DEF", "" })
        {
            string[] parts = WalletJwe.Encrypt("{}", new(key, "RSA-OAEP-256", "A256GCM")).Split('.');
            var header = JsonNode.Parse(Base64UrlEncoder.Decode(parts[0]))!; header["zip"] = zip; parts[0] = Base64UrlEncoder.Encode(header.ToJsonString());
            Assert.Throws<InvalidDataException>(() => encryption.DecryptResponse(Raw(string.Join('.', parts))));
        }
        var plainResponse = new Oid4vcCredentialEncryption(new(key, "RSA-OAEP", "A128CBC-HS256"));
        Assert.Throws<InvalidDataException>(() => plainResponse.DecryptResponse(Raw("credential")));
    }

    [TestMethod]
    public async Task SignedCredentialsPinIssuerTypeLifetimeHolderAndDisclosureIntegrity()
    {
        using var f = new Fixture(); using var signer = RSA.Create(2048); using var holderRsa = RSA.Create(2048);
        var holderKey = new Oid4vcProofKey(new(new RsaSecurityKey(holderRsa), "RS256"), RsaJwk(holderRsa));
        f.Handler.Body = new JsonObject { ["keys"] = new JsonArray(JsonNode.Parse(RsaJwk(signer).GetRawText())) }.ToJsonString();
        var validator = new Oid4vcCredentialValidator(new(f.Transport), f.Issuer.AbsoluteUri);
        JsonObject Claims() => new() { ["iss"] = f.Issuer.AbsoluteUri, ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), ["exp"] = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds(),
            ["vct"] = "https://credential.invalid/person", ["cnf"] = new JsonObject { ["jwk"] = JsonNode.Parse(holderKey.PublicJwk.GetRawText()) } };
        string disclosure = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes("[\"salt-salt-salt-salt\",\"email\",\"user@example.invalid\"]"));
        var claims = Claims(); claims["_sd_alg"] = "sha-256"; claims["_sd"] = new JsonArray(JsonValue.Create(SdJwtDisclosures.Hash("sha-256", disclosure)));
        string jwt = Sign(signer, "dc+sd-jwt", claims), credential = jwt + "~" + disclosure + "~";
        var verified = await validator.ValidateAsync(credential, f.Configuration("sd"), holderKey.Thumbprint);
        Assert.AreEqual("user@example.invalid", verified.Claims.GetProperty("email").GetString()); Assert.AreEqual("dc+sd-jwt", verified.Format);
        Assert.AreEqual(holderKey.Thumbprint, verified.HolderThumbprint); Assert.AreEqual(1, verified.Disclosures.Count);
        var kb = new JsonWebToken(verified.CreateSdJwtPresentation([disclosure], "https://verifier.invalid", "nonce", holderKey).Split('~')[^1]);
        Assert.AreEqual("kb+jwt", kb.Typ); Assert.AreEqual("nonce", kb.GetPayloadValue<string>("nonce"));
        Assert.AreEqual(SdJwtDisclosures.Hash("sha-256", credential), kb.GetPayloadValue<string>("sd_hash"));
        Assert.IsTrue(verified.CreateSdJwtPresentation([], "aud", "nonce", holderKey).StartsWith(jwt + "~", StringComparison.Ordinal));
        Assert.Throws<InvalidDataException>(() => verified.CreateSdJwtPresentation(["unrelated"], "aud", "nonce", holderKey));
        using var otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Assert.Throws<InvalidDataException>(() => verified.CreateSdJwtPresentation([], "aud", "nonce", Oid4vcProofKey.FromEcdsa(otherKey)));
        await Assert.ThrowsAsync<InvalidDataException>(() => validator.ValidateAsync(credential, f.Configuration("sd"), "other-holder"));
        foreach (Action<JsonObject> mutate in new Action<JsonObject>[] { c => c["iss"] = "https://foreign.invalid", c => c["exp"] = 1, c => c["iat"] = "1", c => c["iat"] = 1.25,
            c => c["iat"] = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds(), c => c["vct"] = "other",
            c => c["exp"] = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture),
            c => c["exp"] = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds() + 0.25,
            c => c["nbf"] = DateTimeOffset.UtcNow.AddMinutes(-1).ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture),
            c => c["nbf"] = DateTimeOffset.UtcNow.AddMinutes(-1).ToUnixTimeSeconds() + 0.25 })
        { var bad = (JsonObject)claims.DeepClone(); mutate(bad); await Assert.ThrowsAsync<InvalidDataException>(() => validator.ValidateAsync(Sign(signer, "dc+sd-jwt", bad) + "~" + disclosure + "~", f.Configuration("sd"), holderKey.Thumbprint)); }
        await Assert.ThrowsAsync<InvalidDataException>(() => validator.ValidateAsync(Sign(signer, "JWT", claims) + "~" + disclosure + "~", f.Configuration("sd"), holderKey.Thumbprint));
        await Assert.ThrowsAsync<InvalidDataException>(() => validator.ValidateAsync(jwt, f.Configuration("sd"), holderKey.Thumbprint));
        await Assert.ThrowsAsync<InvalidDataException>(() => validator.ValidateAsync(credential + "proof", f.Configuration("sd"), holderKey.Thumbprint));
        await Assert.ThrowsAsync<ArgumentException>(() => validator.ValidateAsync(credential, f.Configuration("mdoc"), holderKey.Thumbprint));
        var jwtClaims = Claims(); jwtClaims.Remove("vct"); jwtClaims["vc"] = new JsonObject { ["credentialSubject"] = new JsonObject { ["name"] = "user" } };
        var jwtCredential = await validator.ValidateAsync(Sign(signer, "vc+jwt", jwtClaims), f.Configuration("jwt"), holderKey.Thumbprint);
        Assert.AreEqual("jwt_vc_json", jwtCredential.Format); Assert.Throws<InvalidDataException>(() => jwtCredential.CreateSdJwtPresentation([], "a", "n", holderKey));
        await Assert.ThrowsAsync<InvalidDataException>(() => validator.ValidateAsync(Sign(signer, "vc+jwt", jwtClaims) + "~", f.Configuration("jwt"), null));
        jwtClaims.Remove("cnf"); jwtClaims.Remove("iat");
        Assert.IsNull((await validator.ValidateAsync(Sign(signer, "vc+jwt", jwtClaims), f.Configuration("jwt"), null)).HolderThumbprint);
        var metadata = JsonNode.Parse(f.Metadata())!.AsObject(); metadata["iss"] = f.Issuer.AbsoluteUri; metadata["sub"] = f.Issuer.AbsoluteUri; metadata["exp"] = DateTimeOffset.UtcNow.AddMinutes(1).ToUnixTimeSeconds();
        Assert.AreEqual(3, (await validator.ValidateSignedMetadataAsync(Raw(Sign(signer, "openidvci-issuer-metadata+jwt", metadata)))).Configurations.Count);
        metadata["sub"] = "foreign"; await Assert.ThrowsAsync<InvalidDataException>(() => validator.ValidateSignedMetadataAsync(Raw(Sign(signer, "openidvci-issuer-metadata+jwt", metadata))));
        await Assert.ThrowsAsync<InvalidDataException>(() => validator.ValidateSignedMetadataAsync(new(HttpStatusCode.OK, null)));
        Assert.Throws<ArgumentException>(() => new Oid4vcCredentialValidator(new(f.Transport), allowedAlgorithms: []));
        Assert.Throws<ArgumentException>(() => new Oid4vcCredentialValidator(new(f.Transport), allowedAlgorithms: ["HS256"]));
        Assert.Throws<ArgumentNullException>(() => new Oid4vcCredentialValidator(null!));
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        await Assert.ThrowsAsync<OperationCanceledException>(() => validator.ValidateAsync(credential, f.Configuration("sd"), holderKey.Thumbprint, cancelled.Token));
    }

    private static JsonElement RsaJwk(RSA key)
    { var p = key.ExportParameters(false); return Json(new JsonObject { ["kty"] = "RSA", ["n"] = Base64UrlEncoder.Encode(p.Modulus), ["e"] = Base64UrlEncoder.Encode(p.Exponent) }.ToJsonString()); }
    private static ProtocolResponse Raw(string value) => new(HttpStatusCode.OK, null, rawBody: Encoding.UTF8.GetBytes(value), bodyMediaType: "application/jwt");
    private static string Sign(RSA key, string type, JsonObject claims)
        => new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(claims.ToJsonString(), new SigningCredentials(new RsaSecurityKey(key), "RS256"), new Dictionary<string, object> { ["typ"] = type });

    private static JsonElement Json(string text) { using var document = JsonDocument.Parse(text); return document.RootElement.Clone(); }
    private sealed class Handler : HttpMessageHandler
    {
        internal string Body = "{}", Media = "application/json"; internal Uri? Target; internal string? Method, RequestBody, Authorization, Attestation, AttestationProof; internal int Calls;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested(); Calls++; Target = request.RequestUri; Method = request.Method.Method; Authorization = request.Headers.Authorization?.ToString();
            RequestBody = request.Content is null ? null : await request.Content.ReadAsStringAsync(ct);
            Attestation = request.Headers.TryGetValues("OAuth-Client-Attestation", out var att) ? att.Single() : null;
            AttestationProof = request.Headers.TryGetValues("OAuth-Client-Attestation-PoP", out var pop) ? pop.Single() : null;
            return new(HttpStatusCode.OK) { Content = new StringContent(Body, Encoding.UTF8, Media) };
        }
    }
    private sealed class Fixture : IDisposable
    {
        internal readonly Handler Handler = new(); private readonly HttpClient http;
        internal readonly ProtocolTransport Transport; internal readonly Oid4vcIssuerClient Wallet;
        internal readonly Dictionary<string, bool> Flags = new[] { "", ".Oidc", ".Account", ".Wallet", ".WalletOffers", ".WalletPreAuthorized", ".WalletMdoc", ".WalletAttestation" }.ToDictionary(s => "KeycloakSdk.Protocols" + s, _ => true);
        internal readonly KeycloakFeatureSnapshotGate Gate; internal Uri Issuer => Transport.Issuer;
        internal Fixture() { http = new(Handler); Gate = new(Flags); Transport = new(http, new("https://issuer.invalid/"), "r", Gate); Wallet = new(Transport); }
        internal string Metadata() => new JsonObject { ["credential_issuer"] = Issuer.AbsoluteUri, ["credential_endpoint"] = Issuer.AbsoluteUri + "/protocol/oid4vc/credential", ["nonce_endpoint"] = Issuer.AbsoluteUri + "/protocol/oid4vc/nonce",
            ["authorization_servers"] = new JsonArray(JsonValue.Create(Issuer.AbsoluteUri)), ["credential_configurations_supported"] = new JsonObject {
                ["sd"] = new JsonObject { ["format"] = "dc+sd-jwt", ["vct"] = "https://credential.invalid/person" }, ["jwt"] = new JsonObject { ["format"] = "jwt_vc_json" }, ["mdoc"] = new JsonObject { ["format"] = "mso_mdoc" } } }.ToJsonString();
        internal Oid4vcCredentialConfiguration Configuration(string id) => new Oid4vcIssuerMetadata(Issuer, Json(Metadata())).Configurations[id];
        public void Dispose() => http.Dispose();
    }
}
