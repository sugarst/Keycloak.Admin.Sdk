using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Keycloak.Admin.Sdk.Protocols;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualStudio.TestTools.UnitTesting;

[TestClass]
public sealed class WalletJweTests
{
    [TestMethod]
    public void ExplicitAlgorithmsAuthenticateBothGcmAndCbcFraming()
    {
        using var rsa = RSA.Create(2048); var key = new RsaSecurityKey(rsa) { KeyId = "issuer" };
        foreach (string enc in new[] { "A128GCM", "A192GCM", "A256GCM", "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512" })
        foreach (string alg in new[] { "RSA-OAEP", "RSA-OAEP-256" })
        {
            var credentials = new EncryptingCredentials(key, alg, enc) { CryptoProviderFactory = new JweCryptoProviderFactory() };
            string token = WalletJwe.Encrypt("{\"name\":\"Alice\"}", credentials);
            Assert.AreEqual("{\"name\":\"Alice\"}", WalletJwe.Decrypt(token, new(token), JweCryptoProviderFactory.DecryptionKey(key)));
        }
        key.KeyId = null;
        string compact = WalletJwe.Encrypt("{}", new(key, "RSA-OAEP", "A256GCM")); var valid = new JsonWebToken(compact);
        foreach (string malformed in new[] { "too.short", compact + ".extra", compact + "=", compact.Replace('.', '!') })
            Assert.Throws<InvalidDataException>(() => WalletJwe.Decrypt(malformed, valid, key));
        foreach (int index in new[] { 2, 4 })
        { var parts = compact.Split('.'); parts[index] = "AA"; Assert.Throws<InvalidDataException>(() => WalletJwe.Decrypt(string.Join('.', parts), valid, key)); }
        var critical = compact.Split('.'); var header = JsonNode.Parse(Base64UrlEncoder.Decode(critical[0]))!; header["crit"] = new JsonArray("unknown"); critical[0] = Base64UrlEncoder.Encode(header.ToJsonString());
        Assert.Throws<InvalidDataException>(() => WalletJwe.Decrypt(string.Join('.', critical), valid, key));
        var wrongSize = compact.Split('.'); wrongSize[1] = Base64UrlEncoder.Encode(rsa.Encrypt(new byte[16], RSAEncryptionPadding.OaepSHA1));
        Assert.Throws<InvalidDataException>(() => WalletJwe.Decrypt(string.Join('.', wrongSize), valid, key));
        Assert.Throws<InvalidDataException>(() => WalletJwe.Encrypt("{}", new(key, "RSA-OAEP", "unsupportedGCM")));
        string invalidEnc = "A512GCM"; var badHeader = new JsonObject { ["alg"] = "RSA-OAEP", ["enc"] = invalidEnc };
        var unsupported = compact.Split('.'); unsupported[0] = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(badHeader.ToJsonString()));
        Assert.Throws<InvalidDataException>(() => WalletJwe.Decrypt(string.Join('.', unsupported), new(string.Join('.', unsupported)), key));
    }
}
