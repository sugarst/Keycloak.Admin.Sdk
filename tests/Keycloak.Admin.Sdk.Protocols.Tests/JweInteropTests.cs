using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Keycloak.Admin.Sdk.Protocols;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualStudio.TestTools.UnitTesting;

[TestClass]
public sealed class JweInteropTests
{
    [TestMethod]
    public void Oaep256InteroperatesWithPlatformRsaAcrossHostKeyRepresentationsWithoutDisposingHostKeys()
    {
        using var rsa = RSA.Create(2048);
        using var certificate = new CertificateRequest("CN=jwe", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
        using var publicCertificate = X509CertificateLoader.LoadCertificate(certificate.RawData);
        byte[] cek = RandomNumberGenerator.GetBytes(64); var factory = new JweCryptoProviderFactory();
        foreach (SecurityKey key in new SecurityKey[] { new RsaSecurityKey(rsa), new RsaSecurityKey(rsa.ExportParameters(true)),
            new X509SecurityKey(certificate), JsonWebKeyConverter.ConvertFromRSASecurityKey(new(rsa)) })
        {
            key.KeyId = "host-key"; var original = key.CryptoProviderFactory; var adapter = JweCryptoProviderFactory.DecryptionKey(key);
            Assert.AreEqual(2048, adapter.KeySize); Assert.AreEqual("host-key", adapter.KeyId); Assert.AreSame(original, key.CryptoProviderFactory);
            using var wrap = factory.CreateKeyWrapProvider(key, "RSA-OAEP-256");
            Assert.AreSame(key, wrap.Key); Assert.AreEqual("RSA-OAEP-256", wrap.Algorithm); Assert.AreEqual("", wrap.Context); wrap.Context = "host-context";
            byte[] encrypted = wrap.WrapKey(cek);
            CollectionAssert.AreEqual(cek, rsa.Decrypt(encrypted, RSAEncryptionPadding.OaepSHA256));
            using var unwrap = adapter.CryptoProviderFactory.CreateKeyWrapProviderForUnwrap(adapter, "RSA-OAEP-256");
            CollectionAssert.AreEqual(cek, unwrap.UnwrapKey(encrypted));
            encrypted[3] ^= 1; Assert.Throws<CryptographicException>(() => unwrap.UnwrapKey(encrypted));
            wrap.Dispose(); Assert.Throws<ObjectDisposedException>(() => wrap.WrapKey(cek));
            rsa.SignData(cek, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        using var publicWrap = factory.CreateKeyWrapProvider(new X509SecurityKey(publicCertificate), "RSA-OAEP-256");
        CollectionAssert.AreEqual(cek, rsa.Decrypt(publicWrap.WrapKey(cek), RSAEncryptionPadding.OaepSHA256));
        Assert.Throws<CryptographicException>(() => publicWrap.UnwrapKey(rsa.Encrypt(cek, RSAEncryptionPadding.OaepSHA256)));
        using var defaultWrap = factory.CreateKeyWrapProvider(new RsaSecurityKey(rsa), "RSA-OAEP");
        using var defaultUnwrap = factory.CreateKeyWrapProviderForUnwrap(JweCryptoProviderFactory.DecryptionKey(new RsaSecurityKey(rsa)), "RSA-OAEP");
        CollectionAssert.AreEqual(cek, defaultUnwrap.UnwrapKey(defaultWrap.WrapKey(cek)));
    }

    [TestMethod]
    public void Oaep256RejectsSymmetricNonRsaUndersizedAndMalformedKeys()
    {
        var factory = new JweCryptoProviderFactory(); using var small = RSA.Create(1024); using var ec = ECDsa.Create();
        foreach (SecurityKey key in new SecurityKey[] { new SymmetricSecurityKey(new byte[32]), new ECDsaSecurityKey(ec), new RsaSecurityKey(small), new JsonWebKey { Kty = "EC" } })
        {
            Assert.IsFalse(factory.IsSupportedAlgorithm("RSA-OAEP-256", key));
            Assert.Throws<ArgumentException>(() => factory.CreateKeyWrapProvider(key, "RSA-OAEP-256"));
        }
        Assert.Throws<ArgumentNullException>(() => factory.CreateKeyWrapProvider(null!, "RSA-OAEP-256"));
        using var strong = RSA.Create(2048);
        Assert.IsTrue(factory.IsSupportedAlgorithm("RS256", new RsaSecurityKey(strong)));
        Assert.Throws<NotSupportedException>(() => factory.CreateKeyWrapProviderForUnwrap(new RsaSecurityKey(strong), "RSA1_5"));
        var incompleteJwk = new JsonWebKey { Kty = "RSA", N = Base64UrlEncoder.Encode(strong.ExportParameters(false).Modulus) };
        using var incomplete = factory.CreateKeyWrapProvider(incompleteJwk, "RSA-OAEP-256");
        Assert.Throws<ArgumentException>(() => incomplete.WrapKey(new byte[32]));
        var malformed = new RsaSecurityKey(new RSAParameters { Modulus = new byte[256], Exponent = [0] });
        using var bad = factory.CreateKeyWrapProvider(malformed, "RSA-OAEP-256");
        Assert.Throws<CryptographicException>(() => bad.WrapKey(new byte[32]));
    }
}
