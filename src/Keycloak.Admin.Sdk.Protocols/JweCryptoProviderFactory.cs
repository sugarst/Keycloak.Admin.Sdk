using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;

namespace Keycloak.Admin.Sdk.Protocols;

// IdentityModel 8.23 delegates key wrapping through this supported extension point. All RSA operations use the platform implementation.
internal sealed class JweCryptoProviderFactory : CryptoProviderFactory
{
    private const string Oaep256 = "RSA-OAEP-256";
    // IdentityModel resolves key wrapping from the key's factory, independently of TokenValidationParameters.
    // Keep host keys immutable and retain their private-key ownership in a per-validator adapter.
    internal static SecurityKey DecryptionKey(SecurityKey key) => new DecryptionKeyAdapter(key);
    private sealed class DecryptionKeyAdapter : SecurityKey
    {
        internal SecurityKey Source { get; }
        public override int KeySize => Source.KeySize;
        internal DecryptionKeyAdapter(SecurityKey source) { Source = source; KeyId = source.KeyId; CryptoProviderFactory = new JweCryptoProviderFactory(); }
    }
    private static SecurityKey Original(SecurityKey key) => key is DecryptionKeyAdapter adapter ? adapter.Source : key;
    public override bool IsSupportedAlgorithm(string algorithm, SecurityKey key)
        => algorithm == Oaep256 ? Supported(Original(key)) : base.IsSupportedAlgorithm(algorithm, Original(key));
    public override KeyWrapProvider CreateKeyWrapProvider(SecurityKey key, string algorithm)
        => algorithm == Oaep256 ? new Oaep256KeyWrap(Original(key)) : base.CreateKeyWrapProvider(Original(key), algorithm);
    public override KeyWrapProvider CreateKeyWrapProviderForUnwrap(SecurityKey key, string algorithm)
        => algorithm switch { Oaep256 => new Oaep256KeyWrap(Original(key)), "RSA-OAEP" => base.CreateKeyWrapProviderForUnwrap(Original(key), algorithm),
            _ => throw new NotSupportedException("Only RSA-OAEP key unwrapping is permitted.") };
    private static bool Supported(SecurityKey key) => key is RsaSecurityKey or X509SecurityKey or JsonWebKey { Kty: "RSA" } && key.KeySize >= 2048;

    private sealed class Oaep256KeyWrap : KeyWrapProvider
    {
        private bool disposed;
        public override string Algorithm => Oaep256;
        public override SecurityKey Key { get; }
        public override string Context { get; set; } = "";
        internal Oaep256KeyWrap(SecurityKey key)
        {
            ArgumentNullException.ThrowIfNull(key);
            if (!Supported(key)) throw new ArgumentException("RSA-OAEP-256 requires an RSA key of at least 2048 bits.", nameof(key));
            Key = key;
        }
        private byte[] Transform(byte[] bytes, bool unwrap)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            var key = Key;
            if (key is JsonWebKey jwk)
            {
                if (!JsonWebKeyConverter.TryConvertToSecurityKey(jwk, out var converted)) throw new ArgumentException("Invalid RSA JWK.", nameof(key));
                key = converted;
            }
            RSA rsa; bool owned;
            if (key is RsaSecurityKey rsaKey)
            {
                if (rsaKey.Rsa is { } borrowed) { rsa = borrowed; owned = false; }
                else
                {
                    rsa = RSA.Create(); owned = true;
                    try { rsa.ImportParameters(rsaKey.Parameters); }
                    catch { rsa.Dispose(); throw; }
                }
            }
            else
            {
                var certificate = ((X509SecurityKey)key).Certificate;
                rsa = (unwrap ? certificate.GetRSAPrivateKey() : certificate.GetRSAPublicKey()) ?? throw new CryptographicException("The required RSA certificate key is unavailable.");
                owned = true;
            }
            try { return unwrap ? rsa.Decrypt(bytes, RSAEncryptionPadding.OaepSHA256) : rsa.Encrypt(bytes, RSAEncryptionPadding.OaepSHA256); }
            finally { if (owned) rsa.Dispose(); }
        }
        public override byte[] WrapKey(byte[] keyBytes) => Transform(keyBytes, false);
        public override byte[] UnwrapKey(byte[] keyBytes) => Transform(keyBytes, true);
        protected override void Dispose(bool disposing) { disposed = true; }
    }
}
