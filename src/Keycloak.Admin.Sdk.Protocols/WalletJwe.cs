using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Keycloak.Admin.Sdk.Protocols;

// IdentityModel 8.23 supports CBC-HMAC key wrapping but rejects GCM key wrapping.
// RFC 7516 compact framing below uses platform AES-GCM and the same reviewed RSA-OAEP key-wrap provider;
// it never implements a cipher or accepts an unauthenticated plaintext.
internal static class WalletJwe
{
    internal static string Encrypt(string plaintext, EncryptingCredentials credentials)
    {
        if (!credentials.Enc.EndsWith("GCM", StringComparison.Ordinal)) return new JsonWebTokenHandler().EncryptToken(plaintext, credentials);
        int size = KeySize(credentials.Enc); byte[] cek = RandomNumberGenerator.GetBytes(size), iv = RandomNumberGenerator.GetBytes(12);
        var header = new JsonObject { ["alg"] = credentials.Alg, ["enc"] = credentials.Enc };
        if (!string.IsNullOrEmpty(credentials.Key.KeyId)) header["kid"] = credentials.Key.KeyId;
        string encoded = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(header.ToJsonString()));
        try
        {
            using var wrap = new JweCryptoProviderFactory().CreateKeyWrapProvider(credentials.Key, credentials.Alg);
            byte[] encryptedKey = wrap.WrapKey(cek), data = Encoding.UTF8.GetBytes(plaintext), ciphertext = new byte[data.Length], tag = new byte[16];
            using var aes = new AesGcm(cek, 16); aes.Encrypt(iv, data, ciphertext, tag, Encoding.ASCII.GetBytes(encoded));
            return string.Join('.', encoded, Base64UrlEncoder.Encode(encryptedKey), Base64UrlEncoder.Encode(iv), Base64UrlEncoder.Encode(ciphertext), Base64UrlEncoder.Encode(tag));
        }
        finally { CryptographicOperations.ZeroMemory(cek); }
    }
    internal static string Decrypt(string compact, JsonWebToken token, SecurityKey key)
    {
        if (!token.Enc.EndsWith("GCM", StringComparison.Ordinal)) return new JsonWebTokenHandler { MaximumTokenSizeInBytes = 65536 }.DecryptToken(token,
            new TokenValidationParameters { TokenDecryptionKey = key, CryptoProviderFactory = new JweCryptoProviderFactory(), IncludeTokenOnFailedValidation = false, LogTokenId = false, LogValidationExceptions = false });
        string[] parts = compact.Split('.');
        if (parts.Length != 5 || parts.Any(p => p.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('-' or '_')))) throw new InvalidDataException("Invalid compact encryption framing.");
        using var header = JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(parts[0])); WalletJson.Object(header.RootElement);
        if (header.RootElement.TryGetProperty("crit", out _)) throw new InvalidDataException("Unsupported critical encryption header.");
        byte[] iv = Base64UrlEncoder.DecodeBytes(parts[2]), ciphertext = Base64UrlEncoder.DecodeBytes(parts[3]), tag = Base64UrlEncoder.DecodeBytes(parts[4]);
        if (iv.Length != 12 || tag.Length != 16) throw new InvalidDataException("Invalid GCM nonce or authentication tag.");
        using var wrap = new JweCryptoProviderFactory().CreateKeyWrapProviderForUnwrap(key, token.Alg);
        byte[] cek = wrap.UnwrapKey(Base64UrlEncoder.DecodeBytes(parts[1]));
        try
        {
            if (cek.Length != KeySize(token.Enc)) throw new InvalidDataException("Unexpected content-encryption key size.");
            var plaintext = new byte[ciphertext.Length]; using var aes = new AesGcm(cek, 16);
            aes.Decrypt(iv, ciphertext, tag, plaintext, Encoding.ASCII.GetBytes(parts[0]));
            return new UTF8Encoding(false, true).GetString(plaintext);
        }
        finally { CryptographicOperations.ZeroMemory(cek); }
    }
    private static int KeySize(string algorithm) => algorithm switch { "A128GCM" => 16, "A192GCM" => 24, "A256GCM" => 32, _ => throw new InvalidDataException("Unsupported GCM content-encryption algorithm.") };
}
