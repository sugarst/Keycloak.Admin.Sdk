using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.IdentityModel.Tokens;

namespace Keycloak.Admin.Sdk.Protocols;

internal static class WalletEcdhJwe
{
    internal static string Encrypt(string plaintext, JsonElement recipient)
    {
        WalletJson.Object(recipient); var key = DpopProofKey.ReadPublicJwk(recipient);
        if (key.Kty != "EC" || key.Crv != "P-256" || key.Alg != "ECDH-ES" || string.IsNullOrEmpty(key.Kid)) throw new InvalidDataException("An ephemeral P-256 ECDH-ES verifier key is required.");
        using var ephemeral = ECDsa.Create(ECCurve.NamedCurves.nistP256); var publicKey = ephemeral.ExportParameters(false);
        var exchange = new EcdhKeyExchangeProvider(new ECDsaSecurityKey(ephemeral), key, "ECDH-ES", "A256GCM");
        byte[] cek = ((SymmetricSecurityKey)exchange.GenerateKdf("", "")).Key;
        try
        {
            var header = new JsonObject { ["alg"] = "ECDH-ES", ["enc"] = "A256GCM", ["kid"] = key.Kid, ["epk"] = new JsonObject
                { ["kty"] = "EC", ["crv"] = "P-256", ["x"] = Base64UrlEncoder.Encode(publicKey.Q.X), ["y"] = Base64UrlEncoder.Encode(publicKey.Q.Y) } };
            string encoded = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(header.ToJsonString()));
            byte[] iv = RandomNumberGenerator.GetBytes(12), data = Encoding.UTF8.GetBytes(plaintext), ciphertext = new byte[data.Length], tag = new byte[16];
            using var aes = new AesGcm(cek, 16); aes.Encrypt(iv, data, ciphertext, tag, Encoding.ASCII.GetBytes(encoded));
            return string.Join('.', encoded, "", Base64UrlEncoder.Encode(iv), Base64UrlEncoder.Encode(ciphertext), Base64UrlEncoder.Encode(tag));
        }
        finally { CryptographicOperations.ZeroMemory(cek); }
    }
}
