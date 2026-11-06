using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Keycloak.Admin.Sdk.Protocols;

/// <summary>Request encryption and optional response encryption. Keycloak 26.8.1 requires an encrypted request when requesting an encrypted response.
/// The host owns response keys and their lifetime.
/// Authenticated decryption protects the transport content; issued credentials still need issuer and holder verification.</summary>
public sealed class Oid4vcCredentialEncryption
{
    private readonly EncryptingCredentials request;
    private readonly SecurityKey? responseKey;
    private readonly JsonElement? responseJwk;
    private readonly string responseCipher;
    private readonly string? responseAlgorithm;
    internal bool EncryptsResponse => responseKey is not null;
    public Oid4vcCredentialEncryption(EncryptingCredentials requestEncryption, SecurityKey? responseDecryptionKey = null,
        JsonElement? responsePublicJwk = null, string responseContentEncryption = "A256GCM")
    {
        ArgumentNullException.ThrowIfNull(requestEncryption);
        if ((responseDecryptionKey is null) != (responsePublicJwk is null)) throw new ArgumentException("A response private key and its public JWK must be supplied together.");
        ValidateAlgorithms(requestEncryption.Alg, requestEncryption.Enc);
        request = new(requestEncryption.Key, requestEncryption.Alg, requestEncryption.Enc) { CryptoProviderFactory = new JweCryptoProviderFactory() };
        ValidateAlgorithms("RSA-OAEP-256", responseContentEncryption); responseCipher = responseContentEncryption;
        if (responsePublicJwk is not null)
        {
            WalletJson.Object(responsePublicJwk.Value);
            var publicKey = DpopProofKey.ReadPublicJwk(responsePublicJwk.Value);
            if (publicKey.Kty != "RSA" || !System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(publicKey.ComputeJwkThumbprint(), responseDecryptionKey!.ComputeJwkThumbprint()))
                throw new ArgumentException("The public response JWK must match the host's RSA decryption key.", nameof(responsePublicJwk));
            responseAlgorithm = publicKey.Alg;
            if (responseAlgorithm is null) throw new ArgumentException("The response public JWK must explicitly select an issuer-advertised alg.", nameof(responsePublicJwk));
            ValidateAlgorithms(responseAlgorithm, responseCipher);
            var advertised = JsonNode.Parse(responsePublicJwk.Value.GetRawText())!; advertised["alg"] = responseAlgorithm;
            using var document = JsonDocument.Parse(advertised.ToJsonString()); responseJwk = document.RootElement.Clone();
            responseKey = JweCryptoProviderFactory.DecryptionKey(responseDecryptionKey);
        }
    }
    internal string CreateRequest(JsonObject body)
    {
        if (responseJwk is not null) body["credential_response_encryption"] = new JsonObject
            { ["jwk"] = JsonNode.Parse(responseJwk.Value.GetRawText()), ["enc"] = responseCipher };
        string json = body.ToJsonString();
        return WalletJwe.Encrypt(json, request);
    }
    public JsonElement DecryptResponse(ProtocolResponse response)
    {
        ArgumentNullException.ThrowIfNull(response);
        if (responseKey is null || response.BodyMediaType != "application/jwt" || response.RawBody.Length is 0 or > 65536)
            throw new InvalidDataException("An explicitly encrypted credential response and its host key are required.");
        try
        {
            string compact = new UTF8Encoding(false, true).GetString(response.RawBody.Span);
            var token = new JsonWebToken(compact); ValidateAlgorithms(token.Alg, token.Enc);
            if (token.Enc != responseCipher || token.Alg != responseAlgorithm || !string.IsNullOrEmpty(token.Zip)) throw new InvalidDataException("Unexpected credential encryption parameters.");
            string json = WalletJwe.Decrypt(compact, token, responseKey);
            using var document = JsonDocument.Parse(json); WalletJson.Object(document.RootElement); return document.RootElement.Clone();
        }
        catch (Exception error) when (error is ArgumentException or SecurityTokenException or JsonException or InvalidDataException or FormatException or System.Security.Cryptography.CryptographicException)
        { throw new InvalidDataException("Invalid encrypted credential response."); }
    }
    private static void ValidateAlgorithms(string alg, string enc)
    {
        if (alg is not ("RSA-OAEP" or "RSA-OAEP-256") || enc is not ("A128GCM" or "A192GCM" or "A256GCM" or "A128CBC-HS256" or "A192CBC-HS384" or "A256CBC-HS512"))
            throw new ArgumentException("Explicit RSA-OAEP and authenticated content-encryption algorithms are required.");
    }
}
