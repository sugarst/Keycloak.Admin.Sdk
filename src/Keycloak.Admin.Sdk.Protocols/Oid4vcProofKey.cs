using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Keycloak.Admin.Sdk.Protocols;

/// <summary>A host-owned credential holder key. Proof JWTs are distinct from DPoP, client authentication and presentations.
/// Keep the same protected private key with its bound credentials; never publish private JWK parameters.</summary>
public sealed class Oid4vcProofKey
{
    private readonly SigningCredentials signing;
    private readonly JsonElement publicJwk;
    private readonly TimeProvider clock;
    public string Thumbprint { get; }
    public string Algorithm => signing.Algorithm;
    public JsonElement PublicJwk => publicJwk;
    public Oid4vcProofKey(SigningCredentials signing, JsonElement publicJwk, TimeProvider? clock = null)
    {
        ArgumentNullException.ThrowIfNull(signing);
        WalletJson.Object(publicJwk);
        if (!JwtAlgorithms.Asymmetric.Contains(signing.Algorithm, StringComparer.Ordinal)) throw new ArgumentException("An asymmetric credential proof signature is required.", nameof(signing));
        var key = DpopProofKey.ReadPublicJwk(publicJwk);
        if (!CryptographicOperations.FixedTimeEquals(key.ComputeJwkThumbprint(), signing.Key.ComputeJwkThumbprint())) throw new ArgumentException("Public holder key does not match the signing key.", nameof(publicJwk));
        if (key.Alg is not null && key.Alg != signing.Algorithm) throw new ArgumentException("The public holder JWK algorithm must match its signature.", nameof(publicJwk));
        var advertised = JsonNode.Parse(publicJwk.GetRawText())!; advertised["alg"] = signing.Algorithm;
        using var document = JsonDocument.Parse(advertised.ToJsonString());
        this.signing = signing; this.publicJwk = document.RootElement.Clone(); this.clock = clock ?? TimeProvider.System; Thumbprint = Base64UrlEncoder.Encode(key.ComputeJwkThumbprint());
    }
    public static Oid4vcProofKey FromEcdsa(ECDsa key, TimeProvider? clock = null)
    {
        ArgumentNullException.ThrowIfNull(key); var parameters = key.ExportParameters(false);
        if (parameters.Curve.Oid.Value != ECCurve.NamedCurves.nistP256.Oid.Value) throw new ArgumentException("ES256 requires a P-256 key.", nameof(key));
        var jwk = new JsonObject { ["kty"] = "EC", ["crv"] = "P-256", ["x"] = Base64UrlEncoder.Encode(parameters.Q.X), ["y"] = Base64UrlEncoder.Encode(parameters.Q.Y) };
        using var document = JsonDocument.Parse(jwk.ToJsonString());
        return new(new SigningCredentials(new ECDsaSecurityKey(key), "ES256"), document.RootElement, clock);
    }
    /// <summary>c_nonce comes from this issuer's nonce endpoint. Omit clientId only for a server-supported anonymous flow.</summary>
    public string CreateIssuanceProof(Uri credentialIssuer, string nonce, string? clientId = null, string? keyAttestation = null)
    {
        ValidateIssuer(credentialIssuer); WalletJson.Credential(nonce);
        var claims = new Dictionary<string, object> { ["aud"] = credentialIssuer.AbsoluteUri, ["nonce"] = nonce, ["iat"] = clock.GetUtcNow().ToUnixTimeSeconds() };
        if (clientId is not null) { WalletJson.Text(clientId); claims["iss"] = clientId; }
        var headers = new Dictionary<string, object> { ["jwk"] = publicJwk };
        if (keyAttestation is not null) { WalletJson.Credential(keyAttestation); headers["key_attestation"] = keyAttestation; }
        return Sign("openid4vci-proof+jwt", claims, headers);
    }
    public string CreateClientAttestationProof(Uri authorizationServer, string clientId, string? challenge = null)
    {
        ValidateIssuer(authorizationServer); WalletJson.Text(clientId);
        var claims = new Dictionary<string, object> { ["iss"] = clientId, ["aud"] = authorizationServer.AbsoluteUri,
            ["iat"] = clock.GetUtcNow().ToUnixTimeSeconds(), ["jti"] = Guid.NewGuid().ToString("N") };
        if (challenge is not null) { WalletJson.Text(challenge); claims["challenge"] = challenge; }
        return Sign("oauth-client-attestation-pop+jwt", claims, []);
    }
    internal string CreatePresentationProof(string audience, string nonce, string hash)
        => Sign("kb+jwt", new() { ["aud"] = audience, ["nonce"] = nonce, ["sd_hash"] = hash, ["iat"] = clock.GetUtcNow().ToUnixTimeSeconds() }, []);
    internal string Sign(string type, Dictionary<string, object> claims, Dictionary<string, object> headers)
        => new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(new SecurityTokenDescriptor
            { SigningCredentials = signing, IncludeKeyIdInHeader = false, TokenType = type, Claims = claims, AdditionalHeaderClaims = headers });
    private static void ValidateIssuer(Uri issuer)
    {
        DpopProofKey.ValidateTarget(issuer);
        if (issuer.Query.Length != 0 || issuer.AbsoluteUri.EndsWith('/')) throw new ArgumentException("An exact issuer identifier without query or trailing slash is required.", nameof(issuer));
    }
}
