using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Keycloak.Admin.Sdk.Protocols;

/// <summary>A host-owned DPoP signing key. Keep one key with its user's bound tokens, including refresh tokens.
/// The caller owns the signing key lifetime; the SDK never exports or persists private key material.</summary>
public sealed class DpopProofKey
{
    private readonly SigningCredentials signing;
    private readonly JsonElement publicJwk;
    private readonly TimeProvider clock;
    private readonly ConcurrentDictionary<string, string> nonces = new(StringComparer.Ordinal);
    public string Thumbprint { get; }
    public DpopProofKey(SigningCredentials signing, JsonElement publicJwk, TimeProvider? clock = null)
    {
        this.signing = signing ?? throw new ArgumentNullException(nameof(signing));
        if (!JwtAlgorithms.Asymmetric.Contains(signing.Algorithm, StringComparer.Ordinal)) throw new ArgumentException("DPoP requires asymmetric signing credentials.", nameof(signing));
        var jwk = ReadPublicJwk(publicJwk);
        this.publicJwk = publicJwk.Clone(); Thumbprint = Base64UrlEncoder.Encode(jwk.ComputeJwkThumbprint()); this.clock = clock ?? TimeProvider.System;
    }
    public static DpopProofKey FromEcdsa(ECDsa key, TimeProvider? clock = null)
    {
        ArgumentNullException.ThrowIfNull(key); var parameters = key.ExportParameters(false);
        if (parameters.Curve.Oid.Value != ECCurve.NamedCurves.nistP256.Oid.Value) throw new ArgumentException("ES256 requires a P-256 key.", nameof(key));
        var jwk = new JsonObject { ["kty"] = "EC", ["crv"] = "P-256", ["x"] = Base64UrlEncoder.Encode(parameters.Q.X), ["y"] = Base64UrlEncoder.Encode(parameters.Q.Y) };
        using var document = JsonDocument.Parse(jwk.ToJsonString());
        return new(new SigningCredentials(new ECDsaSecurityKey(key), "ES256"), document.RootElement, clock);
    }
    public string CreateProof(HttpMethod method, Uri target, string? accessToken = null)
    {
        ArgumentNullException.ThrowIfNull(method); ValidateTarget(target);
        var claims = new Dictionary<string, object> { ["jti"] = Guid.NewGuid().ToString("N"), ["iat"] = clock.GetUtcNow().ToUnixTimeSeconds(), ["htm"] = method.Method, ["htu"] = target.GetLeftPart(UriPartial.Path) };
        if (accessToken is not null) { ArgumentException.ThrowIfNullOrWhiteSpace(accessToken); claims["ath"] = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(accessToken))); }
        if (nonces.TryGetValue(target.GetLeftPart(UriPartial.Authority), out string? nonce)) claims["nonce"] = nonce;
        return new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(new SecurityTokenDescriptor
        { SigningCredentials = signing, IncludeKeyIdInHeader = false, TokenType = "dpop+jwt", AdditionalHeaderClaims = new Dictionary<string, object> { ["jwk"] = publicJwk }, Claims = claims });
    }
    public void SetNonce(Uri target, string nonce)
    {
        ValidateTarget(target); ArgumentNullException.ThrowIfNull(nonce);
        if (nonce.Length is 0 or > 1024 || nonce.Any(c => c is < '!' or > '~')) throw new ArgumentException("Invalid bounded DPoP nonce.", nameof(nonce));
        nonces[target.GetLeftPart(UriPartial.Authority)] = nonce;
    }
    internal static void ValidateTarget(Uri target)
    {
        ArgumentNullException.ThrowIfNull(target);
        if (!target.IsAbsoluteUri || target.Scheme is not ("https" or "http") || target.UserInfo.Length != 0 || target.Fragment.Length != 0)
            throw new ArgumentException("An absolute HTTP(S) DPoP target without credentials or fragment is required.", nameof(target));
    }
    internal static JsonWebKey ReadPublicJwk(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.Object || value.EnumerateObject().Any(p => p.Name is "d" or "p" or "q" or "dp" or "dq" or "qi" or "oth" or "k"))
            throw new ArgumentException("Only a public asymmetric DPoP JWK is permitted.", nameof(value));
        var key = new JsonWebKey(value.GetRawText());
        if (key.Kty is not ("EC" or "RSA")) throw new ArgumentException("An asymmetric DPoP JWK is required.", nameof(value));
        return key;
    }
}
