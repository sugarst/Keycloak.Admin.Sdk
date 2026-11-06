using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Keycloak.Admin.Sdk.Protocols;

public enum DpopFailure { InvalidProof, TokenBinding, RequestMismatch, NonceRequired, Replay }
public sealed class DpopValidationException(DpopFailure reason) : Exception("DPoP request validation failed: " + reason)
{ public DpopFailure Reason { get; } = reason; }

/// <summary>Implement with an atomic shared insert when resources run on multiple hosts. Return false for replay or exhausted capacity.</summary>
public interface ISecurityTokenReplayStore
{
    ValueTask<bool> TryUseAsync(string key, DateTimeOffset expiresAt, CancellationToken cancellationToken = default);
}

public interface IDpopReplayStore : ISecurityTokenReplayStore { }

/// <summary>Bounded, atomic replay storage for a single process. Multi-node hosts must supply a shared atomic store.</summary>
public sealed class InMemoryDpopReplayStore(int capacity = 10000, TimeProvider? clock = null) : IDpopReplayStore
{
    private readonly int capacity = capacity > 0 ? capacity : throw new ArgumentOutOfRangeException(nameof(capacity));
    private readonly TimeProvider clock = clock ?? TimeProvider.System;
    private readonly Dictionary<string, DateTimeOffset> entries = new(StringComparer.Ordinal);
    private int operations;
    public ValueTask<bool> TryUseAsync(string key, DateTimeOffset expiresAt, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key); cancellationToken.ThrowIfCancellationRequested();
        lock (entries)
        {
            cancellationToken.ThrowIfCancellationRequested(); var now = clock.GetUtcNow();
            if (expiresAt <= now) return ValueTask.FromResult(false);
            if (++operations % 64 == 0 || entries.Count >= capacity)
                foreach (string expired in entries.Where(p => p.Value <= now).Select(p => p.Key).ToArray()) entries.Remove(expired);
            if (entries.TryGetValue(key, out var expiry) && expiry > now) return ValueTask.FromResult(false);
            if (entries.Count >= capacity) return ValueTask.FromResult(false);
            entries[key] = expiresAt; return ValueTask.FromResult(true);
        }
    }
}

/// <summary>Resource-server DPoP verification after independently verifying the access token.
/// Uses the actual externally visible request URL; trusted proxy configuration belongs to the host.</summary>
public sealed class DpopRequestValidator(IDpopReplayStore replayStore, TimeProvider? clock = null)
{
    private readonly IDpopReplayStore replay = replayStore ?? throw new ArgumentNullException(nameof(replayStore));
    private readonly TimeProvider clock = clock ?? TimeProvider.System;
    public async Task ValidateAsync(string proof, HttpMethod method, Uri target, VerifiedAccessToken accessToken, string? expectedNonce = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(proof); ArgumentNullException.ThrowIfNull(method); DpopProofKey.ValidateTarget(target);
        ArgumentNullException.ThrowIfNull(accessToken); cancellationToken.ThrowIfCancellationRequested();
        try
        {
            var handler = new JsonWebTokenHandler { MaximumTokenSizeInBytes = 65536, MapInboundClaims = false };
            var jwt = handler.ReadJsonWebToken(proof);
            if (jwt.IsEncrypted || jwt.Typ != "dpop+jwt" || jwt.TryGetHeaderValue<JsonElement>("crit", out _)
                || !jwt.TryGetHeaderValue<JsonElement>("jwk", out var jwkJson)) throw new DpopValidationException(DpopFailure.InvalidProof);
            var jwk = DpopProofKey.ReadPublicJwk(jwkJson);
            bool algorithmMatches = jwk.Kty == "RSA" ? (jwt.Alg is "RS256" or "RS384" or "RS512" or "PS256" or "PS384" or "PS512") && jwk.KeySize >= 2048
                : (jwt.Alg, jwk.Crv) is ("ES256", "P-256") or ("ES384", "P-384") or ("ES512", "P-521");
            if (!algorithmMatches) throw new DpopValidationException(DpopFailure.InvalidProof);
            string thumbprint = Base64UrlEncoder.Encode(jwk.ComputeJwkThumbprint());
            var tokenClaims = accessToken.Claims;
            if (accessToken.ExpiresAt <= clock.GetUtcNow() || !tokenClaims.TryGetProperty("cnf", out var confirmation) || confirmation.ValueKind != JsonValueKind.Object
                || !confirmation.TryGetProperty("jkt", out var jkt) || jkt.ValueKind != JsonValueKind.String || !OidcLoginTransaction.FixedEquals(thumbprint, jkt.GetString()!))
                throw new DpopValidationException(DpopFailure.TokenBinding);
            var validation = await handler.ValidateTokenAsync(proof, new TokenValidationParameters
            {
                ValidateAudience = false, ValidateIssuer = false, ValidateLifetime = false, RequireExpirationTime = false,
                RequireSignedTokens = true, ValidateIssuerSigningKey = true, IssuerSigningKey = jwk, ValidAlgorithms = JwtAlgorithms.Asymmetric,
                ValidTypes = ["dpop+jwt"], IncludeTokenOnFailedValidation = false, LogTokenId = false, LogValidationExceptions = false
            }).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (!validation.IsValid) throw new DpopValidationException(DpopFailure.InvalidProof);
            using var document = JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(jwt.EncodedPayload)); var claims = document.RootElement;
            if (!claims.TryGetProperty("iat", out var issued) || !issued.TryGetInt64(out long iat) || iat < clock.GetUtcNow().AddMinutes(-5).ToUnixTimeSeconds() || iat > clock.GetUtcNow().AddSeconds(30).ToUnixTimeSeconds()
                || !claims.TryGetProperty("jti", out var id) || id.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(id.GetString()) || id.GetString()!.Length > 200)
                throw new DpopValidationException(DpopFailure.InvalidProof);
            if (!claims.TryGetProperty("htm", out var htm) || htm.ValueKind != JsonValueKind.String || htm.GetString() != method.Method
                || !claims.TryGetProperty("htu", out var htu) || htu.ValueKind != JsonValueKind.String || htu.GetString() != target.GetLeftPart(UriPartial.Path)
                || !claims.TryGetProperty("ath", out var ath) || ath.ValueKind != JsonValueKind.String
                || !OidcLoginTransaction.FixedEquals(ath.GetString()!, Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(accessToken.Credential)))))
                throw new DpopValidationException(DpopFailure.RequestMismatch);
            if (expectedNonce is not null && (!claims.TryGetProperty("nonce", out var nonce) || nonce.ValueKind != JsonValueKind.String || !OidcLoginTransaction.FixedEquals(expectedNonce, nonce.GetString()!)))
                throw new DpopValidationException(DpopFailure.NonceRequired);
            string replayKey = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(thumbprint + ":" + id.GetString())));
            if (!await replay.TryUseAsync(replayKey, clock.GetUtcNow().AddMinutes(6), cancellationToken).ConfigureAwait(false)) throw new DpopValidationException(DpopFailure.Replay);
        }
        catch (Exception error) when (error is ArgumentException or JsonException or SecurityTokenException or InvalidOperationException or OverflowException)
        { throw new DpopValidationException(DpopFailure.InvalidProof); }
    }
}

public static class MutualTlsTokenBinding
{
    /// <summary>Use the peer certificate authenticated by the host's TLS connection, never a client-controlled HTTP header.</summary>
    public static bool Matches(VerifiedAccessToken token, X509Certificate2 authenticatedPeerCertificate)
    {
        ArgumentNullException.ThrowIfNull(token); ArgumentNullException.ThrowIfNull(authenticatedPeerCertificate);
        return token.ExpiresAt > DateTimeOffset.UtcNow && token.Claims.TryGetProperty("cnf", out var confirmation) && confirmation.ValueKind == JsonValueKind.Object
            && confirmation.TryGetProperty("x5t#S256", out var thumbprint) && thumbprint.ValueKind == JsonValueKind.String
            && OidcLoginTransaction.FixedEquals(Base64UrlEncoder.Encode(authenticatedPeerCertificate.GetCertHash(HashAlgorithmName.SHA256)), thumbprint.GetString()!);
    }
}
