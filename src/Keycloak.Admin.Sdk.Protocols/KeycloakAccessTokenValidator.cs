using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Keycloak.Admin.Sdk.Protocols;

/// <summary>An access token whose signature, pinned issuer, audience, lifetime and token type have been verified.
/// Authorization still belongs to the resource server. ToString never renders its bearer credential.</summary>
public sealed class VerifiedAccessToken
{
    internal string Credential { get; }
    public string Subject { get; }
    public string Issuer { get; }
    public DateTimeOffset ExpiresAt { get; }
    public JsonElement Claims { get; }
    internal VerifiedAccessToken(string credential, string subject, string issuer, DateTimeOffset expiresAt, JsonElement claims)
    { Credential = credential; Subject = subject; Issuer = issuer; ExpiresAt = expiresAt; Claims = claims.Clone(); }
}

/// <summary>Resource-server JWT validation. ID tokens cannot be substituted for access tokens.
/// Only signing keys from the pinned realm are trusted; optional decryption keys are explicitly supplied by the host.</summary>
public sealed class KeycloakAccessTokenValidator
{
    private static readonly string[] KeyEncryptionAlgorithms = ["RSA-OAEP", "RSA-OAEP-256"];
    private readonly OidcClient oidc;
    private readonly string audience;
    private readonly string[] algorithms;
    private readonly SecurityKey[] decryptionKeys;
    internal bool MatchesIssuer(Uri issuer) => oidc.Issuer == issuer;
    public KeycloakAccessTokenValidator(OidcClient oidc, string audience, IEnumerable<string>? allowedAlgorithms = null, IEnumerable<SecurityKey>? decryptionKeys = null)
    {
        this.oidc = oidc ?? throw new ArgumentNullException(nameof(oidc)); ArgumentException.ThrowIfNullOrWhiteSpace(audience); this.audience = audience;
        algorithms = (allowedAlgorithms ?? ["RS256"]).Distinct(StringComparer.Ordinal).ToArray();
        if (algorithms.Length == 0 || algorithms.Any(a => !JwtAlgorithms.Asymmetric.Contains(a, StringComparer.Ordinal))) throw new ArgumentException("Explicit asymmetric access-token algorithms are required.", nameof(allowedAlgorithms));
        this.decryptionKeys = (decryptionKeys ?? []).Select(JweCryptoProviderFactory.DecryptionKey).ToArray();
    }
    public async Task<VerifiedAccessToken> ValidateAsync(string credential, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(credential); cancellationToken.ThrowIfCancellationRequested();
        var keys = await oidc.GetSigningKeysAsync(cancellationToken).ConfigureAwait(false);
        var parameters = new TokenValidationParameters { ValidateIssuer = true, ValidIssuer = oidc.Issuer.AbsoluteUri,
            ValidateAudience = true, ValidAudience = audience, IgnoreTrailingSlashWhenValidatingAudience = false,
            ValidateLifetime = true, RequireExpirationTime = true, RequireSignedTokens = true, ValidateIssuerSigningKey = true,
            IssuerSigningKeys = new JsonWebKeySet(keys.Json?.GetRawText() ?? throw new InvalidDataException("Empty realm JWKS.")).GetSigningKeys(),
            TokenDecryptionKeys = decryptionKeys, ValidAlgorithms = algorithms,
            CryptoProviderFactory = new JweCryptoProviderFactory(),
            // IdentityModel applies AlgorithmValidator to JWE content encryption as well as inner JWS signatures.
            AlgorithmValidator = (algorithm, _, token, _) => ((JsonWebToken)token).IsEncrypted
                ? KeyEncryptionAlgorithms.Contains(((JsonWebToken)token).Alg, StringComparer.Ordinal)
                : algorithms.Contains(algorithm, StringComparer.Ordinal),
            ClockSkew = TimeSpan.FromSeconds(30),
            IncludeTokenOnFailedValidation = false, LogTokenId = false, LogValidationExceptions = false };
        var result = await new JsonWebTokenHandler { MapInboundClaims = false, MaximumTokenSizeInBytes = 65536 }.ValidateTokenAsync(credential, parameters).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (!result.IsValid || result.SecurityToken is not JsonWebToken outer) throw new InvalidDataException("Invalid Keycloak access token.");
        var token = outer.InnerToken ?? outer;
        using var document = JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(token.EncodedPayload));
        var claims = document.RootElement;
        if (string.IsNullOrWhiteSpace(token.Subject) || !claims.TryGetProperty("typ", out var type) || type.ValueKind != JsonValueKind.String || type.GetString() is not ("Bearer" or "DPoP"))
            throw new InvalidDataException("A Keycloak access token is required.");
        return new(credential, token.Subject, token.Issuer, new DateTimeOffset(token.ValidTo, TimeSpan.Zero), claims);
    }
}

internal static class JwtAlgorithms
{
    internal static readonly string[] Asymmetric = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"];
}
