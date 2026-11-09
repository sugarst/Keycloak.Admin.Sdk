using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Keycloak.Admin.Sdk.Protocols;

/// <summary>Verified ID-token claims. Access tokens still require independent resource-server authorization.</summary>
public sealed class OidcIdentity
{
    public string Subject { get; }
    public string Issuer { get; }
    public IReadOnlyDictionary<string, object> Claims { get; }
    public JsonElement VerifiedClaims { get; }
    internal OidcIdentity(string subject, string issuer, IDictionary<string, object> claims, JsonElement verifiedClaims)
    { Subject = subject; Issuer = issuer; Claims = new System.Collections.ObjectModel.ReadOnlyDictionary<string, object>(claims); VerifiedClaims = verifiedClaims.Clone(); }
}

/// <summary>Microsoft IdentityModel verifies signatures, exact issuer/audience and lifetime against keys fetched from the pinned realm.
/// Token-provided jku/x5u/jwk are never trusted. A fresh JWKS is fetched for each validation, so rotation requires no global user/token cache.</summary>
public sealed class OidcTokenValidator
{
    private readonly OidcClient oidc;
    private readonly string clientId;
    private readonly string[] algorithms;
    private readonly SecurityKey[] decryptionKeys;
    internal bool Matches(Uri issuer, string audience) => oidc.Issuer == issuer && clientId == audience;
    public OidcTokenValidator(OidcClient oidc, string clientId, IEnumerable<string>? allowedAlgorithms = null, IEnumerable<SecurityKey>? decryptionKeys = null)
    {
        this.oidc = oidc ?? throw new ArgumentNullException(nameof(oidc));
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId); this.clientId = clientId;
        algorithms = (allowedAlgorithms ?? ["RS256"]).Distinct(StringComparer.Ordinal).ToArray();
        string[] asymmetric = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"];
        if (algorithms.Length == 0 || algorithms.Any(a => !asymmetric.Contains(a, StringComparer.Ordinal)))
            throw new ArgumentException("Explicit supported asymmetric signing algorithms are required.", nameof(allowedAlgorithms));
        this.decryptionKeys = (decryptionKeys ?? []).Select(JweCryptoProviderFactory.DecryptionKey).ToArray();
    }

    public Task<OidcIdentity> ValidateIdTokenAsync(string idToken, string expectedNonce, string accessToken, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedNonce); ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);
        return ValidateCoreAsync(idToken, expectedNonce, accessToken, cancellationToken);
    }

    /// <summary>Validates only an ID token received directly from the caller's authenticated standard token exchange.
    /// Exchange responses have no browser nonce. Never use this method to accept a browser callback or an unsolicited token as a login.</summary>
    public Task<OidcIdentity> ValidateExchangedIdTokenAsync(string idToken, CancellationToken cancellationToken = default)
        => ValidateCoreAsync(idToken, null, null, cancellationToken);

    /// <summary>Only for an ID token received directly from the authenticated refresh response. Retain the
    /// original verified login identity: issuer, client and subject cannot change; nonce and auth_time, when
    /// returned, must retain their original values. Reapply any application assurance policy separately.
    /// This method must never accept a browser callback or an unsolicited token as a new login.</summary>
    public async Task<OidcIdentity> ValidateRefreshedIdTokenAsync(string idToken, OidcIdentity originalIdentity, string accessToken, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(originalIdentity); ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);
        var audience = originalIdentity.VerifiedClaims.GetProperty("aud");
        bool matchingAudience = audience.ValueKind == JsonValueKind.String ? audience.GetString() == clientId
            : audience.ValueKind == JsonValueKind.Array && audience.EnumerateArray().Any(a => a.ValueKind == JsonValueKind.String && a.GetString() == clientId);
        bool matchingParty = !originalIdentity.VerifiedClaims.TryGetProperty("azp", out var party) || (party.ValueKind == JsonValueKind.String && party.GetString() == clientId);
        if (originalIdentity.Issuer != oidc.Issuer.AbsoluteUri || !matchingAudience || !matchingParty) throw new ArgumentException("The original verified identity must belong to this issuer and client.", nameof(originalIdentity));
        var refreshed = await ValidateCoreAsync(idToken, null, accessToken, cancellationToken).ConfigureAwait(false);
        if (refreshed.Subject != originalIdentity.Subject) throw new InvalidDataException("A refresh response cannot substitute another subject.");
        foreach (string name in new[] { "nonce", "auth_time" })
            if (refreshed.VerifiedClaims.TryGetProperty(name, out var current)
                && (!originalIdentity.VerifiedClaims.TryGetProperty(name, out var original) || !JsonElement.DeepEquals(current, original)))
                throw new InvalidDataException("A refresh response cannot replace the original authentication context.");
        return refreshed;
    }

    internal Task<OidcIdentity> ValidateBrowserIdTokenAsync(string idToken, string nonce, string? accessToken, string? code, CancellationToken ct)
        => ValidateCoreAsync(idToken, nonce, accessToken, ct, code, true);

    private async Task<OidcIdentity> ValidateCoreAsync(string idToken, string? expectedNonce, string? accessToken, CancellationToken cancellationToken, string? code = null, bool frontChannel = false)
    {
        var (token, claims) = await VerifyAsync(idToken, cancellationToken).ConfigureAwait(false);
        using var document = JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(token.EncodedPayload));
        if (document.RootElement.TryGetProperty("typ", out var tokenKind) && (tokenKind.ValueKind != JsonValueKind.String || tokenKind.GetString() != "ID"))
            throw new InvalidDataException("A Keycloak ID token cannot be replaced by another token type.");
        if (token.Typ != "JWT" || string.IsNullOrWhiteSpace(token.Subject) || (expectedNonce is not null && (!token.TryGetPayloadValue<string>("nonce", out var nonce) || !OidcLoginTransaction.FixedEquals(expectedNonce, nonce)))
            || !token.TryGetPayloadValue<long>("iat", out long issuedAt) || issuedAt > DateTimeOffset.UtcNow.AddSeconds(30).ToUnixTimeSeconds())
            throw new InvalidDataException("Invalid OIDC ID token subject, nonce or issue time.");
        bool hasAzp = token.TryGetPayloadValue<string>("azp", out var azp);
        if ((hasAzp && azp != clientId) || (token.Audiences.Count() > 1 && !hasAzp)) throw new InvalidDataException("Invalid OIDC authorized party.");
        if (token.TryGetPayloadValue<string>("at_hash", out var hash))
        {
            if (accessToken is null) throw new InvalidDataException("An exchange ID token cannot bind an unavailable access token.");
            ValidateHash(token.Alg, hash, accessToken);
        }
        else if (frontChannel && accessToken is not null) throw new InvalidDataException("A front-channel ID token must bind its access token.");
        if (frontChannel && code is not null)
        {
            if (!token.TryGetPayloadValue<string>("c_hash", out var codeHash)) throw new InvalidDataException("A hybrid ID token must bind its authorization code.");
            ValidateHash(token.Alg, codeHash, code);
        }
        return new(token.Subject, token.Issuer, claims, document.RootElement);
    }

    internal async Task<JsonElement> ValidateAuthorizationResponseAsync(string credential, CancellationToken ct)
    {
        var (token, _) = await VerifyAsync(credential, ct).ConfigureAwait(false);
        if (token.Typ is not ("JWT" or "oauth-authz-resp+jwt")) throw new InvalidDataException("Invalid authorization response token type.");
        using var document = JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(token.EncodedPayload));
        var payload = document.RootElement;
        // 26.8.1 writes iss both as a JWT standard claim and an authorization response parameter.
        // Accept only that exact duplicate with both values independently pinned; never permit ambiguous protocol claims.
        if (payload.EnumerateObject().GroupBy(p => p.Name, StringComparer.Ordinal).Any(g => g.Count() != 1
            && (g.Key != "iss" || g.Count() != 2 || g.Any(p => p.Value.ValueKind != JsonValueKind.String || p.Value.GetString() != oidc.Issuer.AbsoluteUri))))
            throw new InvalidDataException("Duplicate signed authorization response claim.");
        return payload.Clone();
    }

    internal static void ValidateHash(string algorithm, string expectedHash, string value)
    {
        byte[] bytes = Encoding.ASCII.GetBytes(value);
        byte[] digest = algorithm.EndsWith("256", StringComparison.Ordinal) ? SHA256.HashData(bytes)
            : algorithm.EndsWith("384", StringComparison.Ordinal) ? SHA384.HashData(bytes) : SHA512.HashData(bytes);
        if (!OidcLoginTransaction.FixedEquals(Base64UrlEncoder.Encode(digest, 0, digest.Length / 2), expectedHash)) throw new InvalidDataException("OIDC bound token or code hash mismatch.");
    }

    private async Task<(JsonWebToken Token, IDictionary<string, object> Claims)> VerifyAsync(string credential, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(credential); cancellationToken.ThrowIfCancellationRequested();
        var keys = await oidc.GetSigningKeysAsync(cancellationToken).ConfigureAwait(false);
        var keySet = new JsonWebKeySet(keys.Json?.GetRawText() ?? throw new InvalidDataException("Empty JWKS."));
        var handler = new JsonWebTokenHandler { MapInboundClaims = false, MaximumTokenSizeInBytes = 65536 };
        var validation = await handler.ValidateTokenAsync(credential, new TokenValidationParameters
        {
            ValidateIssuer = true, ValidIssuer = oidc.Issuer.AbsoluteUri,
            ValidateAudience = true, ValidAudience = clientId, IgnoreTrailingSlashWhenValidatingAudience = false,
            ValidateLifetime = true, RequireExpirationTime = true, RequireSignedTokens = true,
            ValidateIssuerSigningKey = true, IssuerSigningKeys = keySet.GetSigningKeys(), ValidAlgorithms = algorithms,
            TokenDecryptionKeys = decryptionKeys,
            CryptoProviderFactory = new JweCryptoProviderFactory(),
            AlgorithmValidator = (algorithm, _, token, _) => ((JsonWebToken)token).IsEncrypted
                ? ((JsonWebToken)token).Alg is "RSA-OAEP" or "RSA-OAEP-256"
                : algorithms.Contains(algorithm, StringComparer.Ordinal),
            ClockSkew = TimeSpan.FromSeconds(30), IncludeTokenOnFailedValidation = false,
            LogTokenId = false, LogValidationExceptions = false
        }).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        // Do not attach IdentityModel exceptions: some carry token or claim values.
        if (!validation.IsValid || validation.SecurityToken is not JsonWebToken token) throw new InvalidDataException("Invalid OIDC signed or encrypted token.");
        return (token.InnerToken ?? token, validation.Claims);
    }
}
