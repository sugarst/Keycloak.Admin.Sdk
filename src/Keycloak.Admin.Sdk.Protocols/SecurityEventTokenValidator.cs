using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Keycloak.Admin.Sdk.Protocols;

/// <summary>Verified SET claims. Apply only subscribed event semantics and persist the result before acknowledging delivery.
/// An event does not authorize arbitrary changes to accounts outside its issuer and subject namespace.</summary>
public sealed class VerifiedSecurityEventToken
{
    public string Id { get; }
    public JsonElement Claims { get; }
    public JsonElement Events => Claims.GetProperty("events");
    internal VerifiedSecurityEventToken(string id, JsonElement claims) { Id = id; Claims = claims.Clone(); }
}

/// <summary>Validates Keycloak SSF SET signatures, pinned issuer/audience, time bounds, subscribed event types and replay.
/// The host must supply a durable atomic replay store for multi-process receivers.</summary>
public sealed class SecurityEventTokenValidator
{
    private readonly SignedRealmEvents validator;
    private readonly HashSet<string> eventTypes;
    public SecurityEventTokenValidator(OidcClient issuer, string audience, IEnumerable<string> allowedEventTypes, ISecurityTokenReplayStore replayStore,
        TimeSpan? maximumAge = null, TimeProvider? clock = null, IEnumerable<string>? allowedAlgorithms = null)
    {
        ArgumentNullException.ThrowIfNull(allowedEventTypes); eventTypes = new(allowedEventTypes, StringComparer.Ordinal);
        if (eventTypes.Count == 0 || eventTypes.Any(string.IsNullOrWhiteSpace)) throw new ArgumentException("Subscribe to explicit SSF event types.", nameof(allowedEventTypes));
        validator = new(issuer, audience, replayStore, maximumAge, clock, allowedAlgorithms);
    }
    public async Task<VerifiedSecurityEventToken> ValidateAsync(string credential, CancellationToken cancellationToken = default)
    {
        var token = await validator.VerifyAsync(credential, ["secevent+jwt", "application/secevent+jwt"], cancellationToken).ConfigureAwait(false);
        var events = token.GetProperty("events");
        if (events.EnumerateObject().Any(e => !eventTypes.Contains(e.Name) || e.Value.ValueKind != JsonValueKind.Object)) throw new InvalidDataException("Unsubscribed or invalid security event.");
        await validator.ConsumeAsync(token, "ssf", cancellationToken).ConfigureAwait(false);
        return new(token.GetProperty("jti").GetString()!, token);
    }
}

/// <summary>Verifies OIDC back-channel logout tokens. The host must then invalidate only its matching issuer/sub/sid sessions.</summary>
public sealed class OidcLogoutTokenValidator
{
    private const string LogoutEvent = "http://schemas.openid.net/event/backchannel-logout";
    private readonly SignedRealmEvents validator;
    public OidcLogoutTokenValidator(OidcClient issuer, string clientId, ISecurityTokenReplayStore replayStore, TimeSpan? maximumAge = null, TimeProvider? clock = null,
        IEnumerable<string>? allowedAlgorithms = null) => validator = new(issuer, clientId, replayStore, maximumAge, clock, allowedAlgorithms);
    public async Task<VerifiedSecurityEventToken> ValidateAsync(string credential, CancellationToken cancellationToken = default)
    {
        // Keycloak uses JWT; logout+jwt is the explicit OIDC logout token media type.
        var token = await validator.VerifyAsync(credential, ["JWT", "logout+jwt"], cancellationToken).ConfigureAwait(false);
        if (token.TryGetProperty("nonce", out _) || !token.GetProperty("events").TryGetProperty(LogoutEvent, out var logout) || logout.ValueKind != JsonValueKind.Object
            || (!Nonempty(token, "sub") && !Nonempty(token, "sid"))) throw new InvalidDataException("Invalid OIDC logout event.");
        await validator.ConsumeAsync(token, "logout", cancellationToken).ConfigureAwait(false);
        return new(token.GetProperty("jti").GetString()!, token);
    }
    private static bool Nonempty(JsonElement token, string name) => token.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(value.GetString());
}

internal sealed class SignedRealmEvents
{
    private readonly OidcClient issuer;
    private readonly string audience;
    private readonly ISecurityTokenReplayStore replay;
    private readonly TimeSpan maximumAge;
    private readonly TimeProvider clock;
    private readonly string[] algorithms;
    internal SignedRealmEvents(OidcClient issuer, string audience, ISecurityTokenReplayStore replay, TimeSpan? maximumAge, TimeProvider? clock, IEnumerable<string>? algorithms)
    {
        this.issuer = issuer ?? throw new ArgumentNullException(nameof(issuer)); ArgumentException.ThrowIfNullOrWhiteSpace(audience); this.audience = audience;
        this.replay = replay ?? throw new ArgumentNullException(nameof(replay)); this.clock = clock ?? TimeProvider.System; this.maximumAge = maximumAge ?? TimeSpan.FromMinutes(10);
        if (this.maximumAge <= TimeSpan.Zero || this.maximumAge > TimeSpan.FromDays(1)) throw new ArgumentOutOfRangeException(nameof(maximumAge));
        this.algorithms = (algorithms ?? ["RS256"]).ToArray();
        if (this.algorithms.Length == 0 || this.algorithms.Any(a => !JwtAlgorithms.Asymmetric.Contains(a, StringComparer.Ordinal))) throw new ArgumentException("Explicit asymmetric signature algorithms are required.", nameof(algorithms));
    }
    internal async Task<JsonElement> VerifyAsync(string credential, string[] types, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(credential); ct.ThrowIfCancellationRequested();
        var keys = await issuer.GetSigningKeysAsync(ct).ConfigureAwait(false);
        var result = await new JsonWebTokenHandler { MaximumTokenSizeInBytes = 65536, MapInboundClaims = false }.ValidateTokenAsync(credential, new TokenValidationParameters
        {
            ValidateIssuer = true, ValidIssuer = issuer.Issuer.AbsoluteUri, ValidateAudience = true, ValidAudience = audience, IgnoreTrailingSlashWhenValidatingAudience = false,
            RequireSignedTokens = true, ValidateIssuerSigningKey = true, IssuerSigningKeys = new JsonWebKeySet(keys.Json?.GetRawText() ?? throw new InvalidDataException("Empty realm JWKS.")).GetSigningKeys(),
            ValidTypes = types, ValidAlgorithms = algorithms, ValidateLifetime = true, RequireExpirationTime = false, ClockSkew = TimeSpan.FromSeconds(30),
            IncludeTokenOnFailedValidation = false, LogTokenId = false, LogValidationExceptions = false
        }).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested();
        if (!result.IsValid || result.SecurityToken is not JsonWebToken { IsEncrypted: false } token) throw new InvalidDataException("Invalid signed realm event token.");
        using var document = JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(token.EncodedPayload)); var claims = document.RootElement;
        if (!claims.TryGetProperty("iat", out var issued) || issued.ValueKind != JsonValueKind.Number || !issued.TryGetInt64(out long iat) || iat < clock.GetUtcNow().Subtract(maximumAge).ToUnixTimeSeconds() || iat > clock.GetUtcNow().AddSeconds(30).ToUnixTimeSeconds()
            || !claims.TryGetProperty("jti", out var id) || id.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(id.GetString()) || id.GetString()!.Length > 256
            || !claims.TryGetProperty("events", out var events) || events.ValueKind != JsonValueKind.Object || !events.EnumerateObject().Any()
            || claims.EnumerateObject().GroupBy(p => p.Name, StringComparer.Ordinal).Any(g => g.Count() != 1)
            || events.EnumerateObject().GroupBy(p => p.Name, StringComparer.Ordinal).Any(g => g.Count() != 1)) throw new InvalidDataException("Invalid signed realm event claims.");
        return claims.Clone();
    }
    internal async Task ConsumeAsync(JsonElement token, string purpose, CancellationToken ct)
    {
        string key = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(purpose + "\n" + issuer.Issuer.AbsoluteUri + "\n" + audience + "\n" + token.GetProperty("jti").GetString())));
        if (!await replay.TryUseAsync(key, clock.GetUtcNow().Add(maximumAge).AddSeconds(30), ct).ConfigureAwait(false)) throw new InvalidDataException("Replayed realm event token or replay-store capacity exhausted.");
    }
}
