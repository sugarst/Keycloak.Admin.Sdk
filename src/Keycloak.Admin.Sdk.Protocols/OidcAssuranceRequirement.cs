using System.Collections.Frozen;
using System.Text.Json;

namespace Keycloak.Admin.Sdk.Protocols;

/// <summary>Mandatory application assurance, independently of preferred acr_values. Apply only after token signature, issuer, audience and browser correlation verification.
/// Maximum authentication age refers to signed auth_time, not token iat. The fixed clock allowance is thirty seconds.</summary>
public sealed class OidcAssuranceRequirement
{
    public IReadOnlySet<string> AcceptableAcrValues { get; }
    public IReadOnlySet<string> RequiredMethods { get; }
    public TimeSpan? MaximumAuthenticationAge { get; }
    private readonly TimeProvider clock;
    public string? RequestedAcrValues => AcceptableAcrValues.Count == 0 ? null : string.Join(' ', AcceptableAcrValues.Order(StringComparer.Ordinal));
    public int? MaximumAgeSeconds => MaximumAuthenticationAge is { } age ? (int)Math.Ceiling(age.TotalSeconds) : null;
    public OidcAssuranceRequirement(IEnumerable<string>? acceptableAcrValues = null, TimeSpan? maximumAuthenticationAge = null,
        IEnumerable<string>? requiredMethods = null, TimeProvider? clock = null)
    {
        static FrozenSet<string> Values(IEnumerable<string>? values)
        {
            var array = (values ?? []).ToArray();
            if (array.Length > 32 || array.Any(v => string.IsNullOrWhiteSpace(v) || v.Length > 256 || v.Any(c => char.IsWhiteSpace(c) || char.IsControl(c))) || array.Distinct(StringComparer.Ordinal).Count() != array.Length)
                throw new ArgumentException("Assurance values must be unique bounded nonempty identifiers without whitespace.");
            return array.ToFrozenSet(StringComparer.Ordinal);
        }
        AcceptableAcrValues = Values(acceptableAcrValues); RequiredMethods = Values(requiredMethods);
        if (maximumAuthenticationAge < TimeSpan.Zero || maximumAuthenticationAge?.TotalSeconds > int.MaxValue) throw new ArgumentOutOfRangeException(nameof(maximumAuthenticationAge));
        if (AcceptableAcrValues.Count == 0 && RequiredMethods.Count == 0 && maximumAuthenticationAge is null) throw new ArgumentException("At least one mandatory assurance constraint is required.");
        MaximumAuthenticationAge = maximumAuthenticationAge; this.clock = clock ?? TimeProvider.System;
    }
    public void Validate(OidcIdentity identity)
    { ArgumentNullException.ThrowIfNull(identity); Validate(identity.VerifiedClaims); }

    /// <summary>Checks assurance claims from a token already verified by a trusted authentication handler. Does not perform signature or identity validation.</summary>
    public void ValidateVerifiedClaims(JsonElement verifiedClaims) => Validate(verifiedClaims);

    private void Validate(JsonElement claims)
    {
        if (claims.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Verified assurance claims must be an object.");
        if (claims.EnumerateObject().Where(p => p.Name is "acr" or "auth_time" or "amr").GroupBy(p => p.Name, StringComparer.Ordinal).Any(g => g.Count() != 1))
            throw new InvalidDataException("Ambiguous authentication assurance claim.");
        if (AcceptableAcrValues.Count != 0 && (!claims.TryGetProperty("acr", out var acr) || acr.ValueKind != JsonValueKind.String || !AcceptableAcrValues.Contains(acr.GetString()!)))
            throw new InvalidDataException("Required authentication context was not attained.");
        if (MaximumAuthenticationAge is { } age)
        {
            long now = clock.GetUtcNow().ToUnixTimeSeconds();
            if (!claims.TryGetProperty("auth_time", out var time) || time.ValueKind != JsonValueKind.Number || !time.TryGetInt64(out long seconds) || seconds < 0 || seconds > now + 30 || now - seconds > age.TotalSeconds + 30)
                throw new InvalidDataException("Required authentication freshness was not attained.");
        }
        if (RequiredMethods.Count != 0)
        {
            if (!claims.TryGetProperty("amr", out var methods) || methods.ValueKind != JsonValueKind.Array || methods.EnumerateArray().Any(m => m.ValueKind != JsonValueKind.String)
                || !RequiredMethods.IsSubsetOf(methods.EnumerateArray().Select(m => m.GetString()!))) throw new InvalidDataException("Required authentication methods were not attained.");
        }
    }
}
