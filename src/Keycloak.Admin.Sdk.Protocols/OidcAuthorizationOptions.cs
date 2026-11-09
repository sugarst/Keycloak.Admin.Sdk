using System.Globalization;
using System.Text.Json;

namespace Keycloak.Admin.Sdk.Protocols;

/// <summary>Optional authorization inputs. Server-supported authentication, action and assurance policies remain authoritative.</summary>
public sealed class OidcAuthorizationOptions
{
    public string? LoginHint { get; init; }
    public string? IdentityProvider { get; init; }
    public string? Action { get; init; }
    /// <summary>Optional server-hosted login profiles. Each has independent support, stage and host gates.</summary>
    public IReadOnlyList<KeycloakAuthenticationCapability> RequiredAuthenticationCapabilities { get; init; } = [];
    public string? Prompt { get; init; }
    public string? AcrValues { get; init; }
    public string? Locale { get; init; }
    public int? MaximumAuthenticationAgeSeconds { get; init; }
    public OidcAssuranceRequirement? RequiredAssurance { get; init; }
    public JsonElement? Claims { get; init; }
    /// <summary>OID4VCI authorization_details. Keycloak checks the requested configuration, claims and user entitlement.</summary>
    public JsonElement? AuthorizationDetails { get; init; }
    public string? IssuerState { get; init; }
    public OidcAuthorizationResponseMode ResponseMode { get; init; }
    public IReadOnlyList<Uri> Resources { get; init; } = [];
    public IReadOnlyList<OidcParameterizedScope> ParameterizedScopes { get; init; } = [];
    internal IEnumerable<KeyValuePair<string, string>> Parameters()
    {
        string mode = ResponseMode.Wire();
        if (ResponseMode != OidcAuthorizationResponseMode.Query) yield return new("response_mode", mode);
        foreach (var pair in new KeyValuePair<string, string?>[] { new("login_hint", LoginHint), new("kc_idp_hint", IdentityProvider), new("kc_action", Action),
            new("prompt", Prompt), new("acr_values", AcrValues ?? RequiredAssurance?.RequestedAcrValues), new("ui_locales", Locale) })
            if (pair.Value is not null) { ArgumentException.ThrowIfNullOrWhiteSpace(pair.Value); yield return new(pair.Key, pair.Value); }
        int? maximumAge = MaximumAuthenticationAgeSeconds;
        if (RequiredAssurance?.MaximumAgeSeconds is { } requiredAge) maximumAge = maximumAge is { } explicitAge ? Math.Min(explicitAge, requiredAge) : requiredAge;
        if (maximumAge is not null)
        {
            if (maximumAge < 0) throw new ArgumentOutOfRangeException(nameof(MaximumAuthenticationAgeSeconds));
            yield return new("max_age", maximumAge.Value.ToString(CultureInfo.InvariantCulture));
        }
        if (Claims is not null)
        {
            if (Claims.Value.ValueKind != JsonValueKind.Object) throw new ArgumentException("OIDC claims must be an object.", nameof(Claims));
            yield return new("claims", Claims.Value.GetRawText());
        }
        if (AuthorizationDetails is not null)
        {
            var details = AuthorizationDetails.Value;
            if (details.ValueKind != JsonValueKind.Array || details.GetArrayLength() != 1 || details.GetRawText().Length > 32768)
                throw new ArgumentException("Keycloak 26.8.1 requires one bounded credential authorization detail.", nameof(AuthorizationDetails));
            WalletJson.Object(details[0]);
            if (WalletJson.String(details[0], "type") != "openid_credential") throw new ArgumentException("A credential authorization detail is required.", nameof(AuthorizationDetails));
            yield return new("authorization_details", details.GetRawText());
        }
        if (IssuerState is not null) { WalletJson.Text(IssuerState); yield return new("issuer_state", IssuerState); }
        foreach (var resource in ResourceParameters(Resources)) yield return resource;
    }
    internal static IEnumerable<KeyValuePair<string, string>> ResourceParameters(IEnumerable<Uri> resources)
    {
        ArgumentNullException.ThrowIfNull(resources);
        int count = 0;
        foreach (var resource in resources)
        {
            ArgumentNullException.ThrowIfNull(resource);
            // 26.8.1 reads one resource value. Reject repetition rather than silently discard another intended audience constraint.
            if (++count > 1) throw new ArgumentException("Keycloak 26.8.1 accepts one resource indicator per request.", nameof(resources));
            if (!resource.IsAbsoluteUri || resource.Fragment.Length != 0 || resource.UserInfo.Length != 0 || resource.Query.Length != 0) throw new ArgumentException("Resource indicators must be absolute URIs without credentials, query or fragment.", nameof(Resources));
            yield return new("resource", resource.AbsoluteUri);
        }
    }
}
