namespace Keycloak.Admin.Sdk.Protocols;

/// <summary>An explicit Keycloak parameterized scope. Server-side scope assignment, parameter type, consent and policy remain authoritative.</summary>
public sealed class OidcParameterizedScope
{
    public string Value { get; }
    public OidcParameterizedScope(string name, string parameter)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name); ArgumentException.ThrowIfNullOrWhiteSpace(parameter);
        static bool Invalid(char c) => c < 0x21 || c > 0x7e || c is '"' or '\\';
        if (name.Contains(':', StringComparison.Ordinal) || name.Any(Invalid) || parameter.Length > 255 || parameter.Any(Invalid))
            throw new ArgumentException("A scope name without colons and a visible ASCII parameter of at most 255 characters are required.");
        Value = name + ":" + parameter;
    }
}

public sealed partial class OidcClient
{
    public Task<ProtocolResponse> ClientCredentialsWithParameterizedScopesAsync(OAuthClientAuthentication client, IEnumerable<OidcParameterizedScope> scopes,
        string? staticScopes = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scopes); var values = scopes.ToArray();
        if (values.Length == 0 || values.Any(s => s is null)) throw new ArgumentException("At least one parameterized scope is required.", nameof(scopes));
        return FormAsync(client, TokenPath, new() { ["grant_type"] = "client_credentials" }, string.Join(' ', new[] { staticScopes }.Where(s => !string.IsNullOrWhiteSpace(s)).Concat(values.Select(s => s.Value))),
            "Oidc.ClientCredentials", cancellationToken, additionalFeatures: ["KeycloakSdk.Protocols.OidcParameterizedScopes"]);
    }
    internal static string[] AuthorizationFeatures(string scope, OidcAuthorizationOptions? options)
    {
        var features = new List<string> { Feature };
        if (options?.Resources.Count > 0) features.Add("KeycloakSdk.Protocols.OidcResources");
        if (options?.ParameterizedScopes?.Count > 0) features.Add("KeycloakSdk.Protocols.OidcParameterizedScopes");
        if (scope.Split(' ', StringSplitOptions.RemoveEmptyEntries).Any(s => s.StartsWith("delegation:", StringComparison.Ordinal)))
        { features.Add("KeycloakSdk.Protocols.OidcDelegation"); features.Add("KeycloakSdk.Protocols.OidcParameterizedScopes"); }
        if (options?.IdentityProvider is not null) features.Add("KeycloakSdk.Protocols.IdentityBrokerLogin");
        if (options?.Action?.StartsWith("idp_link:", StringComparison.Ordinal) == true) features.Add("KeycloakSdk.Protocols.IdentityLinking");
        if (options?.ResponseMode.Signed() == true) features.Add("KeycloakSdk.Protocols.OidcSignedResponses");
        if (options?.AcrValues is not null || options?.MaximumAuthenticationAgeSeconds is not null || options?.RequiredAssurance is not null) features.Add("KeycloakSdk.Protocols.OidcAssurance");
        if (options?.AuthorizationDetails is not null || options?.IssuerState is not null) features.Add("KeycloakSdk.Protocols.Wallet");
        features.AddRange(AuthenticationCapabilities.Required(options));
        return features.ToArray();
    }
    internal ValueTask EnsureFeaturesAsync(IEnumerable<string> features, CancellationToken ct) => transport.EnsureEnabledAsync(features, ct);
    /// <summary>Checks support and host policy before a framework hands a browser an authorization URL.
    /// The framework must retain its own protected state, nonce and PKCE transaction.</summary>
    public ValueTask EnsureAuthorizationEnabledAsync(OidcAuthorizationOptions options, string scope = "openid", CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options); _ = options.Parameters().ToArray();
        return transport.EnsureEnabledAsync(AuthorizationFeatures(scope, options), cancellationToken);
    }
}
