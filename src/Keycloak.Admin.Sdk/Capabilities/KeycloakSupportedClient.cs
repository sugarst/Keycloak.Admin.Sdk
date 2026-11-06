namespace Keycloak.Admin.Sdk.Capabilities;

public static class KeycloakSupportedClient
{
    /// <summary>Explicit bootstrap reads authenticated serverinfo, then installs the policy for all subsequent requests.
    /// No business API is called by bootstrap. Caller retains ownership of HttpClient and token provider.</summary>
    public static async Task<KeycloakAdminClient> CreateAsync(HttpClient http, Uri server, IAccessTokenProvider tokens,
        KeycloakSupportConfiguration configuration, bool enableUnauthorizedRecovery = false, CancellationToken cancellationToken = default)
        => await CreateCoreAsync(http, server, tokens, configuration, null, enableUnauthorizedRecovery, cancellationToken).ConfigureAwait(false);

    /// <summary>Version/runtime support policy plus a host gate, without Microsoft.FeatureManagement dependencies.</summary>
    public static Task<KeycloakAdminClient> CreateAsync(HttpClient http, Uri server, IAccessTokenProvider tokens,
        KeycloakSupportConfiguration configuration, IKeycloakFeatureGate gate, bool enableUnauthorizedRecovery = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(gate);
        return CreateCoreAsync(http, server, tokens, configuration, gate, enableUnauthorizedRecovery, cancellationToken);
    }

    private static async Task<KeycloakAdminClient> CreateCoreAsync(HttpClient http, Uri server, IAccessTokenProvider tokens,
        KeycloakSupportConfiguration configuration, IKeycloakFeatureGate? gate, bool enableUnauthorizedRecovery, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(tokens);
        ArgumentNullException.ThrowIfNull(configuration);
        var bootstrap = new KeycloakAdminClient(http, server, tokens);
        var info = await bootstrap.ServerInfoAdmin.GetInfoAsync(cancellationToken);
        var snapshot = KeycloakServerCapabilities.FromServerInfo(info.Content);
        var capabilities = new KeycloakCapabilityPolicy(server, configuration, snapshot);
        IKeycloakAdminRequestPolicy policy = gate is null ? capabilities : new KeycloakFeatureGatePolicy(capabilities, gate);
        await policy.EnsureAllowedAsync(HttpMethod.Get, new Uri(new Uri(server.AbsoluteUri.TrimEnd('/') + "/"), "admin/serverinfo"), "ServerInfoAdmin.GetInfoAsync", cancellationToken);
        return new(http, server, tokens, new KeycloakAdminClientOptions { RequestPolicy = policy, EnableUnauthorizedRecovery = enableUnauthorizedRecovery });
    }
}
