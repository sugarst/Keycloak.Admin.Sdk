namespace Keycloak.Admin.Sdk.Capabilities;

public static class KeycloakSupportedClient
{
    /// <summary>Explicit bootstrap reads authenticated serverinfo, then installs the policy for all subsequent requests.
    /// No business API is called by bootstrap. Caller retains ownership of HttpClient and token provider.</summary>
    public static async Task<KeycloakAdminClient> CreateAsync(HttpClient http, Uri server, IAccessTokenProvider tokens,
        KeycloakSupportConfiguration configuration, bool enableUnauthorizedRecovery = false, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(tokens);
        ArgumentNullException.ThrowIfNull(configuration);
        var bootstrap = new KeycloakAdminClient(http, server, tokens);
        var info = await bootstrap.ServerInfoAdmin.GetInfoAsync(cancellationToken);
        var snapshot = KeycloakServerCapabilities.FromServerInfo(info.Content);
        var policy = new KeycloakCapabilityPolicy(server, configuration, snapshot);
        await policy.EnsureAllowedAsync(HttpMethod.Get, new Uri(new Uri(server.AbsoluteUri.TrimEnd('/') + "/"), "admin/serverinfo"), "ServerInfoAdmin.GetInfoAsync", cancellationToken);
        return new(http, server, tokens, new KeycloakAdminClientOptions { RequestPolicy = policy, EnableUnauthorizedRecovery = enableUnauthorizedRecovery });
    }
}
