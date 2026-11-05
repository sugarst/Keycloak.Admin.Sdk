using Keycloak.Admin.Sdk.Capabilities;
using Microsoft.FeatureManagement;

namespace Keycloak.Admin.Sdk.FeatureManagement;

public static class KeycloakFeatureManagedClient
{
    /// <summary>Reads authenticated serverinfo once, then applies catalog and host flags to every SDK transport.
    /// The metadata read is the sole bootstrap exemption. Caller owns HTTP, tokens and feature manager.
    /// Filter/configuration errors propagate and prevent the business request from being sent.</summary>
    public static async Task<KeycloakAdminClient> CreateAsync(HttpClient http, Uri server, IAccessTokenProvider tokens,
        KeycloakSupportConfiguration configuration, IVariantFeatureManager features,
        bool enableUnauthorizedRecovery = false, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(tokens);
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(features);
        var bootstrap = new KeycloakAdminClient(http, server, tokens);
        var info = await bootstrap.ServerInfoAdmin.GetInfoAsync(cancellationToken).ConfigureAwait(false);
        var catalog = new KeycloakCapabilityPolicy(server, configuration, KeycloakServerCapabilities.FromServerInfo(info.Content));
        var policy = new KeycloakFeatureManagementPolicy(catalog, features);
        await policy.EnsureAllowedAsync(HttpMethod.Get, new Uri(new Uri(server.AbsoluteUri.TrimEnd('/') + "/"), "admin/serverinfo"),
            "ServerInfoAdmin.GetInfoAsync", cancellationToken).ConfigureAwait(false);
        return new(http, server, tokens, new KeycloakAdminClientOptions { RequestPolicy = policy, EnableUnauthorizedRecovery = enableUnauthorizedRecovery });
    }
}
