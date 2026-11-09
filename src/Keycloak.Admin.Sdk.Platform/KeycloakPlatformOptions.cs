using Keycloak.Admin.Sdk.Capabilities;
using Keycloak.Admin.Sdk.Protocols;
using Microsoft.FeatureManagement;

namespace Keycloak.Admin.Sdk.Platform;

/// <summary>One host-owned switch surface shared by the Admin and application-protocol capability chains.</summary>
public sealed class KeycloakPlatformOptions
{
    public KeycloakSupportConfiguration Support { get; init; } = null!;
    public ApplicationSupportConfiguration? ProtocolSupport { get; init; }
    public IEnumerable<KeyValuePair<string, bool>> Flags { get; init; } = null!;
    public KeycloakFeatureFlagCatalog? Catalog { get; init; }
    public bool EnableUnauthorizedRecovery { get; init; }
    /// <summary>Optional Microsoft feature manager. Choose this or Flags, not both.
    /// Use a host-scoped IVariantFeatureManagerSnapshot when request consistency is required.</summary>
    public IVariantFeatureManager? FeatureManager { get; init; }
}
