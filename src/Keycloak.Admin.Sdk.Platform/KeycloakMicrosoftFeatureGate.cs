using Keycloak.Admin.Sdk.Capabilities;
using Microsoft.FeatureManagement;

namespace Keycloak.Admin.Sdk.Platform;

/// <summary>Managed adapter to Microsoft's feature manager. Filters and targeting stay owned by the host.</summary>
public sealed class KeycloakMicrosoftFeatureGate : IKeycloakFeatureGate
{
    private readonly IVariantFeatureManager manager;
    private readonly KeycloakFeatureFlagCatalog catalog;

    public KeycloakMicrosoftFeatureGate(IVariantFeatureManager manager, KeycloakFeatureFlagCatalog catalog)
    {
        this.manager = manager ?? throw new ArgumentNullException(nameof(manager));
        this.catalog = catalog ?? throw new ArgumentNullException(nameof(catalog));
    }

    public async ValueTask<bool> IsEnabledAsync(string featureId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentException.ThrowIfNullOrWhiteSpace(featureId);
        return catalog.IsKnown(featureId) && await manager.IsEnabledAsync(featureId, cancellationToken).ConfigureAwait(false);
    }
}
