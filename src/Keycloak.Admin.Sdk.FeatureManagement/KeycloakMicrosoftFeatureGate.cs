using Keycloak.Admin.Sdk.Capabilities;
using Microsoft.FeatureManagement;

namespace Keycloak.Admin.Sdk.FeatureManagement;

/// <summary>Managed host adapter. Manager lifetime and targeting context remain owned by the host.</summary>
public sealed class KeycloakMicrosoftFeatureGate : IKeycloakFeatureGate
{
    private readonly IVariantFeatureManager features;
    public KeycloakMicrosoftFeatureGate(IVariantFeatureManager features) => this.features = features ?? throw new ArgumentNullException(nameof(features));
    public ValueTask<bool> IsEnabledAsync(string featureId, CancellationToken cancellationToken = default)
        => features.IsEnabledAsync(featureId, cancellationToken);
}
