using Keycloak.Admin.Sdk.Capabilities;
using Microsoft.FeatureManagement;

namespace Keycloak.Admin.Sdk.FeatureManagement;

/// <summary>Catalog AND host master flag AND endpoint feature flag. Missing flags fail closed.
/// The SDK evaluates this policy once per logical request, before authentication and transport.
/// Use a manager with the same lifetime as the client; scoped snapshots must not escape their scope.</summary>
public sealed class KeycloakFeatureManagementPolicy : IKeycloakAdminRequestPolicy
{
    public const string AdminApiFeature = KeycloakFeatureGatePolicy.AdminApiFeature;
    private readonly KeycloakFeatureGatePolicy policy;
    public KeycloakFeatureManagementPolicy(KeycloakCapabilityPolicy capabilities, IVariantFeatureManager features)
        => policy = new(capabilities, new KeycloakMicrosoftFeatureGate(features));

    public ValueTask<KeycloakCapabilityDecision> EvaluateAsync(HttpMethod method, Uri target, string? operation = null,
        CancellationToken cancellationToken = default)
        => policy.EvaluateAsync(method, target, operation, cancellationToken);

    public ValueTask EnsureAllowedAsync(HttpMethod method, Uri target, string? operation, CancellationToken cancellationToken)
        => policy.EnsureAllowedAsync(method, target, operation, cancellationToken);
}
