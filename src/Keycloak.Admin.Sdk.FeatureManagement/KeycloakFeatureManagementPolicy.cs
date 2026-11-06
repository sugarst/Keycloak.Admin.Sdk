using Keycloak.Admin.Sdk.Capabilities;
using Microsoft.FeatureManagement;

namespace Keycloak.Admin.Sdk.FeatureManagement;

/// <summary>Catalog AND host master flag AND endpoint feature flag. Missing flags fail closed.
/// The SDK evaluates this policy once per logical request, before authentication and transport.
/// Use a manager with the same lifetime as the client; scoped snapshots must not escape their scope.</summary>
public sealed class KeycloakFeatureManagementPolicy(KeycloakCapabilityPolicy capabilities, IVariantFeatureManager features) : IKeycloakAdminRequestPolicy
{
    public const string AdminApiFeature = "KeycloakSdk.AdminApi";
    private readonly KeycloakCapabilityPolicy capabilities = capabilities ?? throw new ArgumentNullException(nameof(capabilities));
    private readonly IVariantFeatureManager features = features ?? throw new ArgumentNullException(nameof(features));

    public async ValueTask<KeycloakCapabilityDecision> EvaluateAsync(HttpMethod method, Uri target, string? operation = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var decision = capabilities.Evaluate(method, target, operation);
        if (!decision.IsAllowed) return decision;
        if (!await features.IsEnabledAsync(AdminApiFeature, cancellationToken).ConfigureAwait(false)) return decision.DisableByHost();
        cancellationToken.ThrowIfCancellationRequested();
        string feature = decision.Capability!.FeatureId;
        if (feature != AdminApiFeature && !await features.IsEnabledAsync(feature, cancellationToken).ConfigureAwait(false)) return decision.DisableByHost();
        cancellationToken.ThrowIfCancellationRequested();
        return decision;
    }

    public async ValueTask EnsureAllowedAsync(HttpMethod method, Uri target, string? operation, CancellationToken cancellationToken)
    {
        var decision = await EvaluateAsync(method, target, operation, cancellationToken).ConfigureAwait(false);
        if (!decision.IsAllowed) throw new KeycloakCapabilityDeniedException(decision);
    }
}
