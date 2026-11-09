using Microsoft.FeatureManagement;

namespace Keycloak.Admin.Sdk.Platform;

public static class KeycloakTelemetryExtensions
{
    /// <summary>Explicit opt-in to the official FeatureEvaluation publisher. The host registers its
    /// TelemetryClient, starts hosted services and enables telemetry on individual feature flags.
    /// This does not register HTTP request/dependency instrumentation.</summary>
    public static IFeatureManagementBuilder AddKeycloakApplicationInsightsTelemetry(this IFeatureManagementBuilder builder, bool enabled = false)
    {
        ArgumentNullException.ThrowIfNull(builder);
        return enabled ? builder.AddApplicationInsightsTelemetry() : builder;
    }
}
