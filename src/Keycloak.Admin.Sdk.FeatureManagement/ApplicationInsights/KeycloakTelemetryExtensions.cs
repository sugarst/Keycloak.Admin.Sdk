using Microsoft.FeatureManagement;

namespace Keycloak.Admin.Sdk.FeatureManagement.ApplicationInsights;

public static class KeycloakTelemetryExtensions
{
    /// <summary>Explicit opt-in to Microsoft's FeatureEvaluation publisher. The host must register a
    /// TelemetryClient and start its IHostedServices. Each feature must also enable telemetry in configuration.
    /// This registers no HTTP dependency/request instrumentation and supplies no user/realm/token context.</summary>
    public static IFeatureManagementBuilder AddKeycloakApplicationInsightsTelemetry(this IFeatureManagementBuilder builder, bool enabled = false)
    {
        ArgumentNullException.ThrowIfNull(builder);
        return enabled ? builder.AddApplicationInsightsTelemetry() : builder;
    }
}
