using System.Text.Json;

namespace Keycloak.Admin.Sdk.Capabilities;

/// <summary>Exactly one immutable target per SDK build. Historical targets belong to historical packages.</summary>
public static class KeycloakCapabilityCatalog
{
    public static KeycloakReleaseCapabilities Current { get; } = Load();
    public static KeycloakReleaseCapabilities? Find(string version) => Current.ServerVersion == version ? Current : null;

    private static KeycloakReleaseCapabilities Load()
    {
        using var stream = typeof(KeycloakCapabilityCatalog).Assembly.GetManifestResourceStream("Keycloak.Capabilities.Current.json")!;
        using var document = JsonDocument.Parse(stream);
        var root = document.RootElement;
        var endpoints = root.GetProperty("endpoints").EnumerateArray().Select(e => new KeycloakEndpointCapability(
            e.GetProperty("operation").GetString()!, e.GetProperty("method").GetString()!, e.GetProperty("path").GetString()!, e.GetProperty("featureId").GetString()!,
            Enum.Parse<KeycloakFeatureStage>(e.GetProperty("stage").GetString()!),
            Enum.Parse<KeycloakImplementationStatus>(e.GetProperty("implementation").GetString()!),
            Enum.Parse<KeycloakSupportStatus>(e.GetProperty("support").GetString()!),
            Enum.Parse<KeycloakVerification>(e.GetProperty("verification").GetString()!),
            e.GetProperty("requiredServerFeatures").EnumerateArray().Select(f => f.GetString()!).ToArray(), e.GetProperty("evidence").GetString()!,
            e.GetProperty("routes").EnumerateArray().Select(r => Enum.Parse<KeycloakAdminRoute>(r.GetString()!)).ToArray())).ToArray();
        return new(root.GetProperty("serverVersion").GetString()!, root.GetProperty("sourceCommit").GetString()!, endpoints);
    }
}
