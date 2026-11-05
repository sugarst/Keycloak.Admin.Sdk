using System.Text.Json;

namespace Keycloak.Admin.Sdk.Capabilities;

/// <summary>Immutable release snapshots. Adding a release never changes the meaning of an older snapshot.</summary>
public static class KeycloakCapabilityCatalog
{
    public static IReadOnlyList<KeycloakReleaseCapabilities> Releases { get; } = Array.AsReadOnly(new[] { Load("26.8.1") });
    public static KeycloakReleaseCapabilities? Find(string version) => Releases.SingleOrDefault(r => r.ServerVersion == version);

    private static KeycloakReleaseCapabilities Load(string version)
    {
        using var stream = typeof(KeycloakCapabilityCatalog).Assembly.GetManifestResourceStream("Keycloak.Capabilities." + version + ".json")!;
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
