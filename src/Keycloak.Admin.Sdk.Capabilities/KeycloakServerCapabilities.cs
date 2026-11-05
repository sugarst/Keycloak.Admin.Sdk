using System.Collections.Frozen;
using System.Text.Json;

namespace Keycloak.Admin.Sdk.Capabilities;

/// <summary>Immutable snapshot of an authenticated serverinfo response, not a deployment declaration.</summary>
public sealed class KeycloakServerCapabilities
{
    public string ServerVersion { get; }
    public IReadOnlyDictionary<string, bool> Features { get; }
    private KeycloakServerCapabilities(string version, Dictionary<string, bool> features)
    { ServerVersion = version; Features = features.ToFrozenDictionary(StringComparer.Ordinal); }
    public static KeycloakServerCapabilities FromServerInfo(ReadOnlyMemory<byte> json)
    {
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        string version = root.GetProperty("systemInfo").GetProperty("version").GetString()!;
        ArgumentException.ThrowIfNullOrWhiteSpace(version);
        var features = new Dictionary<string, bool>(StringComparer.Ordinal);
        foreach (var feature in root.GetProperty("features").EnumerateArray())
            features.Add(feature.GetProperty("name").GetString()!, feature.GetProperty("enabled").GetBoolean());
        return new(version, features);
    }
}
