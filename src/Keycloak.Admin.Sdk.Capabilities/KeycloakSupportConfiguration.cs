using System.Collections.Frozen;
using System.Text.Json;

namespace Keycloak.Admin.Sdk.Capabilities;

public sealed class KeycloakSupportConfiguration
{
    public string ServerVersion { get; }
    public KeycloakAdminRoute Route { get; }
    public bool AllowPreview { get; }
    public bool AllowExperimental { get; }
    public IReadOnlySet<string> DisabledCapabilities { get; }
    public KeycloakSupportConfiguration(string serverVersion, KeycloakAdminRoute route = KeycloakAdminRoute.FgapV2Stable,
        bool allowPreview = false, bool allowExperimental = false, IEnumerable<string>? disabledCapabilities = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(serverVersion);
        if (!Enum.IsDefined(route)) throw new ArgumentOutOfRangeException(nameof(route));
        ServerVersion = serverVersion; Route = route; AllowPreview = allowPreview; AllowExperimental = allowExperimental;
        DisabledCapabilities = (disabledCapabilities ?? []).ToFrozenSet(StringComparer.Ordinal);
    }

    /// <summary>JSON is explicit; environment overrides are opt-in by supplying e.g. Environment.GetEnvironmentVariable.</summary>
    public static KeycloakSupportConfiguration Parse(string json, Func<string, string?>? environment = null)
    {
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        string[] known = ["schemaVersion", "serverVersion", "route", "allowPreview", "allowExperimental", "disabledCapabilities"];
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in root.EnumerateObject())
            if (!known.Contains(property.Name) || !seen.Add(property.Name)) throw new JsonException("Unknown or duplicate support configuration field.");
        if (root.GetProperty("schemaVersion").GetInt32() != 1) throw new JsonException("Unknown support configuration schema.");
        string? Env(string name) => environment?.Invoke(name);
        bool Flag(string property, string variable) => Env(variable) is { } value ? bool.Parse(value) : root.GetProperty(property).GetBoolean();
        string route = Env("KEYCLOAK_ADMIN_API_ROUTE") ?? root.GetProperty("route").GetString()!;
        KeycloakAdminRoute selected = route switch
        {
            "fgap-v2-stable" => KeycloakAdminRoute.FgapV2Stable,
            "fgap-v1-compat" => KeycloakAdminRoute.FgapV1Compatibility,
            _ => throw new JsonException("Unknown FGAP route.")
        };
        IEnumerable<string> disabled = Env("KEYCLOAK_ADMIN_DISABLED_CAPABILITIES") is { } csv ? csv.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            : root.GetProperty("disabledCapabilities").EnumerateArray().Select(e => e.GetString()!);
        return new(Env("KEYCLOAK_ADMIN_SERVER_VERSION") ?? root.GetProperty("serverVersion").GetString()!, selected,
            Flag("allowPreview", "KEYCLOAK_ADMIN_ALLOW_PREVIEW"), Flag("allowExperimental", "KEYCLOAK_ADMIN_ALLOW_EXPERIMENTAL"), disabled);
    }
}
