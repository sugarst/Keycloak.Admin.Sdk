using System.Collections.Frozen;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace Keycloak.Admin.Sdk.Capabilities;

public sealed class KeycloakSupportConfiguration
{
    public string ServerVersion { get; }
    public KeycloakAdminRoute Route { get; }
    public bool AllowPreview { get; }
    public bool AllowExperimental { get; }
    public IReadOnlySet<string> DisabledCapabilities { get; }
    public KeycloakRuntimeProfile RuntimeProfile { get; }
    public string? RuntimeIdentifier { get; }
    public IReadOnlySet<string> PreviewCapabilities { get; }
    public IReadOnlySet<string> ExperimentalCapabilities { get; }
    internal bool UsesSupportProfiles { get; }

    // Preserve the schema-1/old-constructor contract: both runtime verifications are mandatory.
    public KeycloakSupportConfiguration(string serverVersion, KeycloakAdminRoute route = KeycloakAdminRoute.FgapV2Stable,
        bool allowPreview = false, bool allowExperimental = false, IEnumerable<string>? disabledCapabilities = null)
    {
        Validate(serverVersion, route);
        ServerVersion = serverVersion; Route = route; AllowPreview = allowPreview; AllowExperimental = allowExperimental;
        DisabledCapabilities = (disabledCapabilities ?? []).ToFrozenSet(StringComparer.Ordinal); PreviewCapabilities = Set(null); ExperimentalCapabilities = Set(null);
        RuntimeProfile = KeycloakRuntimeProfile.Portable;
    }

    /// <summary>Schema 2: explicit runtime evidence and individual non-stable capability opt-ins.</summary>
    public KeycloakSupportConfiguration(string serverVersion, KeycloakRuntimeProfile runtimeProfile,
        KeycloakAdminRoute route = KeycloakAdminRoute.FgapV2Stable, string? runtimeIdentifier = null,
        IEnumerable<string>? previewCapabilities = null, IEnumerable<string>? experimentalCapabilities = null,
        IEnumerable<string>? disabledCapabilities = null)
    {
        Validate(serverVersion, route);
        if (!Enum.IsDefined(runtimeProfile)) throw new ArgumentOutOfRangeException(nameof(runtimeProfile));
        if (runtimeProfile == KeycloakRuntimeProfile.Managed && runtimeIdentifier is not null)
            throw new ArgumentException("Managed verification does not select a Native AOT RID.", nameof(runtimeIdentifier));
        if (runtimeIdentifier is not null && (string.IsNullOrWhiteSpace(runtimeIdentifier) || runtimeIdentifier.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '-')))
            throw new ArgumentException("Invalid runtime identifier.", nameof(runtimeIdentifier));
        ServerVersion = serverVersion; Route = route; RuntimeProfile = runtimeProfile;
        RuntimeIdentifier = runtimeProfile == KeycloakRuntimeProfile.Managed ? null : runtimeIdentifier ?? RuntimeInformation.RuntimeIdentifier;
        PreviewCapabilities = Set(previewCapabilities); ExperimentalCapabilities = Set(experimentalCapabilities);
        DisabledCapabilities = Set(disabledCapabilities); UsesSupportProfiles = true;
        AllowPreview = PreviewCapabilities.Count != 0; AllowExperimental = ExperimentalCapabilities.Count != 0;
    }

    private static void Validate(string serverVersion, KeycloakAdminRoute route)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(serverVersion);
        if (!Enum.IsDefined(route)) throw new ArgumentOutOfRangeException(nameof(route));
    }
    private static FrozenSet<string> Set(IEnumerable<string>? values)
    {
        var entries = (values ?? []).ToArray();
        if (entries.Any(string.IsNullOrWhiteSpace) || entries.Distinct(StringComparer.Ordinal).Count() != entries.Length)
            throw new ArgumentException("Capability IDs must be nonempty and unique.");
        return entries.ToFrozenSet(StringComparer.Ordinal);
    }
    internal bool AllowsStage(KeycloakEndpointCapability endpoint) => endpoint.Stage switch
    {
        KeycloakFeatureStage.Preview => UsesSupportProfiles ? PreviewCapabilities.Contains(endpoint.FeatureId) : AllowPreview,
        KeycloakFeatureStage.Experimental => UsesSupportProfiles ? ExperimentalCapabilities.Contains(endpoint.FeatureId) : AllowExperimental,
        KeycloakFeatureStage.Removed => false,
        _ => true
    };

    /// <summary>Strict JSON; environment overrides are applied only with an explicit reader.</summary>
    public static KeycloakSupportConfiguration Parse(string json, Func<string, string?>? environment = null)
    {
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("schemaVersion", out var schemaValue))
            throw new JsonException("Missing support configuration schema.");
        int schema = schemaValue.GetInt32();
        string[] known = schema switch
        {
            1 => ["schemaVersion", "serverVersion", "route", "allowPreview", "allowExperimental", "disabledCapabilities"],
            2 => ["schemaVersion", "serverVersion", "route", "runtimeProfile", "runtimeIdentifier", "previewCapabilities", "experimentalCapabilities", "disabledCapabilities"],
            _ => throw new JsonException("Unknown support configuration schema.")
        };
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in root.EnumerateObject())
            if (!known.Contains(property.Name) || !seen.Add(property.Name)) throw new JsonException("Unknown or duplicate support configuration field.");
        if (seen.Count != known.Length) throw new JsonException("Missing support configuration field.");
        string? Env(string name) => environment?.Invoke(name);
        string version = Env("KEYCLOAK_ADMIN_SERVER_VERSION") ?? root.GetProperty("serverVersion").GetString()!;
        KeycloakAdminRoute route = (Env("KEYCLOAK_ADMIN_API_ROUTE") ?? root.GetProperty("route").GetString()) switch
        {
            "fgap-v2-stable" => KeycloakAdminRoute.FgapV2Stable,
            "fgap-v1-compat" => KeycloakAdminRoute.FgapV1Compatibility,
            _ => throw new JsonException("Unknown FGAP route.")
        };
        IEnumerable<string> Ids(string property, string variable) => Env(variable) is { } csv
            ? csv.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            : root.GetProperty(property).EnumerateArray().Select(e => e.GetString()!);
        var disabled = Ids("disabledCapabilities", "KEYCLOAK_ADMIN_DISABLED_CAPABILITIES");
        if (schema == 1)
        {
            bool Flag(string property, string variable) => Env(variable) is { } value ? bool.Parse(value) : root.GetProperty(property).GetBoolean();
            return new(version, route, Flag("allowPreview", "KEYCLOAK_ADMIN_ALLOW_PREVIEW"), Flag("allowExperimental", "KEYCLOAK_ADMIN_ALLOW_EXPERIMENTAL"), disabled);
        }
        KeycloakRuntimeProfile runtime = (Env("KEYCLOAK_ADMIN_RUNTIME_PROFILE") ?? root.GetProperty("runtimeProfile").GetString()) switch
        {
            "Managed" => KeycloakRuntimeProfile.Managed,
            "NativeAot" => KeycloakRuntimeProfile.NativeAot,
            "Portable" => KeycloakRuntimeProfile.Portable,
            _ => throw new JsonException("Unknown runtime profile.")
        };
        return new(version, runtime, route, Env("KEYCLOAK_ADMIN_RUNTIME_IDENTIFIER") ?? root.GetProperty("runtimeIdentifier").GetString(),
            Ids("previewCapabilities", "KEYCLOAK_ADMIN_PREVIEW_CAPABILITIES"), Ids("experimentalCapabilities", "KEYCLOAK_ADMIN_EXPERIMENTAL_CAPABILITIES"), disabled);
    }
}
