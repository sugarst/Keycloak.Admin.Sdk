using System.Text.Json;
using System.Text.RegularExpressions;

// Shared by the deployment script and actual managed/AOT acceptance executable.
internal sealed record KeycloakRoute(string Id, int FgapVersion, bool CompatibilityOnly, string[] Features,
    (string Feature, string Type, string Pattern)[] ExcludedFeatures, string[] LegacyPatterns)
{
    public static KeycloakRoute Load(string root, string? id = null)
    {
        using var config = JsonDocument.Parse(File.ReadAllText(Path.Combine(root, "contracts/admin-api-routes.json")));
        var policy = config.RootElement;
        if (policy.GetProperty("keycloakVersion").GetString() != "26.8.1") throw new InvalidDataException("Only release 26.8.1 route definitions are supported.");
        id ??= Environment.GetEnvironmentVariable("KEYCLOAK_ADMIN_API_ROUTE") ?? policy.GetProperty("defaultRoute").GetString()!;
        if (!policy.GetProperty("routes").TryGetProperty(id, out var route)) throw new InvalidDataException("Unknown KEYCLOAK_ADMIN_API_ROUTE: " + id);
        if (route.GetProperty("allowPreview").GetBoolean() || route.GetProperty("allowExperimental").GetBoolean()) throw new InvalidDataException("Preview/experimental capabilities are outside this support policy.");
        int version = route.GetProperty("fgapVersion").GetInt32();
        if (route.GetProperty("compatibilityOnly").GetBoolean() != (version == 1)) throw new InvalidDataException("FGAP v1 must be explicitly declared compatibility-only; v2 is the stable route.");
        string[] features = route.GetProperty("features").EnumerateArray().Select(f => f.GetString()!).ToArray();
        if (version is not (1 or 2) || !features.SequenceEqual(new[] { "admin-fine-grained-authz:v" + version })) throw new InvalidDataException("Route must declare exactly one FGAP version, with no additional preview feature switches.");
        return new(id, version, route.GetProperty("compatibilityOnly").GetBoolean(), features,
            policy.GetProperty("excludedFeatures").EnumerateArray().Select(f => (f.GetProperty("feature").GetString()!, f.GetProperty("type").GetString()!, f.GetProperty("pathPattern").GetString()!)).ToArray(),
            policy.GetProperty("fgapV1OnlyPathPatterns").EnumerateArray().Select(f => f.GetString()!).ToArray());
    }
    public string? Exclusion(string path)
    {
        foreach (var feature in ExcludedFeatures)
            if (Regex.IsMatch(path, feature.Pattern)) return feature.Feature + " (" + feature.Type + "; excluded by release support policy)";
        if (FgapVersion != 1 && LegacyPatterns.Any(p => Regex.IsMatch(path, p))) return "FGAP v1 compatibility only; select fgap-v1-compat explicitly";
        return null;
    }
    public void ValidateServer(JsonElement info)
    {
        if (info.GetProperty("systemInfo").GetProperty("version").GetString() != "26.8.1") throw new InvalidDataException("Server version differs from declared route release.");
        var profile = info.GetProperty("profileInfo");
        // profileInfo.previewFeatures/experimentalFeatures enumerate the entire catalog.
        // FeatureRepresentation.enabled reports actual runtime enablement.
        foreach (var feature in info.GetProperty("features").EnumerateArray())
        {
            string type = feature.GetProperty("type").GetString()!;
            if (feature.GetProperty("enabled").GetBoolean() && type is "PREVIEW" or "PREVIEW_DISABLED_BY_DEFAULT" or "EXPERIMENTAL")
                throw new InvalidDataException("Declared route has enabled unsupported feature: " + feature.GetProperty("name").GetString());
        }
        var disabled = profile.GetProperty("disabledFeatures").EnumerateArray().Select(f => f.GetString()).ToHashSet();
        string desired = FgapVersion == 1 ? "ADMIN_FINE_GRAINED_AUTHZ" : "ADMIN_FINE_GRAINED_AUTHZ_V2";
        string opposite = FgapVersion == 1 ? "ADMIN_FINE_GRAINED_AUTHZ_V2" : "ADMIN_FINE_GRAINED_AUTHZ";
        bool enabled = info.GetProperty("features").EnumerateArray().Any(f => f.GetProperty("name").GetString() == desired && f.GetProperty("enabled").GetBoolean());
        if (!enabled || disabled.Contains(desired) || !disabled.Contains(opposite)) throw new InvalidDataException("Actual server FGAP version does not match declared route " + Id);
    }
}
