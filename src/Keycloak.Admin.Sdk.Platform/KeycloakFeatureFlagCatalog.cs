using System.Collections.Frozen;
using System.Text.Json;

namespace Keycloak.Admin.Sdk.Platform;

/// <summary>The complete, generated host switch catalog for the Admin and protocol capability chains.</summary>
public sealed class KeycloakFeatureFlagCatalog
{
    private readonly FrozenSet<string> all;
    private readonly FrozenSet<string> masters;

    public KeycloakFeatureFlagCatalog() : this(Load()) { }

    internal KeycloakFeatureFlagCatalog(JsonElement catalog)
    {
        all = Read(catalog, "all");
        masters = Read(catalog, "masterFlags");
    }

    private static JsonElement Load()
    {
        using var stream = typeof(KeycloakFeatureFlagCatalog).Assembly
            .GetManifestResourceStream("Keycloak.Admin.Sdk.Platform.FeatureFlagCatalog.json")!;
        using var json = JsonDocument.Parse(stream);
        return json.RootElement.Clone();
    }

    private static FrozenSet<string> Read(JsonElement catalog, string property)
        => catalog.GetProperty(property).EnumerateArray().Select(e => e.GetString()!).ToFrozenSet(StringComparer.Ordinal);

    public IReadOnlyCollection<string> All => all;
    public IReadOnlyCollection<string> MasterFlags => masters;
    public bool IsKnown(string id) => all.Contains(id);

    /// <summary>Fail-closed validation: unknown flags and an incomplete switch surface are both rejected.</summary>
    public void EnsureComplete(IEnumerable<KeyValuePair<string, bool>> flags)
    {
        ArgumentNullException.ThrowIfNull(flags);
        var present = flags.Select(f => f.Key).ToHashSet(StringComparer.Ordinal);
        if (present.Any(id => !all.Contains(id))) throw new ArgumentException("Unknown Keycloak SDK feature flag.", nameof(flags));
        if (all.Any(id => !present.Contains(id))) throw new ArgumentException("Incomplete Keycloak SDK feature flag set.", nameof(flags));
    }
}
