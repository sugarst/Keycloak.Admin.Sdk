#if !KEYCLOAK_PLATFORM
using System.Text.Json;
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Capabilities;

// Native acceptance exercises the core gate only. This test fixture is not the Managed Platform package.
namespace NativeCoreFixture;

internal sealed class KeycloakFeatureFlagCatalog
{
    internal string[] All { get; }
    internal KeycloakFeatureFlagCatalog()
    {
        using var stream = typeof(KeycloakFeatureFlagCatalog).Assembly.GetManifestResourceStream("NativeFixture.FeatureFlagCatalog.json")!;
        using var json = JsonDocument.Parse(stream);
        All = json.RootElement.GetProperty("all").EnumerateArray().Select(e => e.GetString()!).ToArray();
    }
    internal bool IsKnown(string id) => All.Contains(id, StringComparer.Ordinal);
    internal void EnsureComplete(IEnumerable<KeyValuePair<string, bool>> flags)
    {
        var ids = flags.Select(f => f.Key).ToArray();
        if (ids.Distinct(StringComparer.Ordinal).Count() != ids.Length || !All.ToHashSet(StringComparer.Ordinal).SetEquals(ids))
            throw new ArgumentException("Native fixture requires the complete reviewed SDK flag catalog.");
    }
}

internal static class KeycloakPlatformGate
{
    internal static KeycloakFeatureSnapshotGate Create(IEnumerable<KeyValuePair<string, bool>> flags, KeycloakFeatureFlagCatalog catalog)
    { var entries = flags.ToArray(); catalog.EnsureComplete(entries); return new(entries); }
    internal static void Replace(KeycloakFeatureSnapshotGate gate, IEnumerable<KeyValuePair<string, bool>> flags, KeycloakFeatureFlagCatalog catalog)
    { var entries = flags.ToArray(); catalog.EnsureComplete(entries); gate.Replace(entries); }
}

internal sealed class KeycloakPlatformOptions
{
    internal KeycloakSupportConfiguration Support { get; init; } = null!;
    internal IEnumerable<KeyValuePair<string, bool>> Flags { get; init; } = null!;
    internal KeycloakFeatureFlagCatalog Catalog { get; init; } = null!;
}

internal sealed class KeycloakPlatformHost
{
    internal KeycloakAdminClient Admin { get; }
    internal KeycloakFeatureSnapshotGate Gate { get; }
    internal KeycloakFeatureFlagCatalog Catalog { get; }
    private KeycloakPlatformHost(KeycloakAdminClient admin, KeycloakFeatureSnapshotGate gate, KeycloakFeatureFlagCatalog catalog)
    { Admin = admin; Gate = gate; Catalog = catalog; }
    internal static async Task<KeycloakPlatformHost> CreateAsync(HttpClient http, Uri server, IAccessTokenProvider tokens,
        KeycloakPlatformOptions options, CancellationToken ct)
    {
        var gate = KeycloakPlatformGate.Create(options.Flags, options.Catalog);
        var admin = await KeycloakSupportedClient.CreateAsync(http, server, tokens, options.Support, gate, cancellationToken: ct);
        return new(admin, gate, options.Catalog);
    }
}
#endif
