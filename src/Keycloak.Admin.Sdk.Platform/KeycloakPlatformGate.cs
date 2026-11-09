using Keycloak.Admin.Sdk.Capabilities;

namespace Keycloak.Admin.Sdk.Platform;

/// <summary>Creates and atomically refreshes the AOT-safe snapshot gate that the protocol chain recognizes.</summary>
public static class KeycloakPlatformGate
{
    public static KeycloakFeatureSnapshotGate Create(IEnumerable<KeyValuePair<string, bool>> flags, KeycloakFeatureFlagCatalog catalog)
    {
        ArgumentNullException.ThrowIfNull(flags);
        ArgumentNullException.ThrowIfNull(catalog);
        return new KeycloakFeatureSnapshotGate(Validate(flags, catalog));
    }

    public static void Replace(KeycloakFeatureSnapshotGate gate, IEnumerable<KeyValuePair<string, bool>> flags, KeycloakFeatureFlagCatalog catalog)
    {
        ArgumentNullException.ThrowIfNull(gate);
        ArgumentNullException.ThrowIfNull(flags);
        ArgumentNullException.ThrowIfNull(catalog);
        gate.Replace(Validate(flags, catalog));
    }

    private static KeyValuePair<string, bool>[] Validate(IEnumerable<KeyValuePair<string, bool>> flags, KeycloakFeatureFlagCatalog catalog)
    {
        var entries = flags.ToArray();
        catalog.EnsureComplete(entries);
        return entries;
    }
}
