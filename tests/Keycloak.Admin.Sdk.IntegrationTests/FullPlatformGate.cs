using System.Net;
using System.Text;
using System.Text.Json;
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Capabilities;
using Keycloak.Admin.Sdk.Platform;

internal static class FullPlatformGate
{
    public static (KeycloakPlatformOptions Options, Dictionary<string, bool> Flags) Create(KeycloakAdminRoute route)
    {
        var catalog = new KeycloakFeatureFlagCatalog();
        var flags = catalog.All.ToDictionary(id => id, _ => true);
        return (new KeycloakPlatformOptions
        {
            Support = new KeycloakSupportConfiguration(KeycloakTarget.Version, route),
            Flags = flags, Catalog = catalog
        }, flags);
    }

    public static async Task VerifyAsync(KeycloakPlatformHost host, Dictionary<string, bool> flags, CancellationToken cancellationToken = default)
    {
        var sdk = host.Admin;
        var gate = (KeycloakFeatureSnapshotGate)host.Gate;
        void Set(string id, bool value)
        {
            flags[id] = value;
            KeycloakPlatformGate.Replace(gate, flags, host.Catalog);
        }
        async Task Denied(Func<Task> action)
        {
            int before = RecordingHandler.SentCount;
            try { await action(); }
            catch (KeycloakCapabilityDeniedException error) when (error.Decision.Reason == KeycloakCapabilityReason.DisabledByHost)
            {
                if (RecordingHandler.SentCount != before) throw new InvalidOperationException("Host flag denial sent HTTP.");
                return;
            }
            throw new InvalidOperationException("Host flag did not deny request.");
        }
        async Task Missing(string path)
        {
            try { await sdk.SendAsync(HttpMethod.Get, path, cancellationToken: cancellationToken); }
            catch (KeycloakAdminException error) when (error.StatusCode == HttpStatusCode.NotFound) { return; }
            throw new InvalidOperationException("Disabled create/deleted realm must be absent on the real server.");
        }

        string realm = "sdk-flags-" + Guid.NewGuid().ToString("N"), path = "/admin/realms/" + realm;
        bool created = false;
        try
        {
            Set("KeycloakSdk.AdminApi", false);
            await Denied(async () => await sdk.SendAsync(HttpMethod.Post, "/admin/realms", content: Body(), cancellationToken: cancellationToken));
            Set("KeycloakSdk.AdminApi", true);
            await Missing(path);
            created = true; // The server may commit creation even if the response is cancelled.
            await sdk.SendAsync(HttpMethod.Post, "/admin/realms", content: Body(), cancellationToken: cancellationToken);
            await Persisted();
            Set("KeycloakSdk.AdminApi", false);
            await Denied(async () => await sdk.SendAsync(HttpMethod.Delete, path, cancellationToken: cancellationToken));
            await Denied(async () => await sdk.Users.GetUsersAsync(realm, cancellationToken: cancellationToken));
            await Denied(async () => await sdk.OpenStreamAsync(HttpMethod.Get, path, cancellationToken: cancellationToken));
            Set("KeycloakSdk.AdminApi", true);
            await Persisted();
            Set("KeycloakSdk.Organizations", false);
            await Denied(async () => await sdk.SendAsync(HttpMethod.Get, path + "/organizations", cancellationToken: cancellationToken));
            // Disabling a feature does not turn off unrelated Admin API access.
            await Persisted();
            Set("KeycloakSdk.Organizations", true);
            await sdk.SendAsync(HttpMethod.Get, path + "/organizations", cancellationToken: cancellationToken);
            await sdk.SendAsync(HttpMethod.Delete, path, cancellationToken: cancellationToken); created = false;
            await Missing(path);
        }
        finally
        {
            Set("KeycloakSdk.AdminApi", true); Set("KeycloakSdk.Organizations", true);
            if (created)
            {
                using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(30));
                try { await sdk.SendAsync(HttpMethod.Delete, path, cancellationToken: cleanup.Token); }
                catch (KeycloakAdminException error) when (error.StatusCode == HttpStatusCode.NotFound) { }
            }
        }
        Console.WriteLine("PASS live platform gate: disabled create leaves no realm; enabled create persists; disabled delete preserves realm; reload allows delete; feature switch is isolated; raw/generated/stream denials send zero HTTP.");
        StringContent Body() => new("{\"realm\":\"" + realm + "\",\"enabled\":true,\"organizationsEnabled\":true}", Encoding.UTF8, "application/json");
        async Task Persisted()
        {
            var response = await sdk.SendAsync(HttpMethod.Get, path, cancellationToken: cancellationToken);
            using var document = JsonDocument.Parse(response.Content);
            if (document.RootElement.GetProperty("realm").GetString() != realm) throw new InvalidOperationException("Feature-controlled write was not persisted.");
        }
    }
}
