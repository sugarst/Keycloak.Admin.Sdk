using System.Net;
using System.Text;
using System.Text.Json;
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Capabilities;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.FeatureManagement;

internal static class FullFeatureManagement
{
    public sealed class Host(ConfigurationRoot configuration, ServiceProvider services) : IDisposable
    {
        public ConfigurationRoot Configuration { get; } = configuration;
        public IVariantFeatureManager Manager { get; } = services.GetRequiredService<IVariantFeatureManager>();
        public void Dispose() { services.Dispose(); Configuration.Dispose(); }
    }
    public static Host CreateHost()
    {
        using var parsed = (ConfigurationRoot)new ConfigurationBuilder().AddJsonFile(Path.Combine(Directory.GetCurrentDirectory(), "contracts/feature-management.example.json")).Build();
        var config = (ConfigurationRoot)new ConfigurationBuilder().AddInMemoryCollection(parsed.AsEnumerable()).Build();
        var services = new ServiceCollection();
        services.AddSingleton<IConfiguration>(config);
        services.AddFeatureManagement();
        return new(config, services.BuildServiceProvider());
    }

    public static async Task VerifyAsync(KeycloakAdminClient sdk, IConfigurationRoot config)
    {
        void Set(string id, bool value)
        {
            var flag = config.GetSection("feature_management:feature_flags").GetChildren().Single(f => f["id"] == id);
            config[flag.Path + ":enabled"] = value ? "true" : "false";
            config.Reload();
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
            try { await sdk.SendAsync(HttpMethod.Get, path); }
            catch (KeycloakAdminException error) when (error.StatusCode == HttpStatusCode.NotFound) { return; }
            throw new InvalidOperationException("Disabled create/deleted realm must be absent on the real server.");
        }

        string realm = "sdk-flags-" + Guid.NewGuid().ToString("N"), path = "/admin/realms/" + realm;
        bool created = false;
        try
        {
            Set("KeycloakSdk.AdminApi", false);
            await Denied(async () => await sdk.SendAsync(HttpMethod.Post, "/admin/realms", content: Body()));
            Set("KeycloakSdk.AdminApi", true);
            await Missing(path);
            await sdk.SendAsync(HttpMethod.Post, "/admin/realms", content: Body()); created = true;
            await Persisted();
            Set("KeycloakSdk.AdminApi", false);
            await Denied(async () => await sdk.SendAsync(HttpMethod.Delete, path));
            await Denied(async () => await sdk.Users.GetUsersAsync(realm));
            await Denied(async () => await sdk.OpenStreamAsync(HttpMethod.Get, path));
            Set("KeycloakSdk.AdminApi", true);
            await Persisted();
            Set("KeycloakSdk.Organizations", false);
            await Denied(async () => await sdk.SendAsync(HttpMethod.Get, path + "/organizations"));
            // Disabling a feature does not turn off unrelated Admin API access.
            await Persisted();
            Set("KeycloakSdk.Organizations", true);
            await sdk.SendAsync(HttpMethod.Get, path + "/organizations");
            await sdk.SendAsync(HttpMethod.Delete, path); created = false;
            await Missing(path);
        }
        finally
        {
            Set("KeycloakSdk.AdminApi", true); Set("KeycloakSdk.Organizations", true);
            if (created) await sdk.SendAsync(HttpMethod.Delete, path);
        }
        Console.WriteLine("PASS live FeatureManagement: disabled create leaves no realm; enabled create persists; disabled delete preserves realm; reload allows delete; feature switch is isolated; raw/generated/stream denials send zero HTTP.");
        StringContent Body() => new("{\"realm\":\"" + realm + "\",\"enabled\":true,\"organizationsEnabled\":true}", Encoding.UTF8, "application/json");
        async Task Persisted()
        {
            var response = await sdk.SendAsync(HttpMethod.Get, path);
            using var document = JsonDocument.Parse(response.Content);
            if (document.RootElement.GetProperty("realm").GetString() != realm) throw new InvalidOperationException("Feature-controlled write was not persisted.");
        }
    }
}
