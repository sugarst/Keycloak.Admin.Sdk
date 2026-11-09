#if KEYCLOAK_PLATFORM
using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Text.Json;
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Capabilities;
using Keycloak.Admin.Sdk.Platform;
using Keycloak.Admin.Sdk.Protocols;
using Microsoft.ApplicationInsights;
using Microsoft.ApplicationInsights.Channel;
using Microsoft.ApplicationInsights.DataContracts;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.FeatureManagement;
using TelemetryConfiguration = Microsoft.ApplicationInsights.Extensibility.TelemetryConfiguration;

internal static class FullMicrosoftFeatureGate
{
    internal static async Task VerifyAsync(HttpClient http, Uri server, IAccessTokenProvider tokens,
        KeycloakAdminRoute route, CancellationToken ct)
    {
        var ids = new KeycloakFeatureFlagCatalog().All.Order(StringComparer.Ordinal).ToArray();
        var settings = new Dictionary<string, string?>();
        for (int index = 0; index < ids.Length; index++)
        {
            string key = "feature_management:feature_flags:" + index;
            settings[key + ":id"] = ids[index];
            settings[key + ":enabled"] = "true";
            settings[key + ":telemetry:enabled"] = "true";
        }
        using var config = (ConfigurationRoot)new ConfigurationBuilder().AddInMemoryCollection(settings).Build();
        using var channel = new Channel();
        using var telemetry = new TelemetryConfiguration
        {
            ConnectionString = "InstrumentationKey=00000000-0000-0000-0000-000000000001", TelemetryChannel = channel
        };
        var services = new ServiceCollection();
        services.AddSingleton<IConfiguration>(config);
        services.AddSingleton(new TelemetryClient(telemetry));
        services.AddFeatureManagement().AddKeycloakApplicationInsightsTelemetry(enabled: true);
        using var provider = services.BuildServiceProvider();
        var workers = provider.GetServices<IHostedService>().ToArray();
        foreach (var worker in workers) await worker.StartAsync(ct);
        var wire = new KeycloakAdminClient(http, server, tokens);
        string realm = "sdk-microsoft-flags-" + Guid.NewGuid().ToString("N"), path = "/admin/realms/" + realm;
        bool attempted = false;
        void Set(string id, bool value)
        {
            config["feature_management:feature_flags:" + Array.IndexOf(ids, id) + ":enabled"] = value ? "true" : "false";
            config.Reload();
        }
        async Task Denied(Func<Task> action)
        {
            int sent = RecordingHandler.SentCount;
            try { await action(); }
            catch (KeycloakCapabilityDeniedException error) when (error.Decision.Reason == KeycloakCapabilityReason.DisabledByHost)
            {
                if (RecordingHandler.SentCount != sent) throw new InvalidOperationException("Microsoft gate denial sent HTTP.");
                return;
            }
            throw new InvalidOperationException("Microsoft gate did not reject the business operation.");
        }
        try
        {
            var host = await KeycloakPlatformHost.CreateAsync(http, server, tokens, new()
            {
                Support = new(KeycloakTarget.Version, route),
                FeatureManager = provider.GetRequiredService<IVariantFeatureManager>()
            }, ct);
            Set("KeycloakSdk.AdminApi", false);
            await Denied(() => host.Admin.SendAsync(HttpMethod.Post, "/admin/realms", content: Body(), cancellationToken: ct));
            try { await wire.SendAsync(HttpMethod.Get, path, cancellationToken: ct); throw new InvalidOperationException("Disabled Microsoft create persisted a realm."); }
            catch (KeycloakAdminException error) when (error.StatusCode == HttpStatusCode.NotFound) { }
            Set("KeycloakSdk.AdminApi", true);
            attempted = true;
            await host.Admin.SendAsync(HttpMethod.Post, "/admin/realms", content: Body(), cancellationToken: ct);
            await Persisted();
            Set("KeycloakSdk.AdminApi", false);
            await Denied(() => host.Admin.SendAsync(HttpMethod.Delete, path, cancellationToken: ct));
            await Persisted();
            Set("KeycloakSdk.AdminApi", true);
            var transport = new ProtocolTransport(http, server, realm, host.Gate);
            var oidc = new OidcClient(transport);
            await oidc.DiscoverAsync(ct);
            Set("KeycloakSdk.Protocols", false);
            int before = RecordingHandler.SentCount;
            try { await oidc.DiscoverAsync(ct); throw new InvalidOperationException("Microsoft protocol master did not close."); }
            catch (InvalidOperationException error) when (error.Message.StartsWith("Protocol disabled by host:", StringComparison.Ordinal)) { }
            if (RecordingHandler.SentCount != before) throw new InvalidOperationException("Microsoft protocol denial sent HTTP.");
            Set("KeycloakSdk.Protocols", true);
            await oidc.DiscoverAsync(ct);
            await host.Admin.SendAsync(HttpMethod.Delete, path, cancellationToken: ct);
            attempted = false;
            var events = channel.Items.OfType<EventTelemetry>().Where(e => e.Name == "FeatureEvaluation").ToArray();
            if (!events.SelectMany(e => e.Properties.Values).Contains("KeycloakSdk.AdminApi")
                || !events.SelectMany(e => e.Properties.Values).Contains("KeycloakSdk.Protocols.Oidc")
                || events.Any(e => e.Properties.Values.Any(v => v.Contains(realm, StringComparison.Ordinal) || v.Contains(server.Host, StringComparison.Ordinal))))
                throw new InvalidOperationException("Official publisher business-event identity/privacy contract failed.");
            Console.WriteLine("PASS live Microsoft FeatureManagement: disabled create leaves no realm; enabled create persists; disabled delete preserves it; refresh restores delete; protocol shutdown sends no HTTP; official FeatureEvaluation reaches the local channel.");
        }
        finally
        {
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            if (attempted)
            {
                try { await wire.SendAsync(HttpMethod.Delete, path, cancellationToken: cleanup.Token); }
                catch (KeycloakAdminException error) when (error.StatusCode == HttpStatusCode.NotFound) { }
            }
            foreach (var worker in workers.Reverse()) await worker.StopAsync(cleanup.Token);
        }
        StringContent Body() => new("{\"realm\":\"" + realm + "\",\"enabled\":true}", Encoding.UTF8, "application/json");
        async Task Persisted()
        {
            var response = await wire.SendAsync(HttpMethod.Get, path, cancellationToken: ct);
            using var json = JsonDocument.Parse(response.Content);
            if (json.RootElement.GetProperty("realm").GetString() != realm) throw new InvalidOperationException("Microsoft gate did not preserve the real realm.");
        }
    }
    private sealed class Channel : ITelemetryChannel
    {
        internal ConcurrentQueue<ITelemetry> Items { get; } = new();
        public bool? DeveloperMode { get; set; }
        public string EndpointAddress { get; set; } = "https://telemetry.invalid/";
        public void Send(ITelemetry item) => Items.Enqueue(item);
        public void Flush() { }
        public void Dispose() { }
    }
}
#endif

