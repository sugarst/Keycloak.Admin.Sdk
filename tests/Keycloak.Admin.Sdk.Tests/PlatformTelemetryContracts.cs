using System.Collections.Concurrent;
using System.Net;
using System.Text;
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Capabilities;
using Keycloak.Admin.Sdk.Platform;
using Keycloak.Admin.Sdk.Protocols;
using Microsoft.ApplicationInsights;
using Microsoft.ApplicationInsights.Channel;
using Microsoft.ApplicationInsights.DataContracts;
using Microsoft.ApplicationInsights.Extensibility;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.FeatureManagement;
using Microsoft.FeatureManagement.FeatureFilters;
using TelemetryConfiguration = Microsoft.ApplicationInsights.Extensibility.TelemetryConfiguration;

public static class PlatformTelemetryContracts
{
    private static void Check(bool value) { if (!value) throw new InvalidOperationException("Microsoft feature management contract failed."); }
    private static async Task Throws<T>(Func<Task> action) where T : Exception
    { try { await action(); } catch (T) { return; } throw new InvalidOperationException("Expected " + typeof(T).Name); }

    public static async Task RunAsync()
    {
        await Throws<ArgumentNullException>(() => Task.FromResult(KeycloakTelemetryExtensions.AddKeycloakApplicationInsightsTelemetry(null!)));
        var offServices = new ServiceCollection();
        offServices.AddSingleton<IConfiguration>(new ConfigurationBuilder().Build());
        offServices.AddFeatureManagement().AddKeycloakApplicationInsightsTelemetry();
        using (var off = offServices.BuildServiceProvider(new ServiceProviderOptions { ValidateOnBuild = true }))
            Check(!off.GetServices<IHostedService>().Any()); // Disabled does not require a TelemetryClient.
        foreach (var (publisher, telemetry) in new[] { (false, true), (true, false), (true, true) })
        {
            using var channel = new Channel(); using var fixture = new Fixture(publisher, telemetry, channel);
            var workers = fixture.Services.GetServices<IHostedService>().ToArray();
            foreach (var worker in workers) await worker.StartAsync(default);
            try
            {
                var catalog = new KeycloakFeatureFlagCatalog();
                var manager = fixture.Services.GetRequiredService<IVariantFeatureManager>();
                await Throws<ArgumentNullException>(() => Task.FromResult(new KeycloakMicrosoftFeatureGate(null!, catalog)));
                await Throws<ArgumentNullException>(() => Task.FromResult(new KeycloakMicrosoftFeatureGate(manager, null!)));
                var gate = new KeycloakMicrosoftFeatureGate(manager, catalog);
                Check(!await gate.IsEnabledAsync("private-unknown-key"));
                await Throws<ArgumentException>(async () => await gate.IsEnabledAsync(" "));
                using var canceled = new CancellationTokenSource(); canceled.Cancel();
                await Throws<OperationCanceledException>(async () => await gate.IsEnabledAsync("KeycloakSdk.AdminApi", canceled.Token));
                using var handler = new Handler(); using var http = new HttpClient(handler);
                var host = await KeycloakPlatformHost.CreateAsync(http, new Uri("https://keycloak.invalid/"),
                    new StaticAccessTokenProvider("private-token"), new()
                    { Support = new(KeycloakTarget.Version), FeatureManager = manager });
                Check(host.Gate is KeycloakMicrosoftFeatureGate && handler.Calls == 1);
                channel.Items.Clear();
                await host.Admin.Users.GetUsersAsync("private-realm");
                var protocol = new ProtocolTransport(http, new Uri("https://keycloak.invalid/"), "private-realm", host.Gate);
                await protocol.EnsureEnabledAsync("KeycloakSdk.Protocols.Oidc");
                var events = channel.Items.OfType<EventTelemetry>().ToArray();
                Check(events.Length == (publisher && telemetry ? 3 : 0));
                Check(events.All(e => e.Name == "FeatureEvaluation"));
                Check(events.All(e => e.Properties.Values.All(v => !v.Contains("private-", StringComparison.Ordinal) && !v.Contains("keycloak.invalid", StringComparison.Ordinal))));
                if (events.Length > 0)
                {
                    Check(events.SelectMany(e => e.Properties.Values).Contains("KeycloakSdk.AdminApi"));
                    Check(events.SelectMany(e => e.Properties.Values).Contains("KeycloakSdk.Protocols.Oidc"));
                }
                int sent = handler.Calls;
                int recorded = channel.Items.Count;
                await Throws<KeycloakCapabilityDeniedException>(() => host.Admin.SendAsync(HttpMethod.Get, "/admin/realms/private-realm/client-types"));
                Check(handler.Calls == sent && channel.Items.Count == recorded); // Catalog rejection precedes the engine.
                fixture.Set("KeycloakSdk.AdminApi", "enabled", "false");
                await Throws<KeycloakCapabilityDeniedException>(() => host.Admin.Users.GetUsersAsync("private-realm"));
                fixture.Set("KeycloakSdk.Protocols", "enabled", "false");
                await Throws<InvalidOperationException>(async () => await protocol.EnsureEnabledAsync("KeycloakSdk.Protocols.Oidc"));
                Check(handler.Calls == sent);
                fixture.Set("KeycloakSdk.AdminApi", "enabled", "true");
                await host.Admin.Users.GetUsersAsync("private-realm");
                fixture.Set("KeycloakSdk.Organizations", "conditions:client_filters:0:name", "Throwing");
                await Throws<FilterFailure>(() => host.Admin.SendAsync(HttpMethod.Get, "/admin/realms/private-realm/organizations"));
                Check(handler.Calls == sent + 1);
                await Throws<ArgumentException>(() => KeycloakPlatformHost.CreateAsync(http, new Uri("https://keycloak.invalid/"),
                    new StaticAccessTokenProvider("token"), new()
                    { Support = new(KeycloakTarget.Version), FeatureManager = manager, Flags = catalog.All.ToDictionary(id => id, _ => true) }));
                fixture.Set("KeycloakSdk.Protocols.Oidc", "id", "OtherApplication.RenamedFlag");
                await Throws<ArgumentException>(() => KeycloakPlatformHost.CreateAsync(http, new Uri("https://keycloak.invalid/"),
                    new StaticAccessTokenProvider("token"), new() { Support = new(KeycloakTarget.Version), FeatureManager = manager }));
            }
            finally { foreach (var worker in workers.Reverse()) await worker.StopAsync(default); }
        }
        using var snapshotChannel = new Channel(); using var snapshotFixture = new Fixture(false, false, snapshotChannel);
        using var firstScope = snapshotFixture.Services.CreateScope();
        var first = new KeycloakMicrosoftFeatureGate(firstScope.ServiceProvider.GetRequiredService<IVariantFeatureManagerSnapshot>(), new());
        Check(await first.IsEnabledAsync("KeycloakSdk.AdminApi"));
        snapshotFixture.Set("KeycloakSdk.AdminApi", "enabled", "false");
        Check(await first.IsEnabledAsync("KeycloakSdk.AdminApi"));
        using var nextScope = snapshotFixture.Services.CreateScope();
        var next = new KeycloakMicrosoftFeatureGate(nextScope.ServiceProvider.GetRequiredService<IVariantFeatureManagerSnapshot>(), new());
        Check(!await next.IsEnabledAsync("KeycloakSdk.AdminApi"));
    }

    private sealed class Fixture : IDisposable
    {
        internal ServiceProvider Services { get; }
        private readonly ConfigurationRoot config;
        private readonly string[] ids = [.. new KeycloakFeatureFlagCatalog().All.Order(StringComparer.Ordinal), "OtherApplication.Flag"];
        internal Fixture(bool publisher, bool telemetry, ITelemetryChannel channel)
        {
            string json = "{\"feature_management\":{\"feature_flags\":[" + string.Join(',', ids.Select(id =>
                "{\"id\":\"" + id + "\",\"enabled\":true,\"telemetry\":{\"enabled\":" + (telemetry ? "true" : "false") + "}}")) + "]}}";
            using var stream = new MemoryStream(Encoding.UTF8.GetBytes(json));
            using var parsed = (ConfigurationRoot)new ConfigurationBuilder().AddJsonStream(stream).Build();
            config = (ConfigurationRoot)new ConfigurationBuilder().AddInMemoryCollection(parsed.AsEnumerable()).Build();
            var services = new ServiceCollection(); services.AddSingleton<IConfiguration>(config);
            var builder = services.AddFeatureManagement().AddFeatureFilter<ThrowingFilter>();
            Check(ReferenceEquals(builder, builder.AddKeycloakApplicationInsightsTelemetry()));
            if (publisher) builder.AddKeycloakApplicationInsightsTelemetry(enabled: true);
            var tc = new TelemetryConfiguration
            { ConnectionString = "InstrumentationKey=00000000-0000-0000-0000-000000000001", TelemetryChannel = channel };
            services.AddSingleton(tc); services.AddSingleton(new TelemetryClient(tc));
            Services = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true, ValidateOnBuild = true });
        }
        internal void Set(string id, string property, string value)
        { config[$"feature_management:feature_flags:{Array.IndexOf(ids, id)}:{property}"] = value; config.Reload(); }
        public void Dispose() { Services.GetRequiredService<TelemetryConfiguration>().Dispose(); Services.Dispose(); config.Dispose(); }
    }
    public sealed class FilterFailure : Exception;
    [FilterAlias("Throwing")]
    public sealed class ThrowingFilter : IFeatureFilter
    { public Task<bool> EvaluateAsync(FeatureFilterEvaluationContext context) => throw new FilterFailure(); }
    private sealed class Handler : HttpMessageHandler
    {
        internal int Calls;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            { Content = new ByteArrayContent(request.RequestUri!.AbsolutePath.EndsWith("admin/serverinfo", StringComparison.Ordinal)
                ? CapabilityContracts.ServerInfo() : "[]"u8.ToArray()) });
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
