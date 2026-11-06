using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Capabilities;
using Keycloak.Admin.Sdk.FeatureManagement;
using Keycloak.Admin.Sdk.FeatureManagement.ApplicationInsights;
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

public static class FeatureManagementContracts
{
    private static readonly Uri Server = new("https://keycloak.invalid/auth/");
    private static readonly string[] Ids = KeycloakCapabilityCatalog.Find(KeycloakTarget.Version)!.Endpoints.Select(e => e.FeatureId).Distinct().Order().ToArray();
    private static Uri Target(string path) => new(Server, path.TrimStart('/'));
    private static KeycloakCapabilityPolicy Catalog(int route = 2, KeycloakSupportConfiguration? configuration = null) => new(Server,
        configuration ?? new(KeycloakTarget.Version, route == 1 ? KeycloakAdminRoute.FgapV1Compatibility : KeycloakAdminRoute.FgapV2Stable),
        KeycloakServerCapabilities.FromServerInfo(CapabilityContracts.ServerInfo(route: route)));
    private static void Check(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
    private static async Task<T> Throws<T>(Func<Task> action) where T : Exception
    { try { await action(); } catch (T error) { return error; } throw new InvalidOperationException("Expected " + typeof(T).Name); }

    private static (ServiceProvider Services, ConfigurationRoot Config, CountingManager Manager) Host(string? disabled = null,
        string? omitted = null, string? filter = null, bool telemetry = false, bool publisher = false, ITelemetryChannel? channel = null)
    {
        string json = "{\"feature_management\":{\"feature_flags\":[" + string.Join(',', Ids.Where(id => id != omitted).Select(id =>
            "{\"id\":\"" + id + "\",\"enabled\":" + (id == disabled ? "false" : "true") + ",\"telemetry\":{\"enabled\":" + (telemetry ? "true" : "false") + "}" +
            (filter is not null && id == "KeycloakSdk.Organizations" ? ",\"conditions\":{\"client_filters\":[{\"name\":\"" + filter + "\"}]}" : "") + "}")) + "]}}";
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(json));
        using var parsed = (ConfigurationRoot)new ConfigurationBuilder().AddJsonStream(stream).Build();
        var config = (ConfigurationRoot)new ConfigurationBuilder().AddInMemoryCollection(parsed.AsEnumerable()).Build();
        var services = new ServiceCollection();
        services.AddSingleton<IConfiguration>(config);
        var builder = services.AddFeatureManagement().AddFeatureFilter<ThrowingFilter>();
        Check(ReferenceEquals(builder, builder.AddKeycloakApplicationInsightsTelemetry(publisher)), "Builder preserved");
        if (channel is not null)
        {
            var tc = new TelemetryConfiguration { ConnectionString = "InstrumentationKey=00000000-0000-0000-0000-000000000001", TelemetryChannel = channel };
            services.AddSingleton(tc);
            services.AddSingleton(new TelemetryClient(tc));
        }
        var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true, ValidateOnBuild = true });
        return (provider, config, new CountingManager(provider.GetRequiredService<IVariantFeatureManager>()));
    }

    public static async Task DecisionsAsync()
    {
        var host = Host(); using var services = host.Services; using var config = host.Config;
        await Throws<ArgumentNullException>(() => Task.FromResult(new KeycloakFeatureManagementPolicy(null!, host.Manager)));
        await Throws<ArgumentNullException>(() => Task.FromResult(new KeycloakFeatureManagementPolicy(Catalog(), null!)));
        foreach (int route in new[] { 1, 2 })
        {
            var catalog = Catalog(route); var policy = new KeycloakFeatureManagementPolicy(catalog, host.Manager);
            int allowed = 0;
            foreach (var endpoint in KeycloakCapabilityCatalog.Find(KeycloakTarget.Version)!.Endpoints)
            {
                var uri = Target(Regex.Replace(endpoint.Path, "\\{[^}]+\\}", "fixture%2Fid"));
                var expected = catalog.Evaluate(new HttpMethod(endpoint.Method), uri, endpoint.Operation);
                host.Manager.Calls.Clear();
                var decision = await policy.EvaluateAsync(new HttpMethod(endpoint.Method), uri, endpoint.Operation);
                Check(decision.Reason == expected.Reason, "Host flags cannot promote catalog status: " + endpoint.Operation);
                Check(host.Manager.Calls.Count == (decision.IsAllowed ? (endpoint.FeatureId == KeycloakFeatureManagementPolicy.AdminApiFeature ? 1 : 2) : 0), "Catalog precedes master and feature evaluations");
                if (decision.IsAllowed) allowed++;
                else Check(ReferenceEquals(decision, decision.DisableByHost()), "Preserve earlier denial");
            }
            Check(allowed == (route == 1 ? 492 : 478), "FeatureManagement release/route count");
        }
        foreach (string id in new[] { "KeycloakSdk.AdminApi", "KeycloakSdk.Organizations" })
        foreach (bool missing in new[] { false, true })
        {
            var off = Host(disabled: missing ? null : id, omitted: missing ? id : null);
            using var offServices = off.Services; using var offConfig = off.Config;
            var decision = await new KeycloakFeatureManagementPolicy(Catalog(), off.Manager).EvaluateAsync(HttpMethod.Get, Target("admin/realms/master/organizations"));
            Check(decision.Reason == KeycloakCapabilityReason.DisabledByHost && decision.Capability!.FeatureId == "KeycloakSdk.Organizations" && decision.ServerVersion == KeycloakTarget.Version && decision.Route == KeycloakAdminRoute.FgapV2Stable, "Missing and false flags deny with identity preserved");
        }
        var blocked = new KeycloakFeatureManagementPolicy(Catalog(configuration: new(KeycloakTarget.Version, disabledCapabilities: ["KeycloakSdk.AdminApi"])), host.Manager);
        host.Manager.Calls.Clear();
        Check((await blocked.EvaluateAsync(HttpMethod.Get, Target("admin/serverinfo"))).Reason == KeycloakCapabilityReason.DisabledByHost && host.Manager.Calls.IsEmpty, "Static disable has priority");
        using var cancellation = new CancellationTokenSource(); cancellation.Cancel();
        await Throws<OperationCanceledException>(async () => await blocked.EvaluateAsync(HttpMethod.Get, Target("admin/serverinfo"), cancellationToken: cancellation.Token));
        var throwing = Host(filter: "Throwing"); using var throwingServices = throwing.Services; using var throwingConfig = throwing.Config;
        await Throws<FilterFailure>(async () => await new KeycloakFeatureManagementPolicy(Catalog(), throwing.Manager).EvaluateAsync(HttpMethod.Get, Target("admin/realms/master/organizations")));
        var missingFilter = Host(filter: "NotRegistered"); using var missingServices = missingFilter.Services; using var missingConfig = missingFilter.Config;
        await Throws<FeatureManagementException>(async () => await new KeycloakFeatureManagementPolicy(Catalog(), missingFilter.Manager).EvaluateAsync(HttpMethod.Get, Target("admin/realms/master/organizations")));
    }

    public static async Task NonStableRolloutAsync()
    {
        const string feature = "KeycloakSdk.ClientTypes";
        const string path = "/admin/realms/master/client-types";
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var ct = cancellation.Token;
        var host = Host(); using var services = host.Services; using var config = host.Config;
        var endpoint = KeycloakCapabilityCatalog.Current.Endpoints.Single(e => e.Operation == "ClientTypes.GetClientTypesAsync");
        var profiles = endpoint.SupportProfiles.ToArray();

        var noOptIn = new KeycloakFeatureManagementPolicy(Catalog(configuration: new(KeycloakTarget.Version, KeycloakRuntimeProfile.Managed)), host.Manager);
        Check((await noOptIn.EvaluateAsync(HttpMethod.Get, Target(path), cancellationToken: ct)).Reason == KeycloakCapabilityReason.StageNotAllowed
            && host.Manager.Calls.IsEmpty, "All flags on cannot supply a non-stable stage opt-in");

        var support = new KeycloakSupportConfiguration(KeycloakTarget.Version, KeycloakRuntimeProfile.Managed, experimentalCapabilities: [feature, "KeycloakSdk.Ssf"]);
        var policy = new KeycloakFeatureManagementPolicy(Catalog(configuration: support), host.Manager);
        var unverified = KeycloakCapabilityCatalog.Current.Endpoints.First(e => e.FeatureId == "KeycloakSdk.Ssf");
        var unverifiedTarget = Target(Regex.Replace(unverified.Path, "\\{[^}]+\\}", "fixture"));
        Check((await policy.EvaluateAsync(new HttpMethod(unverified.Method), unverifiedTarget, unverified.Operation, ct)).Reason == KeycloakCapabilityReason.NotSupported
            && host.Manager.Calls.IsEmpty, "All flags on cannot promote an unverified feature");

        var v1 = new KeycloakFeatureManagementPolicy(Catalog(1, new(KeycloakTarget.Version, KeycloakRuntimeProfile.Managed,
            route: KeycloakAdminRoute.FgapV1Compatibility, experimentalCapabilities: [feature])), host.Manager);
        Check((await v1.EvaluateAsync(HttpMethod.Get, Target(path), cancellationToken: ct)).Reason == KeycloakCapabilityReason.InsufficientVerification
            && host.Manager.Calls.IsEmpty, "Flags cannot extend managed v2 evidence to v1");

        using var handler = new Handler(); using var http = new HttpClient(handler); var tokens = new Tokens();
        var client = new KeycloakAdminClient(http, Server, tokens, new() { RequestPolicy = policy });
        int index = Array.IndexOf(Ids, feature);
        foreach (bool enabled in new[] { false, true, false })
        {
            config[$"feature_management:feature_flags:{index}:enabled"] = enabled ? "true" : "false";
            config.Reload();
            if (enabled) await client.SendAsync(HttpMethod.Get, path, cancellationToken: ct);
            else await Denied(() => client.SendAsync(HttpMethod.Get, path, cancellationToken: ct));
        }
        Check(handler.Sends == 1 && tokens.Acquisitions == 1, "Promoted feature supports off/on/off without HTTP or token acquisition when off");
        config[$"feature_management:feature_flags:{index}:enabled"] = "true";
        config[$"feature_management:feature_flags:{Array.IndexOf(Ids, KeycloakFeatureManagementPolicy.AdminApiFeature)}:enabled"] = "false";
        config.Reload();
        await Denied(() => client.SendAsync(HttpMethod.Get, path, cancellationToken: ct));
        Check(handler.Sends == 1 && tokens.Acquisitions == 1, "Master switch also closes a promoted feature");
        Check(endpoint.Stage == KeycloakFeatureStage.Experimental && endpoint.Support == KeycloakSupportStatus.Supported
            && endpoint.SupportProfiles.SequenceEqual(profiles), "Rollout changes neither upstream stage nor SDK verification profiles");
    }

    public static async Task TransportAsync()
    {
        var host = Host(); using var services = host.Services; using var config = host.Config;
        var policy = new KeycloakFeatureManagementPolicy(Catalog(), host.Manager);
        using var handler = new Handler(); using var http = new HttpClient(handler); var tokens = new Tokens();
        IKeycloakAdminClient client = new KeycloakAdminClient(http, Server, tokens, new() { RequestPolicy = policy, EnableUnauthorizedRecovery = true });
        await client.Users.GetUsersAsync("master");
        Check(handler.Sends == 1 && tokens.Acquisitions == 1 && host.Manager.Calls.Count == 1, "Allowed generated request");
        int index = Array.IndexOf(Ids, "KeycloakSdk.AdminApi");
        config[$"feature_management:feature_flags:{index}:enabled"] = "false";
        config.Reload();
        host.Manager.Calls.Clear();
        await Denied(() => client.Users.GetUsersAsync("master"));
        await Denied(() => client.SendAsync(HttpMethod.Get, "/admin/realms/master/users"));
        await Denied(() => client.OpenStreamAsync(HttpMethod.Get, "/admin/realms/master/users"));
        Check(handler.Sends == 1 && tokens.Acquisitions == 1, "Denied generated/raw/stream send no HTTP and acquire no tokens");
        using var cancellation = new CancellationTokenSource(); cancellation.Cancel();
        await Throws<OperationCanceledException>(async () => await client.Users.GetUsersAsync("master", cancellationToken: cancellation.Token));

        var replay = Host(); using var replayServices = replay.Services; using var replayConfig = replay.Config;
        handler.UnauthorizedNext = true;
        var retryClient = new KeycloakAdminClient(http, Server, tokens, new() { RequestPolicy = new KeycloakFeatureManagementPolicy(Catalog(), replay.Manager), EnableUnauthorizedRecovery = true });
        await retryClient.Users.GetUsersAsync("master");
        Check(handler.Sends == 3 && tokens.Invalidations == 1 && replay.Manager.Calls.Count == 1, "401 replays once without reevaluating flags");
        await retryClient.SendAsync(HttpMethod.Get, "/admin/realms/master/users");
        using (var response = await retryClient.OpenStreamAsync(HttpMethod.Get, "/admin/realms/master/users")) { }
        Check(replay.Manager.Calls.Count == 3, "Each new logical request evaluates flags afresh");

        var throwing = Host(filter: "Throwing"); using var throwingServices = throwing.Services; using var throwingConfig = throwing.Config;
        var failed = new KeycloakAdminClient(http, Server, tokens, new() { RequestPolicy = new KeycloakFeatureManagementPolicy(Catalog(), throwing.Manager) });
        int sent = handler.Sends, acquired = tokens.Acquisitions;
        await Throws<FilterFailure>(async () => await failed.SendAsync(HttpMethod.Get, "/admin/realms/master/organizations"));
        Check(handler.Sends == sent && tokens.Acquisitions == acquired, "Filter errors fail closed before transport/authentication");
    }

    private static async Task Denied(Func<Task> call)
    { var error = await Throws<KeycloakCapabilityDeniedException>(call); Check(error.Decision.Reason == KeycloakCapabilityReason.DisabledByHost, "Host denial"); }

    public static async Task BootstrapAsync()
    {
        var host = Host(); using var services = host.Services; using var config = host.Config;
        using var handler = new Handler(); using var http = new HttpClient(handler); var tokens = new Tokens();
        await Throws<ArgumentNullException>(async () => await KeycloakFeatureManagedClient.CreateAsync(http, Server, null!, new(KeycloakTarget.Version), host.Manager));
        await Throws<ArgumentNullException>(async () => await KeycloakFeatureManagedClient.CreateAsync(http, Server, tokens, null!, host.Manager));
        await Throws<ArgumentNullException>(async () => await KeycloakFeatureManagedClient.CreateAsync(http, Server, tokens, new(KeycloakTarget.Version), null!));
        IKeycloakAdminClient client = await KeycloakFeatureManagedClient.CreateAsync(http, Server, tokens, new(KeycloakTarget.Version), host.Manager, enableUnauthorizedRecovery: true);
        Check(handler.Sends == 1, "Only authenticated metadata read during bootstrap");
        await client.Users.GetUsersAsync("master");
        Check(handler.Sends == 2, "Guarded client works");
        var error = await Throws<KeycloakCapabilityDeniedException>(async () => await KeycloakFeatureManagedClient.CreateAsync(http, Server, tokens, new("unsupported-release"), host.Manager));
        Check(error.Decision.Reason == KeycloakCapabilityReason.UnknownVersion && handler.Sends == 3, "Unknown release rejected after metadata read");
        var off = Host(disabled: "KeycloakSdk.AdminApi"); using var offServices = off.Services; using var offConfig = off.Config;
        await Denied(async () => await KeycloakFeatureManagedClient.CreateAsync(http, Server, tokens, new(KeycloakTarget.Version), off.Manager));
        Check(handler.Sends == 4, "Host off permits bootstrap metadata read only");
    }

    public static async Task TelemetryAsync()
    {
        await Throws<ArgumentNullException>(() => Task.FromResult(KeycloakTelemetryExtensions.AddKeycloakApplicationInsightsTelemetry(null!)));
        foreach (var (publisher, enabled) in new[] { (false, true), (true, false), (true, true) })
        {
            using var channel = new Channel();
            var host = Host(telemetry: enabled, publisher: publisher, channel: channel);
            using var services = host.Services; using var config = host.Config;
            var workers = services.GetServices<IHostedService>().ToArray();
            foreach (var worker in workers) await worker.StartAsync(default);
            var policy = new KeycloakFeatureManagementPolicy(Catalog(), host.Manager);
            await policy.EnsureAllowedAsync(HttpMethod.Get, Target("admin/realms/private-realm/organizations"), null, default);
            var events = channel.Items.OfType<EventTelemetry>().Where(e => e.Name == "FeatureEvaluation").ToArray();
            Check(events.Length == (publisher && enabled ? 2 : 0), "Publisher opt-in AND per-flag telemetry opt-in");
            Check(events.All(e => e.Properties.Values.All(v => !v.Contains("private-realm", StringComparison.Ordinal) && !v.Contains("keycloak.invalid", StringComparison.Ordinal))), "No request URL or realm context added");
            if (events.Length > 0) Check(events.SelectMany(e => e.Properties.Values).Contains("KeycloakSdk.Organizations"), "Official publisher emits feature identity");
            int count = channel.Items.Count;
            var rejected = await policy.EvaluateAsync(HttpMethod.Get, Target("admin/realms/private-realm/client-types"));
            Check(!rejected.IsAllowed && channel.Items.Count == count, "Catalog denials do not run FeatureManagement or emit evaluations");
            foreach (var worker in workers.Reverse()) await worker.StopAsync(default);
            services.GetRequiredService<TelemetryConfiguration>().Dispose();
        }
    }

    public static async Task RunAsync()
    { await DecisionsAsync(); await NonStableRolloutAsync(); await TransportAsync(); await BootstrapAsync(); await TelemetryAsync(); }

    public sealed class FilterFailure : Exception;
    [FilterAlias("Throwing")]
    public sealed class ThrowingFilter : IFeatureFilter
    { public Task<bool> EvaluateAsync(FeatureFilterEvaluationContext context) => throw new FilterFailure(); }

    private sealed class CountingManager(IVariantFeatureManager inner) : IVariantFeatureManager
    {
        public ConcurrentQueue<string> Calls { get; } = new();
        public ValueTask<bool> IsEnabledAsync(string feature, CancellationToken cancellationToken = default)
        { Calls.Enqueue(feature); return inner.IsEnabledAsync(feature, cancellationToken); }
        public IAsyncEnumerable<string> GetFeatureNamesAsync(CancellationToken cancellationToken = default) => inner.GetFeatureNamesAsync(cancellationToken);
        public ValueTask<bool> IsEnabledAsync<TContext>(string feature, TContext context, CancellationToken cancellationToken = default) => inner.IsEnabledAsync(feature, context, cancellationToken);
        public ValueTask<Variant> GetVariantAsync(string feature, CancellationToken cancellationToken = default) => inner.GetVariantAsync(feature, cancellationToken);
        public ValueTask<Variant> GetVariantAsync(string feature, ITargetingContext context, CancellationToken cancellationToken = default) => inner.GetVariantAsync(feature, context, cancellationToken);
    }
    private sealed class Tokens : IRefreshableAccessTokenProvider
    {
        public int Acquisitions, Invalidations;
        public ValueTask<string> GetAccessTokenAsync(CancellationToken cancellationToken = default) { Acquisitions++; return ValueTask.FromResult("private-token"); }
        public ValueTask InvalidateAsync(string rejectedAccessToken, CancellationToken cancellationToken = default) { Invalidations++; return ValueTask.CompletedTask; }
    }
    private sealed class Handler : HttpMessageHandler
    {
        public int Sends; public bool UnauthorizedNext;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Sends++;
            if (UnauthorizedNext) { UnauthorizedNext = false; return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Unauthorized)); }
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(request.RequestUri!.AbsolutePath.EndsWith("admin/serverinfo", StringComparison.Ordinal) ? CapabilityContracts.ServerInfo() : "[]"u8.ToArray()) });
        }
    }
    private sealed class Channel : ITelemetryChannel
    {
        public ConcurrentQueue<ITelemetry> Items { get; } = new();
        public bool? DeveloperMode { get; set; }
        public string EndpointAddress { get; set; } = "https://telemetry.invalid/";
        public void Send(ITelemetry item) => Items.Enqueue(item);
        public void Flush() { }
        public void Dispose() { }
    }
}
