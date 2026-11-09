using System.Net;
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Capabilities;
using Keycloak.Admin.Sdk.Platform;
using Keycloak.Admin.Sdk.Protocols;

public static class PlatformContracts
{
    private static readonly Uri Server = new("https://keycloak.invalid/auth/");
    private const int ExpectedFlags = 66;

    private static void Check(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
    private static T ThrowsSync<T>(Action action) where T : Exception
    { try { action(); } catch (T error) { return error; } throw new InvalidOperationException("Expected " + typeof(T).Name); }
    private static async Task<T> Throws<T>(Func<Task> action) where T : Exception
    { try { await action(); } catch (T error) { return error; } throw new InvalidOperationException("Expected " + typeof(T).Name); }
    private static Dictionary<string, bool> All(KeycloakFeatureFlagCatalog catalog) => catalog.All.ToDictionary(id => id, _ => true);

    public static void Catalog()
    {
        var catalog = new KeycloakFeatureFlagCatalog();
        Check(catalog.All.Count == ExpectedFlags, "Generated flag catalog must be complete.");
        Check(catalog.MasterFlags.Count == 2 && catalog.MasterFlags.Contains("KeycloakSdk.AdminApi")
            && catalog.MasterFlags.Contains("KeycloakSdk.Protocols"), "Both master switches are declared.");
        Check(catalog.IsKnown("KeycloakSdk.AdminApi") && catalog.IsKnown("KeycloakSdk.Protocols.Oidc")
            && !catalog.IsKnown("KeycloakSdk.Unknown"), "Catalog membership is exact.");
        var flags = All(catalog);
        catalog.EnsureComplete(flags);
        ThrowsSync<ArgumentNullException>(() => catalog.EnsureComplete(null!));
        var unknown = new Dictionary<string, bool>(flags) { ["KeycloakSdk.Unknown"] = true };
        ThrowsSync<ArgumentException>(() => catalog.EnsureComplete(unknown));
        var incomplete = new Dictionary<string, bool>(flags);
        incomplete.Remove("KeycloakSdk.Protocols.Oidc");
        ThrowsSync<ArgumentException>(() => catalog.EnsureComplete(incomplete));
    }

    public static async Task GateAsync()
    {
        var catalog = new KeycloakFeatureFlagCatalog();
        var flags = All(catalog);
        var gate = KeycloakPlatformGate.Create(flags, catalog);
        Check(await gate.IsEnabledAsync("KeycloakSdk.AdminApi"), "Master switch on");
        flags["KeycloakSdk.Organizations"] = false;
        KeycloakPlatformGate.Replace(gate, flags, catalog);
        Check(!await gate.IsEnabledAsync("KeycloakSdk.Organizations") && await gate.IsEnabledAsync("KeycloakSdk.AdminApi"),
            "Atomic snapshot replacement");
        ThrowsSync<ArgumentNullException>(() => KeycloakPlatformGate.Create(null!, catalog));
        ThrowsSync<ArgumentNullException>(() => KeycloakPlatformGate.Create(flags, null!));
        ThrowsSync<ArgumentNullException>(() => KeycloakPlatformGate.Replace(null!, flags, catalog));
        ThrowsSync<ArgumentNullException>(() => KeycloakPlatformGate.Replace(gate, null!, catalog));
        ThrowsSync<ArgumentNullException>(() => KeycloakPlatformGate.Replace(gate, flags, null!));
        var incomplete = new Dictionary<string, bool>(flags);
        incomplete.Remove("KeycloakSdk.Protocols.Oidc");
        ThrowsSync<ArgumentException>(() => KeycloakPlatformGate.Replace(gate, incomplete, catalog));
    }

    public static async Task DecisionsAsync()
    {
        var catalog = new KeycloakFeatureFlagCatalog();
        var flags = All(catalog);
        flags["KeycloakSdk.AdminApi"] = false;
        var gate = KeycloakPlatformGate.Create(flags, catalog);
        var policy = new KeycloakFeatureGatePolicy(new KeycloakCapabilityPolicy(Server,
            new KeycloakSupportConfiguration(KeycloakTarget.Version),
            KeycloakServerCapabilities.FromServerInfo(CapabilityTestData.ServerInfo())), gate);
        var target = new Uri(Server, "admin/serverinfo");
        var denied = await policy.EvaluateAsync(HttpMethod.Get, target, "ServerInfoAdmin.GetInfoAsync");
        Check(denied.Reason == KeycloakCapabilityReason.DisabledByHost, "A closed host switch cannot be promoted by the catalog");
        flags["KeycloakSdk.AdminApi"] = true;
        KeycloakPlatformGate.Replace(gate, flags, catalog);
        Check((await policy.EvaluateAsync(HttpMethod.Get, target, "ServerInfoAdmin.GetInfoAsync")).IsAllowed,
            "Reopening the switch allows a catalog-approved operation");
    }

    public static async Task HostAsync()
    {
        var catalog = new KeycloakFeatureFlagCatalog();
        var flags = All(catalog);
        var options = new KeycloakPlatformOptions
        {
            Support = new KeycloakSupportConfiguration(KeycloakTarget.Version),
            ProtocolSupport = new ApplicationSupportConfiguration(KeycloakRuntimeProfile.Managed),
            Flags = flags, Catalog = catalog, EnableUnauthorizedRecovery = true
        };
        using var handler = new Handler();
        using var http = new HttpClient(handler);
        var tokens = new StaticAccessTokenProvider("private-token");
        var host = await KeycloakPlatformHost.CreateAsync(http, Server, tokens, options);
        Check(handler.Sends == 1, "Only authenticated metadata read during bootstrap");
        Check(host.ServerCapabilities.ServerVersion == KeycloakTarget.Version, "One serverinfo bootstrap is shared by both chains");
        Check(host.Catalog.All.Count == ExpectedFlags && host.Gate is KeycloakFeatureSnapshotGate,
            "Shared catalog and AOT-safe snapshot gate");
        await host.Admin.Users.GetUsersAsync("master");
        Check(handler.Sends == 2, "Guarded Admin client works");
        flags["KeycloakSdk.AdminApi"] = false;
        KeycloakPlatformGate.Replace((KeycloakFeatureSnapshotGate)host.Gate, flags, host.Catalog);
        await Throws<KeycloakCapabilityDeniedException>(() => host.Admin.Users.GetUsersAsync("master"));
        Check(handler.Sends == 2, "A closed master switch sends no HTTP and acquires no token");
        var transport = host.CreateProtocolTransport(http, "master");
        Check(transport.Issuer.AbsoluteUri.EndsWith("/realms/master", StringComparison.Ordinal),
            "Protocol transport reuses the same bootstrap and gate");
        var explicitTransport = host.CreateProtocolTransport(http, "master", new ApplicationSupportConfiguration(KeycloakRuntimeProfile.Managed));
        Check(explicitTransport.Issuer == transport.Issuer, "Explicit application support is honored");
        ThrowsSync<ArgumentNullException>(() => host.CreateProtocolTransport(null!, "master"));

        var bare = new KeycloakPlatformOptions { Support = new KeycloakSupportConfiguration(KeycloakTarget.Version), Flags = All(catalog), Catalog = catalog };
        var bareHost = await KeycloakPlatformHost.CreateAsync(http, Server, tokens, bare);
        ThrowsSync<ArgumentException>(() => bareHost.CreateProtocolTransport(http, "master"));
        var defaultCatalog = new KeycloakPlatformOptions { Support = new KeycloakSupportConfiguration(KeycloakTarget.Version), Flags = All(catalog) };
        var defaultHost = await KeycloakPlatformHost.CreateAsync(http, Server, tokens, defaultCatalog);
        Check(defaultHost.Catalog.All.Count == ExpectedFlags, "Default embedded catalog is used when none is supplied");

        await Throws<ArgumentNullException>(async () => await KeycloakPlatformHost.CreateAsync(null!, Server, tokens, options));
        await Throws<ArgumentNullException>(async () => await KeycloakPlatformHost.CreateAsync(http, null!, tokens, options));
        await Throws<ArgumentNullException>(async () => await KeycloakPlatformHost.CreateAsync(http, Server, null!, options));
        await Throws<ArgumentNullException>(async () => await KeycloakPlatformHost.CreateAsync(http, Server, tokens, null!));
        await Throws<ArgumentException>(async () => await KeycloakPlatformHost.CreateAsync(http, Server, tokens,
            new KeycloakPlatformOptions { Flags = flags }));
        await Throws<ArgumentException>(async () => await KeycloakPlatformHost.CreateAsync(http, Server, tokens,
            new KeycloakPlatformOptions { Support = new KeycloakSupportConfiguration(KeycloakTarget.Version) }));
    }

    public static async Task RunAsync()
    { Catalog(); await GateAsync(); await DecisionsAsync(); await HostAsync(); }

    private sealed class Handler : HttpMessageHandler
    {
        public int Sends;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Sends++;
            byte[] body = request.RequestUri!.AbsolutePath.EndsWith("admin/serverinfo", StringComparison.Ordinal)
                ? CapabilityTestData.ServerInfo() : "[]"u8.ToArray();
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(body) });
        }
    }
}
