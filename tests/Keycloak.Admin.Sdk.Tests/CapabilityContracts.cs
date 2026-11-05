using System.Net;
using System.Text;
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Capabilities;

public static class CapabilityContracts
{
    private static readonly Uri Server = new("https://keycloak.invalid/auth/");
    private const string Config = """{"schemaVersion":1,"serverVersion":"26.8.1","route":"fgap-v2-stable","allowPreview":false,"allowExperimental":false,"disabledCapabilities":[]}""";
    public static byte[] ServerInfo(string version = "26.8.1", int route = 2, string? missing = null, string? disabled = null)
    {
        var features = new Dictionary<string, bool> { ["ADMIN_API"] = true, ["AUTHORIZATION"] = true, ["ORGANIZATION"] = true,
            ["ADMIN_V2"] = true, ["WORKFLOWS"] = true, ["CLIENT_POLICIES"] = true, ["IMPERSONATION"] = true, ["ADMIN_FINE_GRAINED_AUTHZ"] = route == 1,
            ["ADMIN_FINE_GRAINED_AUTHZ_V2"] = route == 2, ["OID4VC_VCI"] = true, ["SSF"] = true, ["CLIENT_TYPES"] = true };
        if (missing is not null) features.Remove(missing);
        if (disabled is not null) features[disabled] = false;
        return Encoding.UTF8.GetBytes("{\"systemInfo\":{\"version\":\"" + version + "\"},\"features\":[" + string.Join(',', features.Select(f => "{\"name\":\"" + f.Key + "\",\"enabled\":" + (f.Value ? "true" : "false") + "}")) + "]}");
    }
    private static KeycloakCapabilityPolicy Policy(KeycloakSupportConfiguration? configuration = null, byte[]? server = null) => new(Server,
        configuration ?? new("26.8.1"), KeycloakServerCapabilities.FromServerInfo(server ?? ServerInfo()));
    private static Uri Target(string path) => new(Server, path.TrimStart('/'));
    private static void Check(bool condition) { if (!condition) throw new InvalidOperationException("Capability contract assertion failed."); }
    private static void Throws<T>(Action action) where T : Exception
    { try { action(); } catch (T) { return; } throw new InvalidOperationException("Expected " + typeof(T).Name); }

    public static void Catalog()
    {
        var release = KeycloakCapabilityCatalog.Find("26.8.1")!;
        Check(KeycloakCapabilityCatalog.Releases.Count == 1 && KeycloakCapabilityCatalog.Find("26.8.2") is null);
        Check(release.SourceCommit == "24ed1dadf3f246a555adb6d3d4a99e9b3003fb3b" && release.ServerVersion == "26.8.1");
        Check(release.Endpoints.Count == 520 && release.Endpoints.Select(e => e.Operation).Distinct().Count() == 520);
        Check(release.Endpoints.Count(e => e.Stage == KeycloakFeatureStage.Preview) == 7 && release.Endpoints.Count(e => e.Stage == KeycloakFeatureStage.Experimental) == 21);
        Check(release.Endpoints.Count(e => e.Support == KeycloakSupportStatus.Compatibility) == 14);
        foreach (int route in new[] { 1, 2 })
        {
            var policy = Policy(new("26.8.1", route == 1 ? KeycloakAdminRoute.FgapV1Compatibility : KeycloakAdminRoute.FgapV2Stable), ServerInfo(route: route));
            int allowed = 0;
            foreach (var endpoint in release.Endpoints)
            {
                string path = System.Text.RegularExpressions.Regex.Replace(endpoint.Path, "\\{[^}]+\\}", "fixture%2Fid");
                var decision = policy.Evaluate(new HttpMethod(endpoint.Method), Target(path), endpoint.Operation);
                Check(decision.Capability == endpoint && decision.ServerVersion == "26.8.1" && decision.Route == (route == 1 ? KeycloakAdminRoute.FgapV1Compatibility : KeycloakAdminRoute.FgapV2Stable));
                Check(endpoint.FeatureId.StartsWith("KeycloakSdk.", StringComparison.Ordinal) && endpoint.Evidence.Length > 0 && endpoint.Implementation == KeycloakImplementationStatus.Implemented && endpoint.RequiredServerFeatures.Contains("ADMIN_API"));
                Check(endpoint.Routes.Contains(KeycloakAdminRoute.FgapV1Compatibility));
                if (decision.IsAllowed) { allowed++; Check(endpoint.Verification == (KeycloakVerification.Contract | KeycloakVerification.Managed | KeycloakVerification.NativeAot)); }
                else Check(endpoint.Support == KeycloakSupportStatus.NotSupported || endpoint.Support == KeycloakSupportStatus.Compatibility);
            }
            Check(allowed == (route == 1 ? 492 : 478));
        }
    }
    public static void Configuration()
    {
        var config = KeycloakSupportConfiguration.Parse(Config);
        Check(config.ServerVersion == "26.8.1" && config.Route == KeycloakAdminRoute.FgapV2Stable && !config.AllowPreview && !config.AllowExperimental && config.DisabledCapabilities.Count == 0);
        var environment = new Dictionary<string, string?> { ["KEYCLOAK_ADMIN_API_ROUTE"] = "fgap-v1-compat", ["KEYCLOAK_ADMIN_SERVER_VERSION"] = "future",
            ["KEYCLOAK_ADMIN_ALLOW_PREVIEW"] = "true", ["KEYCLOAK_ADMIN_ALLOW_EXPERIMENTAL"] = "true", ["KEYCLOAK_ADMIN_DISABLED_CAPABILITIES"] = " KeycloakSdk.Ssf,KeycloakSdk.Oid4vcVci," };
        config = KeycloakSupportConfiguration.Parse(Config, name => environment.GetValueOrDefault(name));
        Check(config.Route == KeycloakAdminRoute.FgapV1Compatibility && config.ServerVersion == "future" && config.AllowPreview && config.AllowExperimental && config.DisabledCapabilities.SetEquals(["KeycloakSdk.Ssf", "KeycloakSdk.Oid4vcVci"]));
        Check(KeycloakSupportConfiguration.Parse(Config, _ => null).Route == KeycloakAdminRoute.FgapV2Stable);
        config = KeycloakSupportConfiguration.Parse(Config.Replace("[]", "[\"KeycloakSdk.AdminApi\"]", StringComparison.Ordinal));
        Check(config.DisabledCapabilities.Contains("KeycloakSdk.AdminApi"));
        Throws<ArgumentException>(() => new KeycloakSupportConfiguration(" "));
        Throws<ArgumentOutOfRangeException>(() => new KeycloakSupportConfiguration("26.8.1", (KeycloakAdminRoute)99));
        Throws<System.Text.Json.JsonException>(() => KeycloakSupportConfiguration.Parse(Config.Replace("\"schemaVersion\":1", "\"schemaVersion\":2", StringComparison.Ordinal)));
        Throws<System.Text.Json.JsonException>(() => KeycloakSupportConfiguration.Parse(Config.Replace("\"schemaVersion\":1", "\"unknown\":1", StringComparison.Ordinal)));
        Throws<System.Text.Json.JsonException>(() => KeycloakSupportConfiguration.Parse(Config.Replace("\"schemaVersion\":1", "\"schemaVersion\":1,\"schemaVersion\":1", StringComparison.Ordinal)));
        Throws<System.Text.Json.JsonException>(() => KeycloakSupportConfiguration.Parse(Config.Replace("fgap-v2-stable", "guessed-route", StringComparison.Ordinal)));
        Throws<FormatException>(() => KeycloakSupportConfiguration.Parse(Config, n => n == "KEYCLOAK_ADMIN_ALLOW_PREVIEW" ? "invalid" : null));
        Throws<ArgumentException>(() => new KeycloakCapabilityPolicy(Server, new("26.8.1", disabledCapabilities: ["typo"]), KeycloakServerCapabilities.FromServerInfo(ServerInfo())));
        Throws<ArgumentException>(() => new KeycloakCapabilityPolicy(new Uri("ftp://example.invalid/"), new("26.8.1"), KeycloakServerCapabilities.FromServerInfo(ServerInfo())));
        Throws<ArgumentException>(() => new KeycloakCapabilityPolicy(new Uri("https://example.invalid/?x"), new("26.8.1"), KeycloakServerCapabilities.FromServerInfo(ServerInfo())));
        Throws<ArgumentException>(() => new KeycloakCapabilityPolicy(new Uri("https://example.invalid/#x"), new("26.8.1"), KeycloakServerCapabilities.FromServerInfo(ServerInfo())));
        Throws<ArgumentException>(() => new KeycloakCapabilityPolicy(new Uri("https://u@example.invalid/"), new("26.8.1"), KeycloakServerCapabilities.FromServerInfo(ServerInfo())));
        Throws<ArgumentException>(() => new KeycloakCapabilityPolicy(new Uri("relative", UriKind.Relative), new("26.8.1"), KeycloakServerCapabilities.FromServerInfo(ServerInfo())));
        Check(new KeycloakCapabilityPolicy(new Uri("http://keycloak.invalid/auth"), new("26.8.1"), KeycloakServerCapabilities.FromServerInfo(ServerInfo()))
            .Evaluate(HttpMethod.Get, new Uri("http://keycloak.invalid/auth/admin/serverinfo")).IsAllowed);
        Throws<ArgumentNullException>(() => new KeycloakCapabilityPolicy(null!, new("26.8.1"), KeycloakServerCapabilities.FromServerInfo(ServerInfo())));
        Throws<ArgumentNullException>(() => new KeycloakCapabilityPolicy(Server, null!, KeycloakServerCapabilities.FromServerInfo(ServerInfo())));
        Throws<ArgumentNullException>(() => new KeycloakCapabilityPolicy(Server, new("26.8.1"), null!));
        Throws<ArgumentException>(() => KeycloakServerCapabilities.FromServerInfo(ServerInfo(version: " ")));
        Throws<ArgumentException>(() => KeycloakServerCapabilities.FromServerInfo(Encoding.UTF8.GetBytes("""{"systemInfo":{"version":"26.8.1"},"features":[{"name":"DUP","enabled":true},{"name":"DUP","enabled":false}]}""")));
    }
    public static void Decisions()
    {
        var target = Target("/admin/realms/demo/users");
        void Reason(KeycloakCapabilityPolicy p, KeycloakCapabilityReason reason, Uri? uri = null, string? operation = null, HttpMethod? method = null) => Check(p.Evaluate(method ?? HttpMethod.Get, uri ?? target, operation).Reason == reason);
        Reason(Policy(new("future")), KeycloakCapabilityReason.UnknownVersion);
        Reason(Policy(server: ServerInfo(version: "26.8.2")), KeycloakCapabilityReason.VersionMismatch);
        Reason(Policy(), KeycloakCapabilityReason.WrongServer, new Uri("https://other.invalid/auth/admin/realms/demo/users"));
        Reason(Policy(), KeycloakCapabilityReason.WrongServer, new Uri("https://keycloak.invalid/other/admin/serverinfo"));
        Reason(Policy(), KeycloakCapabilityReason.WrongServer, new Uri("relative", UriKind.Relative));
        Reason(Policy(), KeycloakCapabilityReason.UnknownEndpoint, operation: "Unknown");
        Reason(Policy(), KeycloakCapabilityReason.EndpointMismatch, operation: "ServerInfoAdmin.GetInfoAsync");
        Reason(Policy(), KeycloakCapabilityReason.EndpointMismatch, Target("/admin/serverinfo"), "ServerInfoAdmin.GetInfoAsync", HttpMethod.Post);
        Reason(Policy(), KeycloakCapabilityReason.UnknownEndpoint, Target("/admin/vendor/extension"));
        Reason(Policy(), KeycloakCapabilityReason.UnknownEndpoint, Target("/realms/master/protocol/openid-connect/token"), method: HttpMethod.Post);
        Reason(Policy(server: ServerInfo(missing: "ADMIN_FINE_GRAINED_AUTHZ_V2")), KeycloakCapabilityReason.RouteUnavailable);
        Reason(Policy(server: ServerInfo(missing: "ADMIN_FINE_GRAINED_AUTHZ")), KeycloakCapabilityReason.RouteUnavailable);
        Reason(Policy(server: ServerInfo(route: 1)), KeycloakCapabilityReason.RouteMismatch);
        Reason(Policy(server: ServerInfo(route: 0)), KeycloakCapabilityReason.RouteMismatch);
        byte[] both = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(ServerInfo()).Replace("\"name\":\"ADMIN_FINE_GRAINED_AUTHZ\",\"enabled\":false", "\"name\":\"ADMIN_FINE_GRAINED_AUTHZ\",\"enabled\":true", StringComparison.Ordinal));
        Reason(Policy(server: both), KeycloakCapabilityReason.RouteMismatch);
        Reason(Policy(server: ServerInfo(missing: "ADMIN_API")), KeycloakCapabilityReason.ServerFeatureUnknown);
        Reason(Policy(server: ServerInfo(disabled: "ADMIN_API")), KeycloakCapabilityReason.ServerFeatureDisabled);
        Reason(Policy(new("26.8.1", disabledCapabilities: ["KeycloakSdk.AdminApi"])), KeycloakCapabilityReason.DisabledByHost);
        Reason(Policy(new("26.8.1", disabledCapabilities: ["KeycloakSdk.AdminApi"])), KeycloakCapabilityReason.DisabledByHost, Target("/admin/realms/demo/workflows"));
        Reason(Policy(new("26.8.1", disabledCapabilities: ["KeycloakSdk.Workflows"])), KeycloakCapabilityReason.DisabledByHost, Target("/admin/realms/demo/workflows"));
        Reason(Policy(server: ServerInfo(disabled: "CLIENT_POLICIES")), KeycloakCapabilityReason.ServerFeatureDisabled, Target("/admin/realms/demo/client-policies/policies"));
        Reason(Policy(server: ServerInfo(disabled: "IMPERSONATION")), KeycloakCapabilityReason.ServerFeatureDisabled, Target("/admin/realms/demo/users/user/impersonation"), method: HttpMethod.Post);
        Reason(Policy(), KeycloakCapabilityReason.Allowed, Target("/admin/realms/demo/users/count?x=1"));
        Check(Policy().Evaluate(HttpMethod.Get, Target("/admin/realms/demo/users/count")).Capability!.Path.EndsWith("/count", StringComparison.Ordinal));
        Reason(Policy(), KeycloakCapabilityReason.Allowed, Target("/admin/realms/demo/users/"));
        Reason(Policy(), KeycloakCapabilityReason.UnknownEndpoint, Target("/admin/realms//users"));
        Throws<ArgumentNullException>(() => Policy().Evaluate(null!, target));
        Throws<ArgumentNullException>(() => Policy().Evaluate(HttpMethod.Get, null!));
        foreach (var stage in new[] { KeycloakFeatureStage.Preview, KeycloakFeatureStage.Experimental })
        {
            var endpoint = KeycloakCapabilityCatalog.Find("26.8.1")!.Endpoints.First(e => e.Stage == stage);
            Check(Policy().EvaluateEndpoint(endpoint).Reason == KeycloakCapabilityReason.StageNotAllowed);
            Check(Policy(new("26.8.1", allowPreview: true, allowExperimental: true)).EvaluateEndpoint(endpoint).Reason == KeycloakCapabilityReason.NotSupported);
        }
        KeycloakEndpointCapability Entry(KeycloakFeatureStage stage = KeycloakFeatureStage.Stable, KeycloakImplementationStatus impl = KeycloakImplementationStatus.Implemented,
            KeycloakSupportStatus support = KeycloakSupportStatus.Supported, KeycloakVerification verification = KeycloakVerification.Contract | KeycloakVerification.Managed | KeycloakVerification.NativeAot)
            => new("Future", "GET", "/admin/future", "KeycloakSdk.AdminApi", stage, impl, support, verification, ["ADMIN_API"], "test future release transition", [KeycloakAdminRoute.FgapV2Stable, KeycloakAdminRoute.FgapV1Compatibility]);
        Check(Policy().EvaluateEndpoint(Entry(support: KeycloakSupportStatus.Compatibility)).IsAllowed);
        Check(Policy().EvaluateEndpoint(Entry(stage: KeycloakFeatureStage.Removed)).Reason == KeycloakCapabilityReason.StageNotAllowed);
        Check(Policy().EvaluateEndpoint(Entry(impl: KeycloakImplementationStatus.NotImplemented)).Reason == KeycloakCapabilityReason.NotImplemented);
        Check(Policy().EvaluateEndpoint(Entry(verification: KeycloakVerification.Contract)).Reason == KeycloakCapabilityReason.InsufficientVerification);
        Check(Policy().EvaluateEndpoint(Entry(verification: KeycloakVerification.None)).Reason == KeycloakCapabilityReason.InsufficientVerification);
    }
    public static async Task Transport()
    {
        int calls = 0, tokens = 0;
        using var handler = new Handler(_ => { calls++; return new(HttpStatusCode.OK) { Content = new StringContent("[]") }; });
        using var http = new HttpClient(handler);
        var token = new Token(() => tokens++);
        var sdk = new KeycloakAdminClient(http, Server, token, new() { RequestPolicy = Policy(new("26.8.1", disabledCapabilities: ["KeycloakSdk.AdminApi"])) });
        async Task Denied(Func<Task> action)
        {
            try { await action(); } catch (KeycloakCapabilityDeniedException e) { Check(e.Decision.Reason == KeycloakCapabilityReason.DisabledByHost && !e.ToString().Contains("sensitive-user", StringComparison.Ordinal)); return; }
            throw new Exception("Expected local policy denial");
        }
        await Denied(async () => await sdk.Users.GetUsersAsync("sensitive-user"));
        await Denied(async () => await sdk.SendAsync(HttpMethod.Get, "/admin/realms/demo/users"));
        await Denied(async () => await sdk.OpenStreamAsync(HttpMethod.Get, "/admin/realms/demo/users"));
        var body = new Content();
        await Denied(async () => await sdk.SendAsync(HttpMethod.Post, "/admin/realms/demo/users", content: body));
        Check(body.Disposed && calls == 0 && tokens == 0);
        using var cts = new CancellationTokenSource(); cts.Cancel();
        try { await Policy().EnsureAllowedAsync(HttpMethod.Get, Target("/admin/serverinfo"), null, cts.Token); throw new Exception("Expected cancellation"); } catch (OperationCanceledException) { }
        sdk = new(http, Server, token, new() { RequestPolicy = Policy() });
        await sdk.Users.GetUsersAsync("demo");
        await sdk.SendAsync(HttpMethod.Get, "/admin/realms/demo/users");
        using (var download = await sdk.OpenStreamAsync(HttpMethod.Get, "/admin/realms/demo/users")) Check(download.Content.ReadByte() == '[');
        Check(calls == 3 && tokens == 3);
        // A 401 replay uses the same policy decision instead of reevaluating host state mid-operation.
        int evaluations = 0; calls = 0;
        using var replayHandler = new Handler(_ => new(++calls == 1 ? HttpStatusCode.Unauthorized : HttpStatusCode.OK) { Content = new StringContent("[]") });
        using var replayHttp = new HttpClient(replayHandler);
        sdk = new(replayHttp, Server, new RefreshingToken(), new() { EnableUnauthorizedRecovery = true, RequestPolicy = new CountingPolicy(() => evaluations++) });
        await sdk.Users.GetUsersAsync("demo"); Check(evaluations == 1 && calls == 2);
    }
    public static async Task Bootstrap()
    {
        int calls = 0;
        using var handler = new Handler(request => { calls++; Check(request.Headers.Authorization?.Parameter == "token"); return new(HttpStatusCode.OK) { Content = new ByteArrayContent(ServerInfo()) }; });
        using var http = new HttpClient(handler);
        var token = new Token(() => { });
        var sdk = await KeycloakSupportedClient.CreateAsync(http, Server, token, new("26.8.1"), true);
        Check(calls == 1);
        try { await sdk.SendAsync(HttpMethod.Get, "/admin/vendor/unknown"); throw new Exception("Expected deny"); } catch (KeycloakCapabilityDeniedException e) { Check(e.Decision.Reason == KeycloakCapabilityReason.UnknownEndpoint); }
        Check(calls == 1);
        try { await KeycloakSupportedClient.CreateAsync(http, Server, token, new("future")); throw new Exception("Expected unknown version"); } catch (KeycloakCapabilityDeniedException e) { Check(e.Decision.Reason == KeycloakCapabilityReason.UnknownVersion); }
        try { await KeycloakSupportedClient.CreateAsync(http, Server, null!, new("26.8.1")); throw new Exception("Expected null"); } catch (ArgumentNullException) { }
        try { await KeycloakSupportedClient.CreateAsync(http, Server, token, null!); throw new Exception("Expected null"); } catch (ArgumentNullException) { }
        Check(calls == 2);
    }
    public static async Task RunAsync() { Catalog(); Configuration(); Decisions(); await Transport(); await Bootstrap(); }
    private sealed class Handler(Func<HttpRequestMessage, HttpResponseMessage> send) : HttpMessageHandler
    { protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) => Task.FromResult(send(request)); }
    private sealed class Token(Action acquired) : IAccessTokenProvider
    { public ValueTask<string> GetAccessTokenAsync(CancellationToken cancellationToken = default) { acquired(); return ValueTask.FromResult("token"); } }
    private sealed class RefreshingToken : IRefreshableAccessTokenProvider
    { public ValueTask<string> GetAccessTokenAsync(CancellationToken cancellationToken = default) => ValueTask.FromResult("token"); public ValueTask InvalidateAsync(string rejectedToken, CancellationToken cancellationToken = default) => ValueTask.CompletedTask; }
    private sealed class CountingPolicy(Action evaluate) : IKeycloakAdminRequestPolicy
    { public ValueTask EnsureAllowedAsync(HttpMethod method, Uri target, string? operation, CancellationToken ct) { evaluate(); return ValueTask.CompletedTask; } }
    private sealed class Content : ByteArrayContent
    { public bool Disposed { get; private set; } public Content() : base([]) { } protected override void Dispose(bool disposing) { Disposed = true; base.Dispose(disposing); } }
}
