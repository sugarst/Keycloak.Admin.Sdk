using System.Net;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text.Json;
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Capabilities;

public static class RuntimeCapabilityContracts
{
    private static readonly Uri Server = new("https://keycloak.invalid/auth/");
    private const string Feature = "KeycloakSdk.ClientTypes";
    private const KeycloakVerification All = KeycloakVerification.Contract | KeycloakVerification.Managed | KeycloakVerification.NativeAot;
    private static void Check(bool value) { if (!value) throw new InvalidOperationException("Runtime capability contract failed."); }
    private static void Reject<T>(Action action) where T : Exception
    { try { action(); } catch (T) { return; } throw new InvalidOperationException("Expected " + typeof(T).Name); }
    private static KeycloakCapabilityPolicy Policy(KeycloakSupportConfiguration config) => new(Server, config, KeycloakServerCapabilities.FromServerInfo(CapabilityContracts.ServerInfo()));
    private static KeycloakVerificationProfile Profile(KeycloakRuntimeProfile runtime, KeycloakAdminRoute route = KeycloakAdminRoute.FgapV2Stable, string rid = "linux-musl-x64")
        => new(runtime + "/" + route + "/" + rid, route, runtime, runtime == KeycloakRuntimeProfile.Managed ? null : rid,
            KeycloakVerification.Contract | (runtime == KeycloakRuntimeProfile.Managed ? KeycloakVerification.Managed : KeycloakVerification.NativeAot),
            new string('a', 64), "test-evidence", new string('b', 64));
    private static KeycloakEndpointCapability Endpoint(KeycloakVerificationProfile[] profiles, KeycloakFeatureStage stage = KeycloakFeatureStage.Experimental)
        => new("ClientTypes.GetClientTypesAsync", "GET", "/admin/realms/{realm}/client-types", Feature, stage,
            KeycloakImplementationStatus.Implemented, KeycloakSupportStatus.Supported,
            profiles.Aggregate(KeycloakVerification.Contract, (v, p) => v | p.Verification), ["ADMIN_API", "CLIENT_TYPES"], "test-evidence",
            [KeycloakAdminRoute.FgapV2Stable, KeycloakAdminRoute.FgapV1Compatibility], profiles);

    public static void Configuration()
    {
        string json = $$"""{"schemaVersion":2,"serverVersion":"{{KeycloakTarget.Version}}","route":"fgap-v2-stable","runtimeProfile":"Managed","runtimeIdentifier":null,"previewCapabilities":[],"experimentalCapabilities":["{{Feature}}"],"disabledCapabilities":[]}""";
        var config = KeycloakSupportConfiguration.Parse(json);
        Check(config.UsesSupportProfiles && config.RuntimeProfile == KeycloakRuntimeProfile.Managed && config.RuntimeIdentifier is null && config.ExperimentalCapabilities.SetEquals([Feature]));
        Check(!new KeycloakSupportConfiguration(KeycloakTarget.Version).UsesSupportProfiles);
        var env = new Dictionary<string, string?> { ["KEYCLOAK_ADMIN_RUNTIME_PROFILE"] = "Portable", ["KEYCLOAK_ADMIN_RUNTIME_IDENTIFIER"] = "linux-musl-x64",
            ["KEYCLOAK_ADMIN_PREVIEW_CAPABILITIES"] = "KeycloakSdk.Oid4vcVci", ["KEYCLOAK_ADMIN_EXPERIMENTAL_CAPABILITIES"] = "KeycloakSdk.Ssf", ["KEYCLOAK_ADMIN_DISABLED_CAPABILITIES"] = Feature };
        var overridden = KeycloakSupportConfiguration.Parse(json, name => env.GetValueOrDefault(name));
        Check(overridden.RuntimeProfile == KeycloakRuntimeProfile.Portable && overridden.RuntimeIdentifier == "linux-musl-x64"
            && overridden.PreviewCapabilities.Contains("KeycloakSdk.Oid4vcVci") && overridden.ExperimentalCapabilities.Contains("KeycloakSdk.Ssf") && overridden.DisabledCapabilities.Contains(Feature));
        Check(KeycloakSupportConfiguration.Parse(json.Replace("Managed", "NativeAot", StringComparison.Ordinal)).RuntimeIdentifier == RuntimeInformation.RuntimeIdentifier);
        Reject<JsonException>(() => KeycloakSupportConfiguration.Parse(json.Replace("Managed", "guessed", StringComparison.Ordinal)));
        Reject<JsonException>(() => KeycloakSupportConfiguration.Parse(json.Replace("\"disabledCapabilities\":[]", "\"disabledCapabilities\":[],\"unknown\":true", StringComparison.Ordinal)));
        Reject<JsonException>(() => KeycloakSupportConfiguration.Parse(json.Replace("\"runtimeIdentifier\":null,", "", StringComparison.Ordinal)));
        Reject<JsonException>(() => KeycloakSupportConfiguration.Parse("[]"));
        Reject<JsonException>(() => KeycloakSupportConfiguration.Parse(json.Replace("\"schemaVersion\":2", "\"schemaVersion\":99", StringComparison.Ordinal)));
        Reject<JsonException>(() => KeycloakSupportConfiguration.Parse(json.Replace("\"route\":\"fgap-v2-stable\"", "\"route\":\"fgap-v2-stable\",\"route\":\"fgap-v2-stable\"", StringComparison.Ordinal)));
        Reject<ArgumentException>(() => new KeycloakSupportConfiguration(KeycloakTarget.Version, KeycloakRuntimeProfile.Managed, runtimeIdentifier: "linux-x64"));
        Reject<ArgumentException>(() => new KeycloakSupportConfiguration(KeycloakTarget.Version, KeycloakRuntimeProfile.NativeAot, runtimeIdentifier: "bad/rid"));
        Reject<ArgumentException>(() => new KeycloakSupportConfiguration(KeycloakTarget.Version, KeycloakRuntimeProfile.NativeAot, runtimeIdentifier: ""));
        Reject<ArgumentException>(() => new KeycloakSupportConfiguration(KeycloakTarget.Version, KeycloakRuntimeProfile.Managed, experimentalCapabilities: [Feature, Feature]));
        Reject<ArgumentException>(() => new KeycloakSupportConfiguration(KeycloakTarget.Version, KeycloakRuntimeProfile.Managed, previewCapabilities: [" "]));
        Reject<ArgumentOutOfRangeException>(() => new KeycloakSupportConfiguration(KeycloakTarget.Version, (KeycloakRuntimeProfile)99));
        Reject<ArgumentException>(() => Policy(new(KeycloakTarget.Version, KeycloakRuntimeProfile.Managed, previewCapabilities: [Feature])));
        Reject<ArgumentException>(() => Policy(new(KeycloakTarget.Version, KeycloakRuntimeProfile.Managed, experimentalCapabilities: ["typo"])));
    }

    public static void RuntimeMatrix()
    {
        var managed = Profile(KeycloakRuntimeProfile.Managed);
        var native = Profile(KeycloakRuntimeProfile.NativeAot);
        var endpoint = Endpoint([managed]);
        var config = new KeycloakSupportConfiguration(KeycloakTarget.Version, KeycloakRuntimeProfile.Managed, experimentalCapabilities: [Feature]);
        Check(Policy(config).EvaluateEndpoint(endpoint).IsAllowed);
        Check(Policy(new(KeycloakTarget.Version, KeycloakRuntimeProfile.Managed)).EvaluateEndpoint(endpoint).Reason == KeycloakCapabilityReason.StageNotAllowed);
        Check(Policy(new(KeycloakTarget.Version, KeycloakRuntimeProfile.NativeAot, runtimeIdentifier: "linux-musl-x64", experimentalCapabilities: [Feature])).EvaluateEndpoint(endpoint).Reason == KeycloakCapabilityReason.InsufficientVerification);
        Check(Policy(new(KeycloakTarget.Version, allowExperimental: true)).EvaluateEndpoint(endpoint).Reason == KeycloakCapabilityReason.InsufficientVerification);
        var both = Endpoint([managed, native]);
        Check(Policy(new(KeycloakTarget.Version, KeycloakRuntimeProfile.Portable, runtimeIdentifier: "linux-musl-x64", experimentalCapabilities: [Feature])).EvaluateEndpoint(both).IsAllowed);
        Check(Policy(new(KeycloakTarget.Version, KeycloakRuntimeProfile.NativeAot, runtimeIdentifier: "win-x64", experimentalCapabilities: [Feature])).EvaluateEndpoint(both).Reason == KeycloakCapabilityReason.InsufficientVerification);
        Check(Policy(new(KeycloakTarget.Version, KeycloakRuntimeProfile.Managed, route: KeycloakAdminRoute.FgapV1Compatibility, experimentalCapabilities: [Feature])).EvaluateEndpoint(both).Reason == KeycloakCapabilityReason.InsufficientVerification);
        Check(Policy(new(KeycloakTarget.Version, allowExperimental: true)).EvaluateEndpoint(Endpoint([managed, Profile(KeycloakRuntimeProfile.NativeAot, KeycloakAdminRoute.FgapV1Compatibility)])).Reason == KeycloakCapabilityReason.InsufficientVerification);
        Check(Policy(new(KeycloakTarget.Version, allowExperimental: true)).EvaluateEndpoint(Endpoint([native, Profile(KeycloakRuntimeProfile.Managed, KeycloakAdminRoute.FgapV1Compatibility)])).Reason == KeycloakCapabilityReason.InsufficientVerification);
        Check(Policy(new(KeycloakTarget.Version, KeycloakRuntimeProfile.NativeAot, runtimeIdentifier: "linux-musl-x64", experimentalCapabilities: [Feature])).EvaluateEndpoint(both).IsAllowed);
        Check(Policy(new(KeycloakTarget.Version, KeycloakRuntimeProfile.Portable, runtimeIdentifier: "linux-musl-x64", experimentalCapabilities: [Feature])).EvaluateEndpoint(Endpoint([native])).Reason == KeycloakCapabilityReason.InsufficientVerification);
        var incomplete = new KeycloakVerificationProfile("incomplete", KeycloakAdminRoute.FgapV2Stable, KeycloakRuntimeProfile.Managed, null, KeycloakVerification.Contract, new string('a',64), "proof", new string('b',64));
        Check(Policy(config).EvaluateEndpoint(Endpoint([incomplete])).Reason == KeycloakCapabilityReason.InsufficientVerification);
        Check(Policy(config).EvaluateEndpoint(Endpoint([managed], KeycloakFeatureStage.Removed)).Reason == KeycloakCapabilityReason.StageNotAllowed);
        // Upstream Preview remains Preview after managed verification; an experimental opt-in cannot authorize it.
        Check(Policy(config).EvaluateEndpoint(Endpoint([managed], KeycloakFeatureStage.Preview)).Reason == KeycloakCapabilityReason.StageNotAllowed);
        Check(endpoint.Stage == KeycloakFeatureStage.Experimental && endpoint.Verification != All);
        var activeRuntime = RuntimeFeature.IsDynamicCodeSupported ? KeycloakRuntimeProfile.Managed : KeycloakRuntimeProfile.NativeAot;
        var opposite = activeRuntime == KeycloakRuntimeProfile.Managed ? KeycloakRuntimeProfile.NativeAot : KeycloakRuntimeProfile.Managed;
        var target = new Uri(Server, "admin/serverinfo");
        Check(Policy(new(KeycloakTarget.Version, opposite)).Evaluate(HttpMethod.Get, target).Reason == KeycloakCapabilityReason.RuntimeMismatch);
        if (!RuntimeFeature.IsDynamicCodeSupported)
            Check(Policy(new(KeycloakTarget.Version, activeRuntime, runtimeIdentifier: "other-rid")).Evaluate(HttpMethod.Get, target).Reason == KeycloakCapabilityReason.RuntimeMismatch);
        var release = KeycloakCapabilityCatalog.Current;
        Check(release.SchemaVersion == 2 && release.VerificationProfiles.Count >= 4);
        Check(new KeycloakReleaseCapabilities("legacy", "source", []).SchemaVersion == 1);
        foreach (var p in release.VerificationProfiles) Check(p.SourceFingerprint.Length == 64 && p.Evidence.Length > 0 && p.EvidenceSha256.Length == 64);
        Check(KeycloakCapabilityPolicy.MatchesRuntime(KeycloakRuntimeProfile.Managed, null, true, "win-x64"));
        Check(!KeycloakCapabilityPolicy.MatchesRuntime(KeycloakRuntimeProfile.Managed, null, false, "linux-musl-x64"));
        Check(KeycloakCapabilityPolicy.MatchesRuntime(KeycloakRuntimeProfile.NativeAot, "linux-musl-x64", false, "linux-musl-x64"));
        Check(!KeycloakCapabilityPolicy.MatchesRuntime(KeycloakRuntimeProfile.NativeAot, "linux-musl-x64", true, "linux-musl-x64"));
        Check(!KeycloakCapabilityPolicy.MatchesRuntime(KeycloakRuntimeProfile.NativeAot, "win-x64", false, "linux-musl-x64"));
        Check(KeycloakCapabilityPolicy.MatchesRuntime(KeycloakRuntimeProfile.Portable, "linux-musl-x64", true, "win-x64"));
        Check(KeycloakCapabilityPolicy.MatchesRuntime(KeycloakRuntimeProfile.Portable, "linux-musl-x64", false, "linux-musl-x64"));
        Check(!KeycloakCapabilityPolicy.MatchesRuntime(KeycloakRuntimeProfile.Portable, "win-x64", false, "linux-musl-x64"));
        Check(release.Endpoints.Where(e => e.Support == KeycloakSupportStatus.NotSupported).All(e => e.SupportProfiles.Count == 0));
        foreach (var e in release.Endpoints.Where(e => e.Stage == KeycloakFeatureStage.Stable))
            Check(Policy(new(KeycloakTarget.Version, KeycloakRuntimeProfile.Managed)).EvaluateEndpoint(e).IsAllowed);
    }

    public static void CatalogValidation()
    {
        string profile = $$"""{"id":"managed","route":"FgapV2Stable","runtime":"Managed","runtimeIdentifier":null,"verification":"Contract, Managed","sourceFingerprint":"{{new string('a',64)}}","evidence":"proof.json","evidenceSha256":"{{new string('b',64)}}"}""";
        string endpoint = """{"operation":"Example.ReadAsync","method":"GET","path":"/admin/example","featureId":"KeycloakSdk.AdminApi","stage":"Stable","implementation":"Implemented","support":"Supported","routes":["FgapV2Stable"],"verification":"Contract, Managed","requiredServerFeatures":["ADMIN_API"],"evidence":"proof.json","supportProfiles":["managed"]}""";
        string Json(string p, string e, int schema = 2) => $$"""{"schemaVersion":{{schema}},"serverVersion":"26.8.1","sourceCommit":"test","verificationProfiles":[{{p}}],"endpoints":[{{e}}]}""";
        KeycloakReleaseCapabilities Read(string json) { using var d = JsonDocument.Parse(json); return KeycloakCapabilityCatalog.Read(d.RootElement); }
        Check(Read(Json(profile, endpoint)).Endpoints.Single().SupportProfiles.Single().Runtime == KeycloakRuntimeProfile.Managed);
        Check(Read(Json(profile, endpoint, 1)).Endpoints.Single().SupportProfiles.Count == 0);
        var unverified = Read(Json(profile, endpoint.Replace("\"support\":\"Supported\"", "\"support\":\"NotSupported\"", StringComparison.Ordinal)
            .Replace("[\"managed\"]", "[]", StringComparison.Ordinal))).Endpoints.Single();
        Check(unverified.Support == KeycloakSupportStatus.NotSupported && unverified.SupportProfiles.Count == 0);
        Check(Policy(new(KeycloakTarget.Version)).EvaluateEndpoint(unverified).Reason == KeycloakCapabilityReason.NotSupported);
        Reject<InvalidDataException>(() => Read(Json(profile, endpoint, 9)));
        Reject<InvalidDataException>(() => Read(Json(profile + "," + profile, endpoint)));
        foreach (var bad in new[] {
            profile.Replace("\"Managed\"", "\"Portable\"", StringComparison.Ordinal),
            profile.Replace("FgapV2Stable", "99", StringComparison.Ordinal),
            profile.Replace("\"runtimeIdentifier\":null", "\"runtimeIdentifier\":\"bad\"", StringComparison.Ordinal),
            profile.Replace("Contract, Managed", "Contract", StringComparison.Ordinal),
            profile.Replace("Contract, Managed", "11", StringComparison.Ordinal),
            profile.Replace("\"runtime\":\"Managed\"", "\"runtime\":\"NativeAot\"", StringComparison.Ordinal).Replace("Contract, Managed", "Contract, NativeAot", StringComparison.Ordinal),
            profile.Replace("\"runtime\":\"Managed\"", "\"runtime\":\"NativeAot\"", StringComparison.Ordinal).Replace("Contract, Managed", "Contract, NativeAot", StringComparison.Ordinal).Replace("\"runtimeIdentifier\":null", "\"runtimeIdentifier\":\"../bad\"", StringComparison.Ordinal),
            profile.Replace(new string('a',64), "bad", StringComparison.Ordinal),
            profile.Replace(new string('a',64), new string('g',64), StringComparison.Ordinal),
            profile.Replace(new string('b',64), "bad", StringComparison.Ordinal),
            profile.Replace("proof.json", "", StringComparison.Ordinal),
            profile.Replace("\"id\":\"managed\"", "\"id\":\"\"", StringComparison.Ordinal) })
            Reject<InvalidDataException>(() => Read(Json(bad, endpoint)));
        foreach (var bad in new[] {
            endpoint.Replace("[\"managed\"]", "[\"unknown\"]", StringComparison.Ordinal),
            endpoint.Replace("[\"managed\"]", "[\"managed\",\"managed\"]", StringComparison.Ordinal),
            endpoint.Replace("FgapV2Stable", "FgapV1Compatibility", StringComparison.Ordinal),
            endpoint.Replace("Contract, Managed", "Contract", StringComparison.Ordinal),
            endpoint.Replace("\"support\":\"Supported\"", "\"support\":\"NotSupported\"", StringComparison.Ordinal),
            endpoint.Replace("[\"managed\"]", "[]", StringComparison.Ordinal) })
            Reject<InvalidDataException>(() => Read(Json(profile, bad)));
    }

    public static async Task GatesAsync()
    {
        var flags = new KeycloakFeatureSnapshotGate(new Dictionary<string, bool> { [KeycloakFeatureGatePolicy.AdminApiFeature] = true, ["KeycloakSdk.Organizations"] = true });
        var policy = new KeycloakFeatureGatePolicy(Policy(new(KeycloakTarget.Version)), flags);
        var target = new Uri(Server, "admin/realms/demo/organizations");
        Check((await policy.EvaluateAsync(HttpMethod.Get, target)).IsAllowed);
        flags.Replace(new Dictionary<string, bool> { [KeycloakFeatureGatePolicy.AdminApiFeature] = true });
        Check((await policy.EvaluateAsync(HttpMethod.Get, target)).Reason == KeycloakCapabilityReason.DisabledByHost);
        flags.Replace([]);
        Check(!(await policy.EvaluateAsync(HttpMethod.Get, new Uri(Server, "admin/serverinfo"))).IsAllowed);
        Reject<ArgumentException>(() => flags.Replace([new("duplicate", true), new("duplicate", false)]));
        Check(!await flags.IsEnabledAsync("duplicate"));
        Reject<ArgumentException>(() => flags.Replace([new(" ", true)]));
        Reject<ArgumentNullException>(() => flags.Replace(null!));
        Reject<ArgumentNullException>(() => new KeycloakFeatureGatePolicy(null!, flags));
        Reject<ArgumentNullException>(() => new KeycloakFeatureGatePolicy(Policy(new(KeycloakTarget.Version)), null!));
        using var cancellation = new CancellationTokenSource(); cancellation.Cancel();
        try { await flags.IsEnabledAsync("feature", cancellation.Token); throw new Exception("Expected cancellation"); } catch (OperationCanceledException) { }
        var gate = new CountingGate();
        var composed = new KeycloakFeatureGatePolicy(Policy(new(KeycloakTarget.Version)), gate);
        Check((await composed.EvaluateAsync(HttpMethod.Get, new Uri(Server, "admin/unknown"))).Reason == KeycloakCapabilityReason.UnknownEndpoint && gate.Calls == 0);
        await composed.EnsureAllowedAsync(HttpMethod.Get, target, null, CancellationToken.None);
        Check(gate.Calls == 2);
        gate.Enabled = false;
        try { await composed.EnsureAllowedAsync(HttpMethod.Get, target, null, CancellationToken.None); throw new Exception("Expected flag denial"); }
        catch (KeycloakCapabilityDeniedException e) { Check(e.Decision.Reason == KeycloakCapabilityReason.DisabledByHost); }

        using var handler = new Handler(); using var http = new HttpClient(handler);
        var config = new KeycloakSupportConfiguration(KeycloakTarget.Version);
        var client = await KeycloakSupportedClient.CreateAsync(http, Server, new StaticAccessTokenProvider("test"), config,
            new KeycloakFeatureSnapshotGate(new Dictionary<string, bool> { [KeycloakFeatureGatePolicy.AdminApiFeature] = true }));
        await client.Users.GetUsersAsync("demo"); Check(handler.Calls == 2);
        try { await KeycloakSupportedClient.CreateAsync(http, Server, new StaticAccessTokenProvider("test"), config, new KeycloakFeatureSnapshotGate([])); throw new Exception("Expected bootstrap flag denial"); }
        catch (KeycloakCapabilityDeniedException) { Check(handler.Calls == 3); }
        Reject<ArgumentNullException>(() => KeycloakSupportedClient.CreateAsync(http, Server, new StaticAccessTokenProvider("test"), config, (IKeycloakFeatureGate)null!));
    }

    public static async Task RunAsync() { Configuration(); RuntimeMatrix(); CatalogValidation(); await GatesAsync(); }
    private sealed class CountingGate : IKeycloakFeatureGate
    {
        public int Calls; public bool Enabled = true;
        public ValueTask<bool> IsEnabledAsync(string featureId, CancellationToken cancellationToken = default) { cancellationToken.ThrowIfCancellationRequested(); Calls++; return ValueTask.FromResult(Enabled); }
    }
    private sealed class Handler : HttpMessageHandler
    {
        public int Calls;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++; cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = request.RequestUri!.AbsolutePath.EndsWith("serverinfo", StringComparison.Ordinal)
                ? new ByteArrayContent(CapabilityContracts.ServerInfo()) : new StringContent("[]") });
        }
    }
}
