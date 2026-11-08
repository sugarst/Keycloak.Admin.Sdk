using System.Text.Json.Nodes;
using System.Text.Json;
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Capabilities;
using Microsoft.VisualStudio.TestTools.UnitTesting;

[TestClass]
public sealed class FeatureAcceptanceTests
{
    [TestMethod]
    public void ResetCatalogRetainsUnverifiedOperationsWithoutSupportProfiles()
    {
        using var fixture = new Repository();
        using var document = JsonDocument.Parse(File.ReadAllText(Path.Combine(fixture.Root, "contracts/capabilities.json")));
        var catalog = KeycloakCapabilityCatalog.Read(document.RootElement);
        var unverified = catalog.Endpoints.Where(e => e.FeatureId is "KeycloakSdk.ClientTypes" or "KeycloakSdk.Ssf").ToArray();
        Assert.AreEqual(21, unverified.Length);
        Assert.IsTrue(unverified.All(e => e.Support == KeycloakSupportStatus.NotSupported
            && e.Verification == KeycloakVerification.Contract && e.SupportProfiles.Count == 0));
        var policy = new KeycloakCapabilityPolicy(new Uri("https://keycloak.invalid/auth/"),
            new(KeycloakTarget.Version, allowPreview: true, allowExperimental: true),
            KeycloakServerCapabilities.FromServerInfo(CapabilityContracts.ServerInfo()));
        foreach (var endpoint in unverified)
            Assert.AreEqual(KeycloakCapabilityReason.NotSupported, policy.EvaluateEndpoint(endpoint).Reason);
    }

    [TestMethod, DoNotParallelize]
    public async Task StaleValidationExecutableIsRejectedBeforeNetwork()
    {
        using var fixture = new Repository();
        string previous = Directory.GetCurrentDirectory();
        using var http = new HttpClient();
        try
        {
            Directory.SetCurrentDirectory(fixture.Root);
            await Assert.ThrowsAsync<InvalidDataException>(() => FeatureValidationRunner.RunAsync(http, new Uri("https://keycloak.invalid/"),
                new StaticAccessTokenProvider("test"), "client-types", false, CancellationToken.None));
        }
        finally { Directory.SetCurrentDirectory(previous); }
    }

    [TestMethod]
    public void CandidatePromotionIsLimitedToVerifiedOperationsRuntimeAndRoute()
    {
        using var fixture = new Repository();
        var report = fixture.Report();
        string reportPath = Path.Combine(fixture.Root, "candidate.json");
        File.WriteAllText(reportPath, CapabilityEvidence.Json(report));
        string fingerprint = LiveEvidence.ValidationFingerprint(fixture.Root);
        FeatureAcceptance.Promote(fixture.Root, reportPath);
        var catalog = JsonNode.Parse(File.ReadAllText(Path.Combine(fixture.Root, "contracts/capabilities.json")))!;
        var profiles = catalog["verificationProfiles"]!.AsArray();
        foreach (var operation in report["operations"]!.AsArray())
        {
            var endpoint = catalog["endpoints"]!.AsArray().Single(e => e!["operation"]!.GetValue<string>() == operation!["operation"]!.GetValue<string>())!;
            Assert.AreEqual("Experimental", endpoint["stage"]!.GetValue<string>());
            Assert.AreEqual("Contract, Managed", endpoint["verification"]!.GetValue<string>());
            Assert.AreEqual("Supported", endpoint["support"]!.GetValue<string>());
            Assert.AreEqual(1, endpoint["supportProfiles"]!.AsArray().Count);
            var profile = profiles.Single(p => p!["id"]!.GetValue<string>() == endpoint["supportProfiles"]![0]!.GetValue<string>())!;
            Assert.AreEqual("Managed", profile["runtime"]!.GetValue<string>());
            Assert.AreEqual("FgapV2Stable", profile["route"]!.GetValue<string>());
            Assert.IsTrue(File.Exists(Path.Combine(fixture.Root, profile["evidence"]!.GetValue<string>())));
        }
        Assert.IsTrue(catalog["endpoints"]!.AsArray().Where(e => e!["featureId"]!.GetValue<string>() == "KeycloakSdk.Ssf").All(e => e!["support"]!.GetValue<string>() == "NotSupported"));
        Assert.AreEqual(fingerprint, LiveEvidence.ValidationFingerprint(fixture.Root));
        // Repeating the same promotion does not add duplicate profiles or broaden support.
        FeatureAcceptance.Promote(fixture.Root, reportPath);
        Assert.AreEqual(profiles.Count, JsonNode.Parse(File.ReadAllText(Path.Combine(fixture.Root, "contracts/capabilities.json")))!["verificationProfiles"]!.AsArray().Count);
        Assert.Throws<InvalidDataException>(() => FeatureAcceptance.Validate(fixture.Root, report, true));
    }

    [TestMethod]
    public void CandidateValidationIsReadOnlyAndPromotionRequiresNewGuardedEvidence()
    {
        using var fixture = new Repository();
        string catalogPath = Path.Combine(fixture.Root, "contracts/capabilities.json");
        string rolloutPath = Path.Combine(fixture.Root, "contracts/platform-feature-flags.example.json");
        string catalogBefore = CapabilityEvidence.Digest(catalogPath), rolloutBefore = CapabilityEvidence.Digest(rolloutPath);
        var candidate = fixture.Report();
        FeatureAcceptance.Validate(fixture.Root, candidate, false);
        Assert.AreEqual(catalogBefore, CapabilityEvidence.Digest(catalogPath));
        Assert.AreEqual(rolloutBefore, CapabilityEvidence.Digest(rolloutPath));

        string reportPath = Path.Combine(fixture.Root, "candidate.json");
        File.WriteAllText(reportPath, CapabilityEvidence.Json(candidate));
        FeatureAcceptance.Promote(fixture.Root, reportPath);
        Assert.AreNotEqual(catalogBefore, CapabilityEvidence.Digest(catalogPath));
        Assert.AreEqual(rolloutBefore, CapabilityEvidence.Digest(rolloutPath), "Promotion must not open host feature flags.");
        Assert.Throws<InvalidDataException>(() => FeatureAcceptance.Validate(fixture.Root, candidate, true));

        var guarded = candidate.DeepClone().AsObject(); guarded["phase"] = "guarded";
        Assert.Throws<InvalidDataException>(() => FeatureAcceptance.Validate(fixture.Root, guarded, true));
        guarded["catalogSha256"] = CapabilityEvidence.Digest(catalogPath);
        FeatureAcceptance.Validate(fixture.Root, guarded, true);
    }

    [TestMethod]
    public void EvidenceRejectsStaleWrongScopeIncompleteAndUnguardedClaims()
    {
        using var fixture = new Repository();
        var report = fixture.Report();
        FeatureAcceptance.Validate(fixture.Root, report, false);
        var cases = new Action<JsonObject>[]
        {
            r => r["completed"] = false,
            r => r["validationFingerprint"] = "old-source",
            r => r["serverVersion"] = "future",
            r => r["keycloakSourceCommit"] = "wrong-commit",
            r => r["stage"] = "Stable",
            r => r["featureId"] = "KeycloakSdk.Ssf",
            r => r["mode"] = "guessed",
            r => r["mode"] = "native-aot",
            r => r["runtimeIdentifier"] = "linux-musl-x64",
            r => r["route"] = "guessed",
            r => r["phase"] = "release",
            r => r["executableSha256"] = "bad",
            r => r["nativePublished"] = true,
            r => r["operations"]!.AsArray().RemoveAt(0),
            r => r["operations"]!.AsArray().Add(r["operations"]![0]!.DeepClone()),
            r => r["operations"]![0]!["status"] = 403,
            r => r["operations"]![0]!["proof"] = "",
            r => r["operations"]![0]!["path"] = "/admin/unknown",
            r => r["serverInfo"]!["features"]![2]!["enabled"] = false,
            r => r["serverInfo"]!["features"]!.AsArray().Add(JsonNode.Parse("""{"name":"SSF","type":"EXPERIMENTAL","enabled":true}""")!)
        };
        foreach (var change in cases)
        {
            var copy = report.DeepClone().AsObject(); change(copy);
            Assert.Throws<InvalidDataException>(() => FeatureAcceptance.Validate(fixture.Root, copy, false));
        }
        var guarded = report.DeepClone().AsObject(); guarded["phase"] = "guarded";
        FeatureAcceptance.Validate(fixture.Root, guarded, true);
        guarded["flagDenialVerified"] = false;
        Assert.Throws<InvalidDataException>(() => FeatureAcceptance.Validate(fixture.Root, guarded, true));
        guarded["flagDenialVerified"] = true; guarded["catalogSha256"] = "old-catalog";
        Assert.Throws<InvalidDataException>(() => FeatureAcceptance.Validate(fixture.Root, guarded, true));
        Assert.Throws<InvalidDataException>(() => FeatureValidationPlan.Load(fixture.Root, "../outside"));
        Assert.Throws<InvalidDataException>(() => FeatureValidationPlan.Load(fixture.Root, "unknown"));
        File.AppendAllText(Path.Combine(fixture.Root, "tools/ScriptSupport.cs"), "// code changed");
        Assert.Throws<InvalidDataException>(() => FeatureAcceptance.Validate(fixture.Root, report, false));
    }

    private sealed class Repository : IDisposable
    {
        public string Root { get; } = Path.Combine(Path.GetTempPath(), "keycloak-feature-tests-" + Guid.NewGuid().ToString("N"));
        public Repository()
        {
            foreach (string directory in new[] { "src", "tests/Keycloak.Admin.Sdk.IntegrationTests", "tests/Keycloak.Admin.Sdk.Protocols.Tests", "tests/Keycloak.Admin.Sdk.Hosting.Tests", "tests/Keycloak.Admin.Sdk.AotSmoke", "local/keycloak", "tools", "contracts" })
                Directory.CreateDirectory(Path.Combine(Root, directory));
            string source = ScriptHost.RepositoryRoot();
            foreach (string path in new[] { "contracts/baseline.json", "contracts/admin-api-routes.json", "contracts/capabilities.json", "contracts/capability-rules.json", "contracts/feature-validation-plans.json", "contracts/platform-feature-flags.example.json" })
                File.Copy(Path.Combine(source, path), Path.Combine(Root, path));
            foreach (string path in new[] { "global.json", "Directory.Build.props", "Target.props", "tools/TargetBaseline.cs", "tools/ScriptSupport.cs", "contracts/source-files.sha256", "tests/Keycloak.Admin.Sdk.AotSmoke/Dockerfile" })
                File.WriteAllText(Path.Combine(Root, path), "test-input");
            // Begin with no Client Types or SSF verification, independently of the real catalog's current rollout.
            var catalog = JsonNode.Parse(File.ReadAllText(Path.Combine(Root, "contracts/capabilities.json")))!.AsObject();
            foreach (var e in catalog["endpoints"]!.AsArray().Where(e => e!["featureId"]!.GetValue<string>() is "KeycloakSdk.ClientTypes" or "KeycloakSdk.Ssf"))
            { e!["supportProfiles"] = new JsonArray(); e["support"] = "NotSupported"; e["verification"] = "Contract"; }
            File.WriteAllText(Path.Combine(Root, "contracts/capabilities.json"), CapabilityEvidence.Json(catalog));
        }
        public JsonObject Report()
        {
            var operations = new JsonArray();
            foreach (var e in Keycloak.Admin.Sdk.Capabilities.KeycloakCapabilityCatalog.Current.Endpoints.Where(e => e.FeatureId == "KeycloakSdk.ClientTypes"))
                operations.Add((JsonNode)new JsonObject { ["operation"] = e.Operation, ["method"] = e.Method, ["path"] = e.Path, ["status"] = 200, ["proof"] = "unit-test business proof" });
            return new JsonObject
            {
                ["schemaVersion"] = 1, ["plan"] = "client-types", ["featureId"] = "KeycloakSdk.ClientTypes", ["stage"] = "Experimental",
                ["completed"] = true, ["serverVersion"] = KeycloakTarget.Version, ["keycloakSourceCommit"] = KeycloakTarget.SourceCommit,
                ["validationFingerprint"] = LiveEvidence.ValidationFingerprint(Root), ["mode"] = "managed", ["nativePublished"] = false,
                ["runtimeIdentifier"] = null, ["route"] = "fgap-v2-stable", ["phase"] = "candidate", ["executableSha256"] = new string('a', 64),
                ["catalogSha256"] = CapabilityEvidence.Digest(Path.Combine(Root, "contracts/capabilities.json")),
                ["flagDenialVerified"] = true, ["gate"] = "platform-snapshot", ["operations"] = operations,
                ["serverInfo"] = JsonNode.Parse($$"""{"systemInfo":{"version":"{{KeycloakTarget.Version}}"},"profileInfo":{"disabledFeatures":["ADMIN_FINE_GRAINED_AUTHZ"]},"features":[{"name":"ADMIN_API","type":"DEFAULT","enabled":true},{"name":"ADMIN_FINE_GRAINED_AUTHZ_V2","type":"DEFAULT","enabled":true},{"name":"CLIENT_TYPES","type":"EXPERIMENTAL","enabled":true}]}""")
            };
        }
        public void Dispose()
        {
            if (!Path.GetFullPath(Root).StartsWith(Path.GetFullPath(Path.GetTempPath()), StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Unexpected fixture directory.");
            Directory.Delete(Root, recursive: true);
        }
    }
}
