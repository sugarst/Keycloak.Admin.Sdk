using System.Text.Json.Nodes;
using Microsoft.VisualStudio.TestTools.UnitTesting;

[TestClass]
public sealed class ApplicationAcceptanceTests
{
    [TestMethod]
    public void CounterpartCodeAndImmutableImagesAreBoundToCurrentBusinessEvidence()
    {
        using var fixture = new Fixture(); var plan = fixture.Plan(); plan["requiredCounterpartImages"] = new JsonArray("kerberos"); fixture.WritePlan(plan);
        string directory = Path.Combine(fixture.Root, "local/keycloak/kerberos"); Directory.CreateDirectory(directory);
        foreach (string name in new[] { "Dockerfile", "start.sh", "ticket.py" }) File.WriteAllText(Path.Combine(directory, name), "original");
        var report = fixture.Report(); ApplicationAcceptance.Validate(fixture.Root, report);
        foreach (JsonNode? invalid in new JsonNode?[] { null, new JsonArray(), new JsonObject(), new JsonObject { ["kerberos"] = 1 }, new JsonObject { ["kerberos"] = "mutable:tag" }, new JsonObject { ["kerberos"] = "sha256:invalid" } })
        { var bad = report.DeepClone().AsObject(); bad["counterpartImages"] = invalid; Assert.Throws<InvalidDataException>(() => ApplicationAcceptance.Validate(fixture.Root, bad)); }
        ApplicationAcceptance.Promote(fixture.Root, fixture.SaveReport());
        foreach (string name in new[] { "Dockerfile", "start.sh", "ticket.py" })
        {
            File.WriteAllText(Path.Combine(directory, name), "changed"); Assert.AreEqual(0, ApplicationAcceptance.CurrentProfiles(fixture.Root).Count);
            File.WriteAllText(Path.Combine(directory, name), "original"); Assert.AreEqual(1, ApplicationAcceptance.CurrentProfiles(fixture.Root).Count);
        }
    }
    [TestMethod]
    public void EvidencePromotionIsScopedImmutableAndCannotSurviveChangedInputs()
    {
        using var fixture = new Fixture();
        string before = LiveEvidence.ValidationFingerprint(fixture.Root);
        ApplicationAcceptance.Promote(fixture.Root, fixture.SaveReport());
        Assert.AreEqual(before, LiveEvidence.ValidationFingerprint(fixture.Root), "Derived profiles must not introduce circular fingerprints.");
        var result = PlatformCoverage.Generate(fixture.Root);
        var catalog = JsonNode.Parse(result.Json)!;
        var authzen = catalog["applicationCapabilities"]!.AsArray().Single(c => c!["id"]!.GetValue<string>() == "authzen")!;
        Assert.AreEqual("Supported", authzen["support"]!.GetValue<string>());
        Assert.AreEqual(1, authzen["verificationProfiles"]!.AsArray().Count);
        Assert.IsFalse(result.Complete);
        ApplicationAcceptance.Promote(fixture.Root, fixture.SaveReport("native-aot"));
        Assert.AreEqual(2, ApplicationAcceptance.CurrentProfiles(fixture.Root).Count);
        File.WriteAllText(Path.Combine(fixture.Root, "contracts/platform-capabilities.json"), result.Json);
        Assert.AreEqual(before, LiveEvidence.ValidationFingerprint(fixture.Root));
        File.WriteAllText(Path.Combine(fixture.Root, "tests/Keycloak.Admin.Sdk.Protocols.Tests/Changed.cs"), "// changed security test");
        Assert.AreEqual(0, ApplicationAcceptance.CurrentProfiles(fixture.Root).Count);
        Assert.IsFalse(PlatformCoverage.Generate(fixture.Root).Complete);
    }

    [TestMethod]
    public void ForgedIncompleteOrWrongRuntimeReportsCannotPromote()
    {
        using var fixture = new Fixture();
        var original = fixture.Report();
        foreach (Action<JsonObject> corrupt in new Action<JsonObject>[]
        {
            r => r["schemaVersion"] = 2, r => r["completed"] = false, r => r["promoted"] = true,
            r => r["serverVersion"] = "future", r => r["sourceCommit"] = "unknown", r => r["inputFingerprint"] = "old",
            r => r["runtime"] = "other", r => r["runtimeIdentifier"] = "linux-x64", r => r["scope"] = "all supported",
            r => r["executableSha256"] = "bad", r => r["serverInfoSha256"] = new string('A', 64),
            r => r["checks"]!.AsArray().RemoveAt(0), r => r["checks"]!.AsArray().Add(r["checks"]![0]!.DeepClone()),
            r => r["checks"]![0] = "unexpected", r => r["checks"]![0] = " ", r => r.Remove("checks"),
            r => r.Remove("serverFeatures"), r => r["serverFeatures"]![0]!["enabled"] = false
            , r => r["serverProfile"] = "unknown"
        })
        {
            var report = original.DeepClone().AsObject(); corrupt(report);
            Assert.Throws<InvalidDataException>(() => ApplicationAcceptance.Validate(fixture.Root, report));
        }
        var native = fixture.Report("native-aot"); native["runtimeIdentifier"] = "win-x64";
        Assert.Throws<InvalidDataException>(() => ApplicationAcceptance.Validate(fixture.Root, native));
        string path = fixture.SaveReport(); File.AppendAllText(fixture.Binary("managed"), "changed");
        Assert.Throws<InvalidDataException>(() => ApplicationAcceptance.Promote(fixture.Root, path));
    }

    [TestMethod]
    public void MutuallyExclusiveServerProfilesCoexistAndCannotBorrowEachOthersChecks()
    {
        using var fixture = new Fixture();
        ApplicationAcceptance.Promote(fixture.Root, fixture.SaveReport());
        string legacyPath = Path.Combine(fixture.Root, "managed-legacy.json");
        var report = fixture.Report(legacy: true); File.WriteAllText(legacyPath, report.ToJsonString());
        ApplicationAcceptance.Promote(fixture.Root, legacyPath);
        Assert.AreEqual(2, ApplicationAcceptance.CurrentProfiles(fixture.Root).Count);
        Assert.AreEqual(1, ApplicationAcceptance.CurrentProfiles(fixture.Root).Count(p => p!["serverProfile"]!.GetValue<string>() == "legacy"));
        ApplicationAcceptance.Promote(fixture.Root, fixture.SaveReport());
        Assert.AreEqual(2, ApplicationAcceptance.CurrentProfiles(fixture.Root).Count);
        report["serverProfile"] = "standard";
        Assert.Throws<InvalidDataException>(() => ApplicationAcceptance.Validate(fixture.Root, report));
    }

    [TestMethod]
    public void CompleteGateRequiresAllCriteriaAndAdminOperationsRatherThanAHardcodedFalse()
    {
        using var fixture = new Fixture();
        // Controlled synthetic unit fixture only; real production plans still contain the remaining unimplemented families.
        var rules = ApplicationAcceptance.Read(Path.Combine(fixture.Root, "contracts/platform-coverage-rules.json"));
        var plan = fixture.Plan(); var capabilities = new JsonArray();
        foreach (var item in rules["applicationCapabilities"]!.AsArray())
        {
            item!["implementation"] = "Implemented";
            capabilities.Add(new JsonObject { ["id"] = item["id"]!.DeepClone(), ["requiredServerFeatures"] = plan["requiredServerFeatures"]!.DeepClone(), ["criteria"] = new JsonArray(item["acceptanceCriteria"]!.AsArray().Select(c => (JsonNode)new JsonObject
                { ["criterion"] = c!.DeepClone(), ["checks"] = new JsonArray(plan["expectedChecks"]![0]!.DeepClone()) }).ToArray()) });
        }
        plan["capabilities"] = capabilities;
        File.WriteAllText(Path.Combine(fixture.Root, "contracts/platform-coverage-rules.json"), rules.ToJsonString()); fixture.WritePlan(plan);
        var admin = ApplicationAcceptance.Read(Path.Combine(fixture.Root, "contracts/capabilities.json"));
        foreach (var endpoint in admin["endpoints"]!.AsArray())
            if (endpoint!["support"]!.GetValue<string>() != "Compatibility") endpoint["support"] = "Supported";
        File.WriteAllText(Path.Combine(fixture.Root, "contracts/capabilities.json"), admin.ToJsonString());
        ApplicationAcceptance.Promote(fixture.Root, fixture.SaveReport());
        Assert.IsTrue(PlatformCoverage.Generate(fixture.Root).Complete);
        plan["capabilities"]![0]!["criteria"]!.AsArray().RemoveAt(0); fixture.WritePlan(plan);
        ApplicationAcceptance.Promote(fixture.Root, fixture.SaveReport());
        Assert.IsFalse(PlatformCoverage.Generate(fixture.Root).Complete);
    }

    [TestMethod]
    public void ManagedHostChecksCannotPromoteANativeCapabilityOrBeOmittedFromManagedEvidence()
    {
        using var fixture = new Fixture(); var plan = fixture.Plan();
        plan["runtimeChecks"] = new JsonObject { ["managed"] = new JsonArray("managed-host-proof") };
        var capability = plan["capabilities"]![0]!.DeepClone(); capability["runtime"] = "managed";
        capability["criteria"]![0]!["checks"] = new JsonArray("managed-host-proof"); plan["capabilities"] = new JsonArray(capability); fixture.WritePlan(plan);
        var incomplete = fixture.Report(); incomplete["checks"]!.AsArray().RemoveAt(incomplete["checks"]!.AsArray().Count - 1);
        Assert.Throws<InvalidDataException>(() => ApplicationAcceptance.Validate(fixture.Root, incomplete));
        ApplicationAcceptance.Promote(fixture.Root, fixture.SaveReport()); ApplicationAcceptance.Promote(fixture.Root, fixture.SaveReport("native-aot"));
        var profiles = ApplicationAcceptance.CurrentProfiles(fixture.Root);
        Assert.AreEqual(1, profiles.Single(p => p!["runtime"]!.GetValue<string>() == "managed")!["capabilities"]!.AsArray().Count);
        Assert.AreEqual(0, profiles.Single(p => p!["runtime"]!.GetValue<string>() == "native-aot")!["capabilities"]!.AsArray().Count);
        plan["runtimeChecks"]!["unknown"] = new JsonArray("unexpected"); fixture.WritePlan(plan);
        Assert.Throws<InvalidDataException>(() => ApplicationAcceptance.Validate(fixture.Root, fixture.Report()));
        plan["runtimeChecks"]!.AsObject().Remove("unknown"); plan["runtimeChecks"]!["native-aot"] = new JsonArray("managed-host-proof"); fixture.WritePlan(plan);
        Assert.Throws<InvalidDataException>(() => ApplicationAcceptance.Validate(fixture.Root, fixture.Report()));
        plan["runtimeChecks"]!.AsObject().Remove("native-aot"); plan["capabilities"]![0]!["runtime"] = "unknown"; fixture.WritePlan(plan);
        Assert.Throws<InvalidDataException>(() => ApplicationAcceptance.Validate(fixture.Root, fixture.Report()));
    }

    [TestMethod]
    public void UnknownCriteriaAndTamperedImmutableEvidenceAreRejected()
    {
        using var fixture = new Fixture(); var plan = fixture.Plan();
        plan["capabilities"]![0]!["criteria"]![0]!["criterion"] = "unreviewed"; fixture.WritePlan(plan);
        Assert.Throws<InvalidDataException>(() => ApplicationAcceptance.Validate(fixture.Root, fixture.Report()));
        plan["capabilities"]!.AsArray().Clear(); fixture.WritePlan(plan);
        ApplicationAcceptance.Promote(fixture.Root, fixture.SaveReport());
        var profile = ApplicationAcceptance.CurrentProfiles(fixture.Root)[0]!;
        File.AppendAllText(Path.Combine(fixture.Root, profile["evidence"]!.GetValue<string>()), " ");
        Assert.Throws<InvalidDataException>(() => ApplicationAcceptance.CurrentProfiles(fixture.Root));
    }

    private sealed class Fixture : IDisposable
    {
        internal readonly string Root = Path.Combine(Path.GetTempPath(), "keycloak-application-tests-" + Guid.NewGuid().ToString("N"));
        internal Fixture()
        {
            var repo = new DirectoryInfo(AppContext.BaseDirectory); while (repo is not null && !File.Exists(Path.Combine(repo.FullName, "Target.props"))) repo = repo.Parent;
            Assert.IsNotNull(repo);
            foreach (string directory in new[] { "src", "tests/Keycloak.Admin.Sdk.IntegrationTests", "tests/Keycloak.Admin.Sdk.Protocols.Tests", "tests/Keycloak.Admin.Sdk.Hosting.Tests", "tests/Keycloak.Admin.Sdk.AotSmoke", "local/keycloak", "tools/Shared", "contracts" }) Directory.CreateDirectory(Path.Combine(Root, directory));
            foreach (string file in new[] { "global.json", "Directory.Build.props", "Keycloak.Admin.Sdk.slnx", "Target.props", "tools/Shared/TargetBaseline.cs", "tools/Shared/ScriptSupport.cs", "contracts/source-files.sha256", "tests/Keycloak.Admin.Sdk.AotSmoke/Dockerfile" }) File.Copy(Path.Combine(repo.FullName, file), Path.Combine(Root, file));
            foreach (string file in Directory.EnumerateFiles(Path.Combine(repo.FullName, "contracts"), "*.json")) File.Copy(file, Path.Combine(Root, "contracts", Path.GetFileName(file)));
            var baseline = TargetBaseline.Load(Root); string destination = Path.Combine(baseline.Source(Root), PlatformCoverage.ProfilePath);
            Directory.CreateDirectory(Path.GetDirectoryName(destination)!); File.Copy(Path.Combine(baseline.Source(repo.FullName), PlatformCoverage.ProfilePath), destination);
            File.WriteAllText(Path.Combine(Root, "contracts/application-verification-profiles.json"), new JsonObject { ["schemaVersion"] = 1, ["serverVersion"] = baseline.Version, ["sourceCommit"] = baseline.Commit, ["profiles"] = new JsonArray() }.ToJsonString());
            foreach (string mode in new[] { "managed", "native-aot" }) { Directory.CreateDirectory(Path.GetDirectoryName(Binary(mode))!); File.WriteAllText(Binary(mode), "unit-test-controlled-binary"); }
        }
        internal string Binary(string mode) => Path.Combine(Root, mode == "managed" ? "tests/Keycloak.Admin.Sdk.IntegrationTests/bin/Release/net10.0/Keycloak.Admin.Sdk.IntegrationTests.dll" : "artifacts/aot/application-protocols/Keycloak.Admin.Sdk.IntegrationTests");
        internal JsonObject Plan() => ApplicationAcceptance.Read(Path.Combine(Root, "contracts/application-validation-plans.json"));
        internal void WritePlan(JsonObject plan) => File.WriteAllText(Path.Combine(Root, "contracts/application-validation-plans.json"), plan.ToJsonString());
        internal JsonObject Report(string mode = "managed", bool legacy = false)
        {
            var plan = legacy ? ApplicationAcceptance.Read(Path.Combine(Root, "contracts/application-legacy-validation-plans.json")) : Plan(); var baseline = TargetBaseline.Load(Root);
            var checks = plan["expectedChecks"]!.DeepClone().AsArray();
            foreach (var check in plan["runtimeChecks"]?[mode]?.AsArray() ?? new JsonArray()) checks.Add(check!.DeepClone());
            var enabledFeatures = plan["requiredServerFeatures"]!.AsArray().Select(f => f!.GetValue<string>()).Concat(plan["capabilities"]!.AsArray()
                .Where(c => c!["runtime"] is null || c["runtime"]!.GetValue<string>() == mode).SelectMany(c => c!["requiredServerFeatures"]!.AsArray().Select(f => f!.GetValue<string>())))
                .Distinct(StringComparer.Ordinal).ToArray();
            var counterparts = new JsonObject(); foreach (var id in plan["requiredCounterpartImages"]?.AsArray() ?? new JsonArray()) counterparts[id!.GetValue<string>()] = "sha256:" + new string('b', 64);
            return new() { ["schemaVersion"] = 1, ["completed"] = true, ["promoted"] = false, ["serverVersion"] = baseline.Version, ["sourceCommit"] = baseline.Commit,
                ["inputFingerprint"] = LiveEvidence.ValidationFingerprint(Root), ["runtime"] = mode, ["serverProfile"] = legacy ? "legacy" : "standard", ["runtimeIdentifier"] = mode == "managed" ? null : "linux-musl-x64",
                ["scope"] = "selected application workflows; promotion is determined independently", ["executableSha256"] = ApplicationAcceptance.Digest(Binary(mode)),
                ["serverInfoSha256"] = new string('a', 64), ["checks"] = checks, ["counterpartImages"] = counterparts,
                ["serverFeatures"] = new JsonArray(enabledFeatures.Select(f => (JsonNode)new JsonObject { ["name"] = f, ["enabled"] = true }).ToArray()) };
        }
        internal string SaveReport(string mode = "managed") { string path = Path.Combine(Root, mode + ".json"); File.WriteAllText(path, Report(mode).ToJsonString()); return path; }
        public void Dispose()
        {
            if (!Path.GetFullPath(Root).StartsWith(Path.GetFullPath(Path.GetTempPath()), StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Unexpected fixture path.");
            Directory.Delete(Root, true);
        }
    }
}
