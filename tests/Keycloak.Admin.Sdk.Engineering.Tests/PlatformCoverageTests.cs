using System.Text.Json.Nodes;
using Microsoft.VisualStudio.TestTools.UnitTesting;

[TestClass]
public sealed class PlatformCoverageTests
{
    [TestMethod]
    public void PinnedFeatureInventoryIsCompleteWithoutClaimingProtocolSupport()
    {
        using var fixture = new Fixture();
        var result = PlatformCoverage.Generate(fixture.Root);
        var catalog = JsonNode.Parse(result.Json)!;
        Assert.IsFalse(result.Complete);
        Assert.IsFalse(result.Json.Contains('\r'), "Generated snapshots must use deterministic LF on every platform.");
        Assert.IsFalse(catalog["complete"]!.GetValue<bool>());
        Assert.AreEqual(80, catalog["features"]!.AsArray().Count);
        Assert.AreEqual(52, catalog["applicationCapabilities"]!.AsArray().Count);
        Assert.IsTrue(catalog["applicationCapabilities"]!.AsArray().All(d => d!["verificationProfiles"]!.AsArray().Count == 0));
        StringAssert.Contains(result.Markdown, "TOKEN_EXCHANGE_DELEGATION");
        StringAssert.Contains(result.Markdown, "不能宣称全功能覆盖");
    }

    [TestMethod]
    public void MissingMappingsAndUnearnedVerificationAreRejected()
    {
        using var fixture = new Fixture();
        var original = JsonNode.Parse(File.ReadAllText(fixture.RulesPath))!;
        foreach (Action<JsonNode> corrupt in new Action<JsonNode>[]
        {
            n => n["serverVersion"] = "future",
            n => n["sourceCommit"] = "unknown",
            n => n["profileSha256"] = new string('0', 64),
            n => n["features"]!.AsArray().RemoveAt(0),
            n => n["features"]![0]!["responsibility"] = "guess",
            n => n["applicationCapabilities"]![0]!["upstreamFeatures"]!.AsArray().Add(JsonValue.Create("UNKNOWN")),
            n => n["applicationCapabilities"]![0]!["implementation"] = "Supported",
            n => n["applicationCapabilities"]![0]!["acceptanceCriteria"] = new JsonArray(),
            n => n["applicationCapabilities"]![0]!["verificationProfiles"]!.AsArray().Add(JsonValue.Create("unearned")),
            n => n["applicationCapabilities"]!.AsArray().RemoveAt(0)
        })
        {
            var node = original.DeepClone(); corrupt(node);
            File.WriteAllText(fixture.RulesPath, node.ToJsonString());
            Assert.Throws<InvalidDataException>(() => PlatformCoverage.Generate(fixture.Root));
        }
    }

    private sealed class Fixture : IDisposable
    {
        public string Root { get; } = Path.Combine(Path.GetTempPath(), "keycloak-platform-tests-" + Guid.NewGuid().ToString("N"));
        public string RulesPath => Path.Combine(Root, "contracts/platform-coverage-rules.json");
        public Fixture()
        {
            var repo = new DirectoryInfo(AppContext.BaseDirectory);
            while (repo is not null && !File.Exists(Path.Combine(repo.FullName, "Keycloak.Admin.Sdk.slnx"))) repo = repo.Parent;
            Assert.IsNotNull(repo);
            Directory.CreateDirectory(Path.Combine(Root, "contracts"));
            File.Copy(Path.Combine(repo.FullName, "contracts/baseline.json"), Path.Combine(Root, "contracts/baseline.json"));
            File.Copy(Path.Combine(repo.FullName, "contracts/platform-coverage-rules.json"), RulesPath);
            File.Copy(Path.Combine(repo.FullName, "contracts/capabilities.json"), Path.Combine(Root, "contracts/capabilities.json"));
            var baseline = TargetBaseline.Load(Root);
            string destination = Path.Combine(baseline.Source(Root), PlatformCoverage.ProfilePath);
            Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
            File.Copy(Path.Combine(baseline.Source(repo.FullName), PlatformCoverage.ProfilePath), destination);
        }
        public void Dispose()
        {
            if (!Path.GetFullPath(Root).StartsWith(Path.GetFullPath(Path.GetTempPath()), StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Unexpected fixture path.");
            Directory.Delete(Root, true);
        }
    }
}
