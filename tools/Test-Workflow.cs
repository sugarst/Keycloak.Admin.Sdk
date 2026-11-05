#!/usr/bin/env -S dotnet --
#:property TargetFramework=net10.0
#:property PublishAot=false
#:include ScriptSupport.cs
#:include TargetBaseline.cs
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Security.Cryptography;

return await ScriptHost.ExecuteAsync(args, "dotnet run --file tools/Test-Workflow.cs", [], async ct =>
{
    string root = ScriptHost.RepositoryRoot(), fixture = ScriptHost.Within(root, "artifacts/workflow-test/" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(fixture);
    foreach (string file in ScriptHost.RepositoryFiles(root))
    {
        if (Path.GetFileName(file) == ".env") continue;
        string path = ScriptHost.Within(fixture, Path.GetRelativePath(root, file)); Directory.CreateDirectory(Path.GetDirectoryName(path)!); File.Copy(file, path);
    }
    var target = TargetBaseline.Load(root); Directory.CreateDirectory(target.Cache(fixture)); File.Copy(target.Archive(root), target.Archive(fixture));
    string bundle = ScriptHost.Within(fixture, "artifacts/candidate"); Directory.CreateDirectory(bundle);
    foreach (string name in new[] { "baseline.json", "admin-api-routes.json", "capability-rules.json", "overrides.json", "support-policy.example.json", "feature-management.example.json", "openapi.json" }) File.Copy(Path.Combine(root, "contracts", name), Path.Combine(bundle, name));
    string sentinel = Path.Combine(fixture, "src/Keycloak.Admin.Sdk/Generated/RetiredApi.g.cs");
    await File.WriteAllTextAsync(sentinel, "// obsolete generated file, must disappear on complete replacement", ct);
    string obsoleteEvidence = Path.Combine(fixture, "docs/contracts/full-live-evidence/obsolete.json");
    await File.WriteAllTextAsync(obsoleteEvidence, "{}", ct);
    string Before() => Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(string.Join('\n', ScriptHost.RepositoryFiles(fixture).Order(StringComparer.Ordinal).Select(p => Path.GetRelativePath(fixture, p) + ":" + Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(p))))))));
    string before = Before();
    var bad = JsonNode.Parse(File.ReadAllText(Path.Combine(bundle, "baseline.json")))!;
    bad["openApiSha256"] = new string('0', 64); await File.WriteAllTextAsync(Path.Combine(bundle, "baseline.json"), bad.ToJsonString(), ct);
    var failed = await ScriptHost.RunAsync(fixture, "dotnet", ["run", "--file", "tools/Upgrade.cs", "--", "--candidate=" + bundle, "--apply"], ct, capture: true);
    if (failed.ExitCode == 0 || !failed.StandardError.Contains("hash mismatch", StringComparison.Ordinal) || Before() != before) throw new InvalidOperationException("Failed upgrade changed the active tree.");
    File.Copy(Path.Combine(root, "contracts/baseline.json"), Path.Combine(bundle, "baseline.json"), true);
    await ScriptHost.RunCheckedAsync(fixture, "dotnet", ["run", "--file", "tools/Upgrade.cs", "--", "--candidate=" + bundle], ct);
    if (Before() != before) throw new InvalidOperationException("Read-only upgrade changed the active tree.");
    await ScriptHost.RunCheckedAsync(fixture, "dotnet", ["run", "--file", "tools/Upgrade.cs", "--", "--candidate=" + bundle, "--apply"], ct);
    using var capabilities = JsonDocument.Parse(File.ReadAllText(Path.Combine(fixture, "contracts/capabilities.json")));
    if (File.Exists(sentinel) || File.Exists(obsoleteEvidence) || capabilities.RootElement.GetProperty("endpoints").EnumerateArray().Any(e => e.GetProperty("verification").GetString() != "Contract" || e.GetProperty("support").GetString() != "NotSupported"))
        throw new InvalidOperationException("Upgrade retained retired APIs, stale evidence or unearned verification.");
    Console.WriteLine("PASS workflow: invalid hash preserves active tree; preparation is read-only; replacement removes retired APIs and evidence; every new-target capability starts Contract-only. Real workspace and database untouched.");
});
