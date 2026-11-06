#!/usr/bin/env -S dotnet --
#:property TargetFramework=net10.0
#:property PublishAot=false
#:include ScriptSupport.cs
#:include TargetBaseline.cs
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Security.Cryptography;

return await ScriptHost.ExecuteAsync(args, "dotnet run --file tools/Upgrade.cs -- --candidate=<reviewed-bundle-directory> [--apply]", ["--apply", .. args.Where(a => a.StartsWith("--candidate=", StringComparison.Ordinal))], async ct =>
{
    string root = ScriptHost.RepositoryRoot();
    string candidate = Path.GetFullPath(args.Single(a => a.StartsWith("--candidate=", StringComparison.Ordinal))[12..]);
    var next = TargetBaseline.Parse(File.ReadAllText(Path.Combine(candidate, "baseline.json")));
    var previous = TargetBaseline.Load(root);
    if (next.Version != previous.Version && next.PackageVersion == previous.PackageVersion) throw new InvalidDataException("A new upstream target requires a new immutable SDK package version.");
    string[] reviewed = ["baseline.json", "admin-api-routes.json", "capability-rules.json", "feature-validation-plans.json", "overrides.json", "support-policy.example.json", "support-policy.managed.example.json", "support-policy.native-aot.example.json", "feature-management.example.json"];
    foreach (string name in reviewed) if (!File.Exists(Path.Combine(candidate, name))) throw new InvalidDataException("Missing reviewed input: " + name);
    string stage = ScriptHost.Within(root, "artifacts/upgrade/" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(stage);
    // Prepare a complete isolated tree. Active contracts and code are untouched until all generation succeeds.
    foreach (string file in ScriptHost.RepositoryFiles(root))
    {
        if (Path.GetFileName(file) == ".env") continue;
        string destination = ScriptHost.Within(stage, Path.GetRelativePath(root, file)); Directory.CreateDirectory(Path.GetDirectoryName(destination)!); File.Copy(file, destination);
    }
    foreach (string name in reviewed) File.Copy(Path.Combine(candidate, name), Path.Combine(stage, "contracts", name), true);
    await File.WriteAllTextAsync(Path.Combine(stage, "Target.props"), next.Props, ct);
    await File.WriteAllTextAsync(Path.Combine(stage, "src/Keycloak.Admin.Sdk/KeycloakTarget.g.cs"), next.TargetSource, ct);
    await File.WriteAllTextAsync(Path.Combine(stage, "global.json"), "{\"sdk\":{\"version\":\"" + next.Sdk + "\",\"rollForward\":\"disable\"}}", ct);
    string openapi = Path.Combine(stage, "contracts/openapi.json");
    if (File.Exists(Path.Combine(candidate, "openapi.json"))) File.Copy(Path.Combine(candidate, "openapi.json"), openapi, true);
    else
    {
        using var http = new HttpClient(); await File.WriteAllBytesAsync(openapi, await http.GetByteArrayAsync($"https://www.keycloak.org/docs-api/{next.Version}/rest-api/openapi.json", ct), ct);
    }
    if (Convert.ToHexStringLower(SHA256.HashData(await File.ReadAllBytesAsync(openapi, ct))) != next.OpenApiHash) throw new InvalidDataException("Candidate OpenAPI hash mismatch.");
    Directory.CreateDirectory(next.Cache(stage));
    // Reuse immutable bytes, not an extraction that may contain removed Java classes.
    string archive = File.Exists(next.Archive(root)) ? next.Archive(root) : Path.Combine(root, ".cache/keycloak/source.tar.gz");
    if (File.Exists(archive) && Convert.ToHexStringLower(SHA256.HashData(await File.ReadAllBytesAsync(archive, ct))) == next.ArchiveHash) File.Copy(archive, next.Archive(stage));
    File.Delete(Path.Combine(stage, "contracts/source-files.sha256"));
    // The core project embeds this resource, including while the seed tool is compiled.
    // Never copy old acceptance state into a new target, even temporarily.
    var emptyCatalog = new JsonObject
    {
        ["schemaVersion"] = 1,
        ["serverVersion"] = next.Version,
        ["sourceCommit"] = next.Commit,
        ["endpoints"] = new JsonArray()
    };
    await File.WriteAllTextAsync(Path.Combine(stage, "contracts/capabilities.json"), emptyCatalog.ToJsonString(), ct);
    foreach (string script in new[] { "Update-Contracts.cs", "Generate-CapabilityCatalog.cs", "Generate-TestMatrix.cs", "Generate-LiveRoutes.cs" })
    {
        string[] mode = script == "Generate-TestMatrix.cs" ? ["--", "--refresh-contracts"] : script == "Generate-CapabilityCatalog.cs" ? ["--", "--seed"] : [];
        await ScriptHost.RunCheckedAsync(stage, "dotnet", ["run", "--file", "tools/" + script, .. mode], ct);
    }
    // Refresh generated metadata and validate reviewed target-specific declarations.
    await ScriptHost.RunCheckedAsync(stage, "dotnet", ["run", "--file", "tools/Check-Baseline.cs", "--", "--sync"], ct);
    await ScriptHost.RunCheckedAsync(stage, "dotnet", ["run", "--file", "tools/Check-Baseline.cs"], ct);
    var old = Signatures(root); var current = Signatures(stage);
    var diff = new JsonObject { ["from"] = previous.Version, ["to"] = next.Version,
        ["added"] = Array(current.Keys.Except(old.Keys)), ["removed"] = Array(old.Keys.Except(current.Keys)),
        ["changed"] = Array(current.Keys.Intersect(old.Keys).Where(k => current[k] != old[k])),
        ["oldOpenApiSha256"] = previous.OpenApiHash, ["newOpenApiSha256"] = next.OpenApiHash,
        ["openApiChanges"] = JsonChanges(JsonNode.Parse(File.ReadAllText(Path.Combine(root, "contracts/openapi.json"))), JsonNode.Parse(File.ReadAllText(openapi)), "$"),
        ["newCapabilities"] = "Contract only; real acceptance and support promotion required" };
    await File.WriteAllTextAsync(Path.Combine(stage, "upgrade-diff.json"), diff.ToJsonString(new JsonSerializerOptions { WriteIndented = true }), ct);
    Console.WriteLine("Prepared replacement and contract diff: " + stage);
    if (!args.Contains("--apply")) { Console.WriteLine("Active tree unchanged. Review upgrade-diff.json; --apply prepares and installs a fresh replacement."); return; }
    string[] fixedFiles = [.. reviewed.Select(n => "contracts/" + n), "contracts/openapi.json", "contracts/source-files.sha256", "contracts/source-signatures.json", "contracts/source-dispatches.json",
        "contracts/admin-api-test-matrix.json", "contracts/capabilities.json", "Target.props", "global.json", "src/Keycloak.Admin.Sdk/KeycloakTarget.g.cs",
        "tests/Keycloak.Admin.Sdk.Tests/Endpoints.g.cs", "tests/Keycloak.Admin.Sdk.Tests/EndpointMatrix.g.cs", "tests/Keycloak.Admin.Sdk.Tests/EndpointMatrixTests.g.cs", "tests/Keycloak.Admin.Sdk.Tests/ModelMatrix.g.cs",
        "tests/Keycloak.Admin.Sdk.IntegrationTests/LiveRoutes.g.cs", "docs/contracts/endpoint-inventory.md", "docs/contracts/admin-api-test-matrix.md", "docs/contracts/source-routes.tsv", "docs/contracts/unresolved-locators.txt"];
    var generated = Directory.EnumerateFiles(Path.Combine(stage, "src/Keycloak.Admin.Sdk/Generated"), "*.g.cs").Select(p => Path.GetRelativePath(stage, p));
    var installedGenerated = Directory.EnumerateFiles(Path.Combine(root, "src/Keycloak.Admin.Sdk/Generated"), "*.g.cs").Select(p => Path.GetRelativePath(root, p));
    string[] staleEvidence = [.. Directory.EnumerateFiles(Path.Combine(root, "docs/contracts/full-live-evidence")).Select(p => Path.GetRelativePath(root, p)),
        "docs/contracts/full-live-acceptance.md", "docs/contracts/full-live-acceptance.tsv", "docs/contracts/admin-api-validation-list.md", "docs/contracts/test-coverage.md"];
    var changes = fixedFiles.Concat(generated).Concat(installedGenerated).Concat(staleEvidence).Distinct().ToArray();
    var backup = changes.ToDictionary(p => p, p => File.Exists(ScriptHost.Within(root, p)) ? File.ReadAllBytes(ScriptHost.Within(root, p)) : null);
    try
    {
        foreach (string path in changes)
        {
            ct.ThrowIfCancellationRequested();
            string destination = ScriptHost.Within(root, path), source = ScriptHost.Within(stage, path);
            if (staleEvidence.Contains(path) || !File.Exists(source)) File.Delete(destination);
            else { Directory.CreateDirectory(Path.GetDirectoryName(destination)!); File.Copy(source, destination, true); }
        }
        Directory.CreateDirectory(next.Cache(root)); File.Copy(next.Archive(stage), next.Archive(root), true);
    }
    catch
    {
        foreach (var (path, bytes) in backup) { if (bytes is null) File.Delete(ScriptHost.Within(root, path)); else File.WriteAllBytes(ScriptHost.Within(root, path), bytes); }
        throw;
    }
    Console.WriteLine("Installed one target. Historical generated APIs and published acceptance claims were removed. Run Release.cs; no packages published and no database volumes changed.");
});

static JsonArray Array(IEnumerable<string> values) => new(values.Order(StringComparer.Ordinal).Select(v => (JsonNode?)JsonValue.Create(v)).ToArray());
static JsonArray JsonChanges(JsonNode? previous, JsonNode? current, string path)
{
    var result = new JsonArray();
    if (JsonNode.DeepEquals(previous, current)) return result;
    if (previous is JsonObject oldObject && current is JsonObject newObject)
        foreach (string key in oldObject.Select(p => p.Key).Union(newObject.Select(p => p.Key)).Order(StringComparer.Ordinal))
        {
            if (!oldObject.ContainsKey(key) || !newObject.ContainsKey(key)) result.Add(new JsonObject { ["path"] = path + "." + key, ["change"] = newObject.ContainsKey(key) ? "added" : "removed", ["before"] = oldObject[key]?.DeepClone(), ["after"] = newObject[key]?.DeepClone() });
            else foreach (var change in JsonChanges(oldObject[key], newObject[key], path + "." + key)) result.Add(change!.DeepClone());
        }
    else result.Add(new JsonObject { ["path"] = path, ["before"] = previous?.DeepClone(), ["after"] = current?.DeepClone() });
    return result;
}
static Dictionary<string, string> Signatures(string root)
{
    using var document = JsonDocument.Parse(File.ReadAllText(Path.Combine(root, "contracts/source-signatures.json")));
    return document.RootElement.EnumerateArray().ToDictionary(e => e.GetProperty("method").GetString() + " " + e.GetProperty("path").GetString(), e => e.GetProperty("returnType").GetString() + " " + e.GetProperty("parameters").GetString() + " " + e.GetProperty("annotations").GetString());
}
