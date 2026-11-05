#!/usr/bin/env -S dotnet --
#:property TargetFramework=net10.0
#:property PublishAot=false
#:include ScriptSupport.cs
#:include TargetBaseline.cs
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;

return await ScriptHost.ExecuteAsync(args, "dotnet run --file tools/Check-Baseline.cs -- [--sync|--self-test]", ["--sync", "--self-test"], async ct =>
{
    string root = ScriptHost.RepositoryRoot();
    if (args.Length > 1) throw new ArgumentException("Choose one mode.");
    var target = TargetBaseline.Load(root);
    if (args.Contains("--self-test"))
    {
        var valid = JsonNode.Parse(File.ReadAllText(Path.Combine(root, "contracts/baseline.json")))!.AsObject();
        foreach (string json in new[] { valid.ToJsonString().Replace("{", "{\"unknown\":0,", StringComparison.Ordinal), valid.ToJsonString().Replace("{", "{\"schemaVersion\":1,", StringComparison.Ordinal) })
        {
            try { TargetBaseline.Parse(json); }
            catch (InvalidDataException) { continue; }
            throw new InvalidOperationException("Baseline accepted an unknown/duplicate field.");
        }
        foreach (var field in new[] { "schemaVersion", "keycloakVersion", "commit", "sourceArchiveSha256", "openApiSha256", "serverImage", "sdk", "packageVersion", "discoveredEndpoints", "testedServerPlatform", "postgresImage", "postgresVersionNumber", "nativeSdkImage", "nativeRuntimeImage" })
        {
            var invalid = valid.DeepClone().AsObject();
            invalid[field] = field is "schemaVersion" or "discoveredEndpoints" ? JsonValue.Create(-1) : JsonValue.Create("../invalid");
            try { TargetBaseline.Parse(invalid.ToJsonString()); }
            catch (InvalidDataException) { continue; }
            throw new InvalidOperationException("Baseline accepted invalid field: " + field);
        }
        Console.WriteLine("PASS baseline negative controls: target, hashes, digest, toolchain, package, image and count.");
        return;
    }
    var derived = new Dictionary<string, string>
    {
        ["Target.props"] = target.Props,
        ["src/Keycloak.Admin.Sdk/KeycloakTarget.g.cs"] = target.TargetSource,
        ["global.json"] = "{\n  \"sdk\": {\n    \"version\": \"" + target.Sdk + "\",\n    \"rollForward\": \"disable\"\n  }\n}\n"
    };
    foreach (var (path, expected) in derived)
    {
        string full = Path.Combine(root, path);
        if (args.Contains("--sync")) await File.WriteAllTextAsync(full, expected, ct);
        else if (!File.Exists(full) || File.ReadAllText(full).Replace("\r\n", "\n", StringComparison.Ordinal) != expected)
            throw new InvalidDataException("Stale baseline-derived metadata: " + path + "; run Check-Baseline.cs -- --sync.");
    }
    using var routes = JsonDocument.Parse(File.ReadAllText(Path.Combine(root, "contracts/admin-api-routes.json")));
    using var support = JsonDocument.Parse(File.ReadAllText(Path.Combine(root, "contracts/support-policy.example.json")));
    using var capabilities = JsonDocument.Parse(File.ReadAllText(Path.Combine(root, "contracts/capabilities.json")));
    using var rules = JsonDocument.Parse(File.ReadAllText(Path.Combine(root, "contracts/capability-rules.json")));
    if (routes.RootElement.GetProperty("keycloakVersion").GetString() != target.Version || support.RootElement.GetProperty("serverVersion").GetString() != target.Version
        || capabilities.RootElement.GetProperty("serverVersion").GetString() != target.Version || capabilities.RootElement.GetProperty("sourceCommit").GetString() != target.Commit
        || rules.RootElement.GetProperty("keycloakVersion").GetString() != target.Version)
        throw new InvalidDataException("Target-specific contracts require review for the current baseline.");
    string hash = Convert.ToHexStringLower(SHA256.HashData(await File.ReadAllBytesAsync(Path.Combine(root, "contracts/openapi.json"), ct)));
    if (hash != target.OpenApiHash) throw new InvalidDataException("OpenAPI hash differs from baseline.");
    if (Directory.EnumerateFiles(Path.Combine(root, "contracts"), "keycloak-*.openapi.json").Any()
        || Directory.Exists(Path.Combine(root, "contracts/capabilities")) && Directory.EnumerateFiles(Path.Combine(root, "contracts/capabilities")).Any())
        throw new InvalidDataException("Historical target contracts remain in the active tree.");
    Console.WriteLine($"PASS single target: Keycloak {target.Version}, SDK package {target.PackageVersion}, toolchain {target.Sdk}; derived files and contracts agree.");
});
