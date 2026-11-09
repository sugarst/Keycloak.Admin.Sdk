#!/usr/bin/env -S dotnet --
#:property TargetFramework=net10.0
#:property PublishAot=false
#:include Shared/ScriptSupport.cs
#:include Shared/TargetBaseline.cs
#:include CapabilityEvidence.cs
#:project ../src/Keycloak.Admin.Sdk/Keycloak.Admin.Sdk.csproj
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Keycloak.Admin.Sdk;

return await ScriptHost.ExecuteAsync(args, "dotnet run --file tools/Generate-CapabilityCatalog.cs -- [--check|--seed|--promote]", ["--check", "--seed", "--promote"], async ct =>
{
    if (args.Length > 1) throw new ArgumentException("Choose one mode.");
    string root = ScriptHost.RepositoryRoot(); var target = TargetBaseline.Load(root);
    using var mapping = JsonDocument.Parse(File.ReadAllText(Path.Combine(root, "contracts/capability-rules.json")));
    if (mapping.RootElement.GetProperty("keycloakVersion").GetString() != target.Version) throw new InvalidDataException("Review capability rules for this target.");
    var rules = mapping.RootElement.GetProperty("rules").EnumerateArray().ToArray();
    string profile = File.ReadAllText(Path.Combine(target.Source(root), "common/src/main/java/org/keycloak/common/Profile.java"));
    foreach (var rule in rules)
        if (!Regex.IsMatch(profile, @"\b" + Regex.Escape(rule.GetProperty("serverFeature").GetString()!) + @"\([^\r\n]*Type\." + Regex.Escape(rule.GetProperty("sourceType").GetString()!) + @"\b"))
            throw new InvalidDataException("Capability stage differs from target source: " + rule.GetProperty("featureId").GetString());
    JsonObject? current = File.Exists(Path.Combine(root, "contracts/capabilities.json")) ? JsonNode.Parse(File.ReadAllText(Path.Combine(root, "contracts/capabilities.json")))!.AsObject() : null;
    bool sameTarget = current?["serverVersion"]?.GetValue<string>() == target.Version && current?["sourceCommit"]?.GetValue<string>() == target.Commit;
    if (!args.Contains("--seed") && sameTarget && current!["schemaVersion"]!.GetValue<int>() == 1)
        CapabilityEvidence.ImportFullAcceptance(root, current, Path.Combine(root, "docs/contracts/full-live-evidence"));
    if (args.Contains("--promote")) await ScriptHost.RunCheckedAsync(root, "dotnet", ["run", "--file", "tools/Check-FullAcceptance.cs", "--", "--bootstrap"], ct);
    if (args.Contains("--promote"))
    {
        // Check-FullAcceptance validated every route/mode above. Read each manifest, not a single managed ledger.
        var promoted = current?.DeepClone().AsObject() ?? throw new InvalidDataException("Seed the target catalog before promotion.");
        CapabilityEvidence.ImportFullAcceptance(root, promoted, Path.Combine(root, "artifacts/full-live"), promote: true);
        current = promoted; sameTarget = true;
    }
    var profiles = !args.Contains("--seed") && sameTarget ? current!["verificationProfiles"]!.DeepClone().AsArray() : new JsonArray();
    var entries = new JsonArray();
    foreach (var endpoint in AdminEndpointCatalog.All)
    {
        var rule = rules.First(r => Regex.IsMatch(endpoint.Path, r.GetProperty("pattern").GetString()!)); string stage = rule.GetProperty("stage").GetString()!;
        var previous = !args.Contains("--seed") && sameTarget ? current!["endpoints"]!.AsArray().SingleOrDefault(e => e!["operation"]!.GetValue<string>() == endpoint.Operation
            && e["method"]!.GetValue<string>() == endpoint.Method && e["path"]!.GetValue<string>() == endpoint.Path) : null;
        var entry = new JsonObject { ["operation"] = endpoint.Operation, ["method"] = endpoint.Method, ["path"] = endpoint.Path,
            ["featureId"] = rule.GetProperty("featureId").GetString(), ["stage"] = stage, ["implementation"] = "Implemented",
            ["support"] = "NotSupported",
            ["routes"] = JsonNode.Parse(rule.GetProperty("routes").GetRawText()), ["verification"] = "Contract",
            ["requiredServerFeatures"] = new JsonArray(new[] { "ADMIN_API", rule.GetProperty("serverFeature").GetString()! }.Distinct().Select(s => (JsonNode?)JsonValue.Create(s)).ToArray()),
            ["evidence"] = previous?["evidence"]?.DeepClone() ?? JsonValue.Create("contracts/admin-api-test-matrix.json; no real acceptance"),
            ["supportProfiles"] = previous?["supportProfiles"]?.DeepClone() ?? new JsonArray() };
        CapabilityEvidence.RefreshAggregate(entry, profiles); entries.Add(entry);
    }
    string output = CapabilityEvidence.Json(new JsonObject { ["schemaVersion"] = 2, ["serverVersion"] = target.Version, ["sourceCommit"] = target.Commit, ["endpoints"] = entries, ["verificationProfiles"] = profiles })
        .Replace("\r\n", "\n", StringComparison.Ordinal) + "\n";
    string file = Path.Combine(root, "contracts/capabilities.json");
    if (args.Contains("--check")) { if (File.ReadAllText(file).Replace("\r\n", "\n", StringComparison.Ordinal) != output) throw new InvalidDataException("Capability catalog is stale."); }
    else await File.WriteAllTextAsync(file, output, ct);
    Console.WriteLine($"Single-target capability catalog: {target.Version}, {entries.Count} operations; seed never claims real acceptance.");
});
