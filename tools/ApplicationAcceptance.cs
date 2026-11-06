using System.Security.Cryptography;
using System.Text.Json.Nodes;

internal static class ApplicationAcceptance
{
    internal static JsonObject Validate(string root, JsonObject report)
    {
        var baseline = TargetBaseline.Load(root);
        string profile = Profile(report);
        var plan = Read(Path.Combine(root, profile == "legacy" ? "contracts/application-legacy-validation-plans.json" : "contracts/application-validation-plans.json"));
        string Text(string name) => report[name]?.GetValue<string>() ?? "";
        static bool Hash(string value) => value.Length == 64 && value.All(c => char.IsAsciiHexDigit(c) && !char.IsAsciiLetterUpper(c));
        string mode = Text("runtime"); bool native = mode == "native-aot";
        if (plan["schemaVersion"]?.GetValue<int>() != 1 || plan["serverVersion"]?.GetValue<string>() != baseline.Version || plan["sourceCommit"]?.GetValue<string>() != baseline.Commit
            || report["schemaVersion"]?.GetValue<int>() != 1 || report["completed"]?.GetValue<bool>() != true || report["promoted"]?.GetValue<bool>() != false
            || Text("serverVersion") != baseline.Version || Text("sourceCommit") != baseline.Commit || Text("inputFingerprint") != LiveEvidence.ValidationFingerprint(root)
            || mode is not ("managed" or "native-aot") || (native ? Text("runtimeIdentifier") != "linux-musl-x64" : report["runtimeIdentifier"] is not null)
            || Text("scope") != "selected application workflows; promotion is determined independently"
            || !Hash(Text("executableSha256")) || !Hash(Text("serverInfoSha256")))
            throw new InvalidDataException("Incomplete, stale or wrong-target application evidence.");
        if (plan["requiredCounterpartImages"] is { } counterpartImages)
            foreach (string id in Strings(counterpartImages))
                if (report["counterpartImages"] is not JsonObject images || images[id] is not JsonValue value || !value.TryGetValue<string>(out string? image)
                    || image is null || !image.StartsWith("sha256:", StringComparison.Ordinal) || !Hash(image[7..]))
                    throw new InvalidDataException("Missing immutable application counterpart image evidence.");
        var expected = Strings(plan["expectedChecks"]);
        var knownChecks = new HashSet<string>(expected, StringComparer.Ordinal);
        if (plan["runtimeChecks"] is { } runtimeChecks)
            foreach (var runtime in runtimeChecks.AsObject())
            {
                if (runtime.Key is not ("managed" or "native-aot")) throw new InvalidDataException("Unknown application runtime check group.");
                var extra = Strings(runtime.Value);
                if (extra.Overlaps(knownChecks)) throw new InvalidDataException("Runtime application checks must have unique identities.");
                knownChecks.UnionWith(extra); if (runtime.Key == mode) expected.UnionWith(extra);
            }
        var actual = Strings(report["checks"]);
        if (expected.Count == 0 || actual.Count != expected.Count || !actual.SetEquals(expected)) throw new InvalidDataException("Application evidence has missing or unexpected business checks.");
        var enabled = report["serverFeatures"]?.AsArray().Where(f => f!["enabled"]!.GetValue<bool>()).Select(f => f!["name"]!.GetValue<string>()).ToHashSet(StringComparer.Ordinal)
            ?? throw new InvalidDataException("Missing actual application server features.");
        if (!Strings(plan["requiredServerFeatures"]).IsSubsetOf(enabled)) throw new InvalidDataException("Required application server features are disabled or unknown.");
        var rules = Read(Path.Combine(root, "contracts/platform-coverage-rules.json"));
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var capability in plan["capabilities"]!.AsArray())
        {
            string id = capability!["id"]!.GetValue<string>();
            string? onlyRuntime = capability["runtime"]?.GetValue<string>();
            if (onlyRuntime is not (null or "managed" or "native-aot")) throw new InvalidDataException("Unknown application capability runtime.");
            bool applicable = onlyRuntime is null || onlyRuntime == mode;
            var target = rules["applicationCapabilities"]!.AsArray().SingleOrDefault(c => c!["id"]!.GetValue<string>() == id);
            if (!seen.Add(id) || target is null || capability["criteria"]!.AsArray().Count == 0) throw new InvalidDataException("Unknown or duplicate application validation capability.");
            if (applicable && !Strings(capability["requiredServerFeatures"]).IsSubsetOf(enabled)) throw new InvalidDataException("Application capability requires disabled server features.");
            var criteria = new HashSet<string>(StringComparer.Ordinal);
            foreach (var criterion in capability["criteria"]!.AsArray())
            {
                string name = criterion!["criterion"]!.GetValue<string>(); var checks = Strings(criterion["checks"]);
                if (!criteria.Add(name) || !Strings(target["acceptanceCriteria"]).Contains(name) || checks.Count == 0 || !checks.IsSubsetOf(applicable ? actual : knownChecks))
                    throw new InvalidDataException("Application criterion is unknown, duplicate or missing a business proof.");
            }
        }
        return plan;
    }

    internal static JsonArray CurrentProfiles(string root)
    {
        var result = new JsonArray(); string path = Path.Combine(root, "contracts/application-verification-profiles.json");
        if (!File.Exists(path)) return result;
        var registry = Read(path); var baseline = TargetBaseline.Load(root);
        if (registry["schemaVersion"]?.GetValue<int>() != 1 || registry["serverVersion"]?.GetValue<string>() != baseline.Version || registry["sourceCommit"]?.GetValue<string>() != baseline.Commit)
            throw new InvalidDataException("Application verification registry targets another server.");
        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var entry in registry["profiles"]!.AsArray())
        {
            string hash = entry!["evidenceSha256"]!.GetValue<string>();
            string relative = "docs/contracts/application-protocol-evidence/" + hash + ".json";
            if (hash.Length != 64 || !hash.All(char.IsAsciiHexDigit) || !ids.Add(hash) || entry["evidence"]!.GetValue<string>() != relative)
                throw new InvalidDataException("Invalid application evidence reference.");
            string evidence = Path.Combine(root, relative);
            if (Digest(evidence) != hash) throw new InvalidDataException("Application evidence hash mismatch.");
            var report = Read(evidence);
            // Older immutable evidence is retained as history, never used to support changed code.
            if (report["inputFingerprint"]!.GetValue<string>() != LiveEvidence.ValidationFingerprint(root)) continue;
            var plan = Validate(root, report);
            result.Add(new JsonObject { ["id"] = hash, ["serverProfile"] = Profile(report), ["runtime"] = report["runtime"]!.DeepClone(), ["runtimeIdentifier"] = report["runtimeIdentifier"]?.DeepClone(),
                ["sourceFingerprint"] = report["inputFingerprint"]!.DeepClone(), ["evidence"] = relative, ["evidenceSha256"] = hash,
                ["capabilities"] = new JsonArray(plan["capabilities"]!.AsArray().Where(c => c!["runtime"] is null || c["runtime"]!.GetValue<string>() == report["runtime"]!.GetValue<string>()).Select(c => c!.DeepClone()).ToArray()) });
        }
        return result;
    }

    internal static void Promote(string root, string reportPath)
    {
        var report = Read(reportPath); Validate(root, report);
        bool native = report["runtime"]!.GetValue<string>() == "native-aot";
        string binary = Path.Combine(root, native ? "artifacts/aot/application-protocols/Keycloak.Admin.Sdk.IntegrationTests" : "tests/Keycloak.Admin.Sdk.IntegrationTests/bin/Release/net10.0/Keycloak.Admin.Sdk.IntegrationTests.dll");
        if (Digest(binary) != report["executableSha256"]!.GetValue<string>()) throw new InvalidDataException("Application validation executable differs from the evidence.");
        string hash = Digest(reportPath), relative = "docs/contracts/application-protocol-evidence/" + hash + ".json";
        string destination = Path.Combine(root, relative); Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        byte[] bytes = File.ReadAllBytes(reportPath);
        if (File.Exists(destination) && !File.ReadAllBytes(destination).SequenceEqual(bytes)) throw new IOException("Immutable application evidence collision.");
        File.WriteAllBytes(destination, bytes);
        string registryPath = Path.Combine(root, "contracts/application-verification-profiles.json"); var registry = Read(registryPath);
        // Different server profiles may prove disjoint capabilities in the same runtime; neither replaces the other.
        CurrentProfiles(root);
        var profiles = registry["profiles"]!.AsArray();
        for (int i = profiles.Count - 1; i >= 0; i--)
        {
            var previous = Read(Path.Combine(root, profiles[i]!["evidence"]!.GetValue<string>()));
            if (previous["runtime"]!.GetValue<string>() == report["runtime"]!.GetValue<string>() && Profile(previous) == Profile(report)) profiles.RemoveAt(i);
        }
        profiles.Add(new JsonObject { ["evidence"] = relative, ["evidenceSha256"] = hash });
        File.WriteAllText(registryPath, registry.ToJsonString(new System.Text.Json.JsonSerializerOptions { WriteIndented = true }) + "\n");
    }

    internal static JsonObject Read(string path) => JsonNode.Parse(File.ReadAllText(path))!.AsObject();
    private static string Profile(JsonObject report) => report["serverProfile"]?.GetValue<string>() switch
    {
        null or "standard" => "standard", "legacy" => "legacy", _ => throw new InvalidDataException("Unknown application server profile.")
    };
    internal static string Digest(string path) => Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path)));
    private static HashSet<string> Strings(JsonNode? array)
    {
        var result = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in array?.AsArray() ?? throw new InvalidDataException("Missing application evidence list."))
            if (string.IsNullOrWhiteSpace(item?.GetValue<string>()) || !result.Add(item.GetValue<string>())) throw new InvalidDataException("Empty or duplicate application evidence list item.");
        return result;
    }
}
