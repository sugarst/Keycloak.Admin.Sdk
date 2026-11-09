using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Security.Cryptography;
using System.Text;

internal static class PlatformCoverage
{
    internal const string ProfilePath = "common/src/main/java/org/keycloak/common/Profile.java";
    internal static (string Json, string Markdown, bool Complete) Generate(string root)
    {
        var baseline = TargetBaseline.Load(root);
        var rules = JsonNode.Parse(File.ReadAllText(Path.Combine(root, "contracts/platform-coverage-rules.json")))!.AsObject();
        if (rules["schemaVersion"]?.GetValue<int>() != 1 || rules["serverVersion"]?.GetValue<string>() != baseline.Version || rules["sourceCommit"]?.GetValue<string>() != baseline.Commit)
            throw new InvalidDataException("Review platform coverage rules for the exact target.");
        var sourceText = File.ReadAllText(Path.Combine(baseline.Source(root), ProfilePath)).Replace("\r\n", "\n", StringComparison.Ordinal);
        string profileHash = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(sourceText)));
        if (profileHash != rules["profileSha256"]?.GetValue<string>()) throw new InvalidDataException("Pinned feature source hash mismatch.");
        var upstream = Regex.Matches(sourceText, "(?m)^\\s{8}([A-Z][A-Z_0-9]*)\\(\"([^\"\\r\\n]+)\", Type\\.([A-Z_]+)")
            .ToDictionary(m => m.Groups[1].Value, m => (Label: m.Groups[2].Value, Type: m.Groups[3].Value,
                Deprecated: m.Groups[3].Value == "DEPRECATED" || Regex.IsMatch(sourceText[(m.Index + m.Length)..].Split('\n')[0], @"^\s*,\s*\d+\s*,\s*true\b")), StringComparer.Ordinal);
        if (upstream.Count == 0) throw new InvalidDataException("No pinned upstream features discovered.");
        var reviewed = rules["features"]!.AsArray().ToDictionary(n => n!["id"]!.GetValue<string>(), n => n!.AsObject(), StringComparer.Ordinal);
        if (!upstream.Keys.ToHashSet(StringComparer.Ordinal).SetEquals(reviewed.Keys))
            throw new InvalidDataException("Every pinned upstream feature must have exactly one reviewed responsibility mapping.");
        string[] responsibilities = ["SdkAdmin", "SdkProtocol", "HostIntegration", "ServerRuntime", "ServerExtension"];
        var features = new JsonArray();
        var md = new StringBuilder("# Keycloak 全能力覆盖矩阵 / Platform capability coverage\n\n");
        md.AppendLine($"固定目标 / Exact target: Keycloak {baseline.Version}, upstream `{baseline.Commit}`.\n");
        md.AppendLine("本表登记上游功能及责任边界，不把登记、生成或 HTTP 可调用视为完成支持。HostIntegration 仍属于应用全覆盖待完成项；ServerRuntime 和 ServerExtension 明确由服务端或外部工具承担。用户自定义 SPI 不属于有限上游清单。\n");
        md.AppendLine("Admin API 的 520 项操作独立维护于 [操作支持矩阵](admin-api-support-matrix.tsv)。下表的上游功能数不能与操作数相加。\n");
        md.AppendLine("## 上游功能 / Upstream features\n\n| Feature | Upstream stage | Deprecated | Responsibility |\n| --- | --- | --- | --- |");
        foreach (var (id, info) in upstream.OrderBy(p => p.Key, StringComparer.Ordinal))
        {
            string owner = reviewed[id]["responsibility"]!.GetValue<string>();
            if (!responsibilities.Contains(owner)) throw new InvalidDataException("Unknown feature responsibility: " + id);
            string stage = info.Type switch { "DEFAULT" or "DISABLED_BY_DEFAULT" => "Stable", "PREVIEW" => "Preview", "EXPERIMENTAL" => "Experimental", "DEPRECATED" => "Deprecated", _ => throw new InvalidDataException("Unknown upstream feature stage.") };
            features.Add((JsonNode)new JsonObject { ["id"] = id, ["label"] = info.Label, ["stage"] = stage, ["sourceType"] = info.Type,
                ["deprecated"] = info.Deprecated, ["responsibility"] = owner, ["sourceFile"] = ProfilePath });
            md.AppendLine($"| `{id}` | {stage} | {info.Deprecated.ToString().ToLowerInvariant()} | {owner} |");
        }
        var domains = rules["applicationCapabilities"]!.AsArray();
        var profiles = ApplicationAcceptance.CurrentProfiles(root);
        var generatedDomains = new JsonArray();
        bool complete = true;
        var ids = new HashSet<string>(StringComparer.Ordinal);
        md.AppendLine("\n## 应用协议与运行时 / Application protocols and runtime\n\n| Capability | Responsibility | Implementation | Verified runtime profiles |\n| --- | --- | --- | --- |");
        foreach (var node in domains)
        {
            var item = node!.AsObject(); string id = item["id"]!.GetValue<string>();
            if (string.IsNullOrWhiteSpace(id) || !ids.Add(id) || item["responsibility"]!.GetValue<string>() is not ("SdkProtocol" or "HostIntegration"))
                throw new InvalidDataException("Invalid/duplicate application capability identity.");
            if (item["implementation"]!.GetValue<string>() is not ("NotImplemented" or "Partial" or "Implemented")
                || item["acceptanceCriteria"]!.AsArray().Count == 0 || item["acceptanceCriteria"]!.AsArray().Any(c => string.IsNullOrWhiteSpace(c!.GetValue<string>()))
                || item["upstreamFeatures"]!.AsArray().Any(f => !upstream.ContainsKey(f!.GetValue<string>())))
                throw new InvalidDataException("Invalid application implementation, criteria or upstream references.");
            // References in reviewed rules are forbidden; only validated independent evidence may populate the generated catalog.
            if (item["verificationProfiles"]!.AsArray().Count != 0)
                throw new InvalidDataException("Manual application profile claims are forbidden; run the independent evidence promotion tool.");
            var supported = new JsonArray();
            foreach (var profile in profiles)
            {
                var proof = profile!["capabilities"]!.AsArray().SingleOrDefault(c => c!["id"]!.GetValue<string>() == id);
                if (item["implementation"]!.GetValue<string>() == "Implemented" && proof is not null
                    && item["acceptanceCriteria"]!.AsArray().All(c => proof["criteria"]!.AsArray().Any(p => p!["criterion"]!.GetValue<string>() == c!.GetValue<string>())))
                    supported.Add(profile["id"]!.DeepClone());
            }
            bool verified = supported.Count != 0;
            complete &= verified;
            var generated = item.DeepClone().AsObject(); generated["verificationProfiles"] = supported; generated["support"] = verified ? "Supported" : "NotVerified";
            generatedDomains.Add(generated);
            md.AppendLine($"| `{id}` | {item["responsibility"]!.GetValue<string>()} | {item["implementation"]!.GetValue<string>()} | {supported.Count}; {(verified ? "verified for referenced profiles only" : "not promoted")} |");
        }
        if (new[] { "oidc", "registration", "browser-oidc", "saml", "mutual-tls", "identity-broker-login", "identity-linking", "oidc-request-objects", "oidc-signed-responses", "oidc-browser-compatibility", "oidc-assurance" }.Any(id => !ids.Contains(id)))
            throw new InvalidDataException("Missing core application protocol capability.");
        foreach (string feature in reviewed.Where(p => p.Value["responsibility"]!.GetValue<string>() is "SdkProtocol" or "HostIntegration").Select(p => p.Key))
            if (!domains.Any(d => d!["upstreamFeatures"]!.AsArray().Any(f => f!.GetValue<string>() == feature)))
                throw new InvalidDataException("Protocol feature has no application acceptance plan: " + feature);
        var admin = JsonNode.Parse(File.ReadAllText(Path.Combine(root, "contracts/capabilities.json")))!;
        // Compatibility is real, verified coverage in an explicitly selected FGAP v1 route; it must not be relabelled Stable/default support.
        complete &= admin["endpoints"]!.AsArray().All(e => e!["support"]!.GetValue<string>() is "Supported" or "Compatibility");
        md.AppendLine("\n`Partial` 表示仅有部分调用实现；不表示完整协议支持，也不继承 Admin API 的验收。晋升引用绑定输入指纹、运行模式、RID 和不可变业务证据；修改代码后旧证据自动退出当前支持。\n");
        md.AppendLine(complete ? "全部审阅应用能力和 Admin API 已有支持配置。发布仍须通过完整契约、原生构建和真实验收门禁。\n" : "全部应用能力尚未通过协议业务晋升，不能宣称全功能覆盖。运行 `Generate-PlatformMatrix.cs -- --require-complete` 会明确拒绝当前未完成项。\n");
        var result = new JsonObject { ["schemaVersion"] = 1, ["serverVersion"] = baseline.Version, ["sourceCommit"] = baseline.Commit,
            ["profileSha256"] = profileHash,
            ["adminCatalog"] = "contracts/capabilities.json", ["features"] = features,
            ["applicationCapabilities"] = generatedDomains, ["verificationProfiles"] = profiles, ["boundaries"] = rules["boundaries"]!.DeepClone(), ["complete"] = complete };
        return (result.ToJsonString(new System.Text.Json.JsonSerializerOptions { WriteIndented = true }).Replace("\r\n", "\n", StringComparison.Ordinal) + "\n", md.ToString().Replace("\r\n", "\n", StringComparison.Ordinal), complete);
    }
}
