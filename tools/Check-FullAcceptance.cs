#!/usr/bin/env -S dotnet --
#:property TargetFramework=net10.0
#:property PublishAot=false
#:include ScriptSupport.cs
#:include TargetBaseline.cs
#:include ../tests/Keycloak.Admin.Sdk.IntegrationTests/KeycloakRouteSupport.cs
#:include ../tests/Keycloak.Admin.Sdk.IntegrationTests/LiveEvidence.cs
#:project ../src/Keycloak.Admin.Sdk/Keycloak.Admin.Sdk.csproj

using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Keycloak.Admin.Sdk;

return await ScriptHost.ExecuteAsync(args, "dotnet run --file tools/Check-FullAcceptance.cs -- [--v2|--v1] [--update-docs] [--evidence=<artifacts-subdirectory>]", ["--v2", "--v1", "--update-docs", "--bootstrap", .. args.Where(a => a.StartsWith("--evidence=", StringComparison.Ordinal))], async ct =>
{
    if (args.Contains("--v1") && args.Contains("--v2")) throw new ArgumentException("Choose one route, or neither for both.");
    if (args.Contains("--update-docs") && (args.Contains("--v1") || args.Contains("--v2"))) throw new ArgumentException("Documentation requires both routes and both execution modes.");
    string root = ScriptHost.RepositoryRoot(), fingerprint = LiveEvidence.Fingerprint(root);
    string evidenceDirectory = ScriptHost.Within(Path.Combine(root, "artifacts"), args.SingleOrDefault(a => a.StartsWith("--evidence=", StringComparison.Ordinal))?[11..] ?? "full-live");
    if (args.Contains("--update-docs") && args.Any(a => a.StartsWith("--evidence=", StringComparison.Ordinal))) throw new ArgumentException("Documentation requires the original full-live evidence directory.");
    string[] routes = args.Contains("--v2") ? ["fgap-v2-stable"] : args.Contains("--v1") ? ["fgap-v1-compat"] : ["fgap-v2-stable", "fgap-v1-compat"];
    bool bootstrap = args.Contains("--bootstrap");
    if (bootstrap && args.Contains("--update-docs")) throw new ArgumentException("Bootstrap evidence cannot be exported as release evidence.");
    var target = TargetBaseline.Load(root);
    string[] modes = ["managed", "native-aot"];
    var evidence = new Dictionary<string, Dictionary<string, (string Status, string Proof)>>(StringComparer.Ordinal);
    var reports = new List<string>();
    var exports = new List<(string Source, string Target)>();
    foreach (string routeId in routes)
    {
        var route = KeycloakRoute.Load(root, routeId);
        var expected = AdminEndpointCatalog.All.Where(e => route.Exclusion(e.Path) is null).Select(e => e.Method + "\t" + e.Path).ToHashSet(StringComparer.Ordinal);
        foreach (string mode in modes)
        {
            string prefix = Path.Combine(evidenceDirectory, routeId + "-" + mode);
            using var manifest = JsonDocument.Parse(await File.ReadAllTextAsync(prefix + ".json", ct));
            var m = manifest.RootElement;
            if (m.GetProperty("route").GetString() != routeId || m.GetProperty("mode").GetString() != mode || !m.GetProperty("completed").GetBoolean()
                || m.GetProperty("missing").GetInt32() != 0 || m.GetProperty("accepted").GetInt32() != expected.Count || m.GetProperty("expected").GetInt32() != expected.Count
                || m.GetProperty("sourceFingerprint").GetString() != fingerprint || m.GetProperty("evidence").GetProperty("serverVersion").GetString() != target.Version
                || m.GetProperty("evidence").GetProperty("postgres").GetProperty("versionNumber").GetString() != target.PostgresVersionNumber) throw new InvalidDataException("Incomplete, wrong-server or stale acceptance manifest: " + prefix);
            var delegation = m.GetProperty("evidence").GetProperty("fgapDelegation");
            if (m.GetProperty("evidence").GetProperty("supportPolicy").GetString() != (bootstrap ? "bootstrap-wire" : "catalog-conjunctive-v1") || m.GetProperty("evidence").GetProperty("supportPolicyLocalGuards").GetBoolean() != !bootstrap) throw new InvalidDataException("Real acceptance must use the support policy and verify local guards.");
            if (m.GetProperty("evidence").GetProperty("featureManagement").GetString() != (mode == "managed" ? bootstrap ? "not-loaded-bootstrap" : "microsoft-4.8.0" : "not-loaded-native-aot")
                || m.GetProperty("evidence").GetProperty("featureManagementBusinessGuards").GetBoolean() != (mode == "managed" && !bootstrap)) throw new InvalidDataException("FeatureManagement evidence must match managed-only extension scope.");
            if (!delegation.GetProperty("initialDenied").GetBoolean() || !delegation.GetProperty("grantAllowsReadAndWrite").GetBoolean() || !delegation.GetProperty("revocationDenied").GetBoolean()) throw new InvalidDataException("FGAP delegation must be verified against real server.");
            var features = m.GetProperty("evidence").GetProperty("features").EnumerateArray().ToArray();
            string desired = route.FgapVersion == 1 ? "ADMIN_FINE_GRAINED_AUTHZ" : "ADMIN_FINE_GRAINED_AUTHZ_V2";
            if (!features.Any(f => f.GetProperty("name").GetString() == desired && f.GetProperty("enabled").GetBoolean()) || features.Any(f => f.GetProperty("enabled").GetBoolean() && f.GetProperty("type").GetString() is "PREVIEW" or "PREVIEW_DISABLED_BY_DEFAULT" or "EXPERIMENTAL")) throw new InvalidDataException("Manifest runtime features violate declared support route.");
            var actual = new Dictionary<string, (string Status, string Proof)>(StringComparer.Ordinal);
            foreach (string row in (await File.ReadAllLinesAsync(prefix + ".tsv", ct)).Skip(1))
            {
                string[] f = row.Split('\t');
                if (f.Length != 4 || !int.TryParse(f[2], out int status) || status is < 200 or >= 300 || string.IsNullOrWhiteSpace(f[3]) || !actual.TryAdd(f[0] + "\t" + f[1], (f[2], f[3]))) throw new InvalidDataException("Invalid or duplicate business proof: " + prefix);
            }
            string hash = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(prefix + ".tsv", ct))).ToLowerInvariant();
            if (!expected.SetEquals(actual.Keys) || hash != m.GetProperty("ledgerSha256").GetString() || (await File.ReadAllLinesAsync(prefix + "-missing.tsv", ct)).Length != 0) throw new InvalidDataException("Missing, altered or unsupported acceptance rows: " + prefix);
            var exclusions = (await File.ReadAllLinesAsync(prefix + "-excluded.tsv", ct)).Skip(1).Select(l => l.Split('\t')).ToArray();
            var expectedExclusions = AdminEndpointCatalog.All.Where(e => route.Exclusion(e.Path) is not null).Select(e => e.Method + "\t" + e.Path + "\t" + route.Exclusion(e.Path)).ToHashSet(StringComparer.Ordinal);
            if (exclusions.Length != expectedExclusions.Count || !expectedExclusions.SetEquals(exclusions.Select(f => string.Join('\t', f))) || m.GetProperty("excluded").GetInt32() != expectedExclusions.Count) throw new InvalidDataException("Invalid exclusion ledger.");
            evidence.Add(routeId + "/" + mode, actual);
            reports.Add($"| `{routeId}` | {mode} | {actual.Count}/{expected.Count} | 0 | {exclusions.Length} | {m.GetProperty("finishedUtc").GetString()} |");
            exports.Add((prefix + ".json", "full-live-evidence/" + routeId + "-" + mode + ".json"));
            Console.WriteLine($"PASS full acceptance gate: {routeId}/{mode} = {actual.Count}/{expected.Count}; current source fingerprint verified.");
        }
    }
    if (!args.Contains("--update-docs")) return;
    string docs = Path.Combine(root, "docs/contracts"); Directory.CreateDirectory(Path.Combine(docs, "full-live-evidence"));
    var images = new JsonObject { ["checkedUtc"] = DateTimeOffset.UtcNow.ToString("O") };
    using var baseline = ScriptHost.Baseline(root);
    foreach (string service in new[] { "keycloak", "postgres" })
    {
        var running = await ScriptHost.RunCheckedAsync(root, "docker", ["inspect", "--format", "{{.Image}}", "keycloak-admin-sdk-local-" + service + "-1"], ct, capture: true);
        string imageId = running.StandardOutput.Trim();
        var digests = await ScriptHost.RunCheckedAsync(root, "docker", ["image", "inspect", "--format", "{{json .RepoDigests}}", imageId], ct, capture: true);
        using var parsed = JsonDocument.Parse(digests.StandardOutput);
        string[] official = parsed.RootElement.EnumerateArray().Select(d => d.GetString()!).Where(d => d.StartsWith(service == "keycloak" ? "quay.io/keycloak/keycloak@" : "postgres@", StringComparison.Ordinal)).ToArray();
        if (official.Length == 0 || service == "keycloak" && !official.Contains(baseline.RootElement.GetProperty("serverImage").GetString())) throw new InvalidDataException("Actual running service image differs from pinned release: " + service);
        images[service] = new JsonObject { ["imageId"] = imageId, ["officialDigests"] = new JsonArray(official.Select(d => (JsonNode?)JsonValue.Create(d)).ToArray()) };
    }
    await File.WriteAllTextAsync(Path.Combine(docs, "full-live-evidence/container-images.json"), images.ToJsonString(), ct);
    foreach (var (source, destination) in exports) File.Copy(source, Path.Combine(docs, destination), overwrite: true);
    var rows = new List<string> { "method\tpath\tfgapV2Managed\tfgapV2NativeAot\tfgapV1Managed\tfgapV1NativeAot\tproof" };
    foreach (var endpoint in AdminEndpointCatalog.All)
    {
        string key = endpoint.Method + "\t" + endpoint.Path;
        string[] cells = (from route in routes from mode in modes select evidence[route + "/" + mode].TryGetValue(key, out var proof) ? "PASS " + proof.Status : "EXCLUDED: " + KeycloakRoute.Load(root, route).Exclusion(endpoint.Path)).ToArray();
        string assertion = evidence.Values.Select(v => v.TryGetValue(key, out var p) ? p.Proof : null).FirstOrDefault(p => p is not null) ?? "Outside both declared support routes";
        rows.Add(key + "\t" + string.Join('\t', cells) + "\t" + assertion);
    }
    await File.WriteAllLinesAsync(Path.Combine(docs, "full-live-acceptance.tsv"), rows, ct);
    await File.WriteAllTextAsync(Path.Combine(docs, "full-live-acceptance.md"), $"# 真实容器全功能验收\n\n固定服务：Keycloak {target.Version} + {target.PostgresImage}；构建 SDK {target.Sdk}，Native AOT 目标 linux-musl-x64。\n\n| 路线 | 执行方式 | 业务断言通过 | 未完成 | 政策排除 | 完成时间 UTC |\n| --- | --- | --- | --- | --- | --- |\n" + string.Join('\n', reports) + "\n\n逐接口结果和业务断言见 [full-live-acceptance.tsv](full-live-acceptance.tsv)。排除项不计入成功。范围和排除数量以当前基线及上述实测表为准。\n\n托管入口使用 Microsoft FeatureManagement 4.8.0，在目录判断后检查总开关及功能开关，并实际验证关闭创建无数据、开启创建持久化、关闭删除保留数据和刷新后删除成功。Native AOT 入口编译时排除两个托管扩展，仍使用能力策略；manifest 分别标识 microsoft-4.8.0 和 not-loaded-native-aot。Application Insights 仅做本地事件测试，未启用云端投递。\n\n全部结果来自真实 SDK 请求。写操作核对持久化或协议侧效果；只读操作核对已知真实资源、关系或已安装提供方。认证、SMTP、HTTP/JWKS、LDAP、X509/CRL 和 PostgreSQL 缓存验证均实际通信。外部协议夹具由 .NET 10 实现，LDAP 使用独立真实 OpenLDAP 容器。完整 wire 契约单测仍覆盖完整发布清单，政策排除不代表漏写单测。\n\n证据清单保留实际版本、功能开关、数据库版本、原生/托管程序 SHA256、逐项 ledger SHA256 和代码指纹。门禁拒绝缺失、重复、非成功、无业务证明、旧源码或未完成记录。该验收覆盖每个支持范围内的方法/路径的业务场景，不宣称穷尽所有配置、策略类型和管理员权限组合。\n\n重跑两个路线的 `Service.cs -- test-full` 与 `-- test-full-native`，然后执行 `dotnet run --file tools/Check-FullAcceptance.cs -- --update-docs`。路线声明与切换见 [admin-api-routing.md](admin-api-routing.md)。\n", ct);
    // Upgrade the existing inventory's live column without conflating policy exclusions with success.
    string inventory = Path.Combine(docs, "endpoint-inventory.md");
    var routing = (await File.ReadAllLinesAsync(Path.Combine(root, "artifacts/routing-verified.tsv"), ct)).ToHashSet(StringComparer.Ordinal);
    if (!routing.SetEquals(AdminEndpointCatalog.All.Select(e => e.Method + "\t" + e.Path))) throw new InvalidDataException("Complete current routing evidence is required for inventory export.");
    string[] lines = await File.ReadAllLinesAsync(inventory, ct);
    for (int i = 0; i < lines.Length; i++)
    {
        if (lines[i].StartsWith("Generated from the pinned", StringComparison.Ordinal))
            lines[i] = "Generated from the pinned OpenAPI, audited overrides and reachable Java resource locators. `routing pass` records independent SDK contract tests; `business pass` records real Keycloak/PostgreSQL business assertions in the named routes and managed/Native AOT modes. `excluded` records the declared release policy, never a successful test. See [business evidence](full-live-acceptance.md) and [support routes](admin-api-routing.md).";
        if (!lines[i].StartsWith("| ", StringComparison.Ordinal)) continue;
        var f = lines[i].Split('|'); if (f.Length != 8) continue;
        string key = f[1].Trim() + "\t" + f[2].Trim().Trim('`');
        if (!AdminEndpointCatalog.All.Any(e => e.Method + "\t" + e.Path == key)) continue;
        f[5] = " routing pass ";
        f[6] = evidence["fgap-v2-stable/managed"].ContainsKey(key) ? " business pass: v2/v1 managed+AOT " : evidence["fgap-v1-compat/managed"].ContainsKey(key) ? " business pass: v1 compat managed+AOT " : " excluded: preview/experimental ";
        lines[i] = string.Join('|', f);
    }
    await File.WriteAllLinesAsync(inventory, lines, ct);
});
