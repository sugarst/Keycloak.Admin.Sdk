#!/usr/bin/env -S dotnet --
#:property TargetFramework=net10.0
#:property PublishAot=false
#:include ScriptSupport.cs

using System.Text;
using System.Text.Json;

return await ScriptHost.ExecuteAsync(args, "dotnet run --file tools/Generate-ValidationList.cs", [], async ct =>
{
    string root = ScriptHost.RepositoryRoot(), docs = Path.Combine(root, "docs/contracts");
    Dictionary<string, string[]> Read(string name, int count)
    {
        var rows = File.ReadAllLines(Path.Combine(docs, name)).Skip(1).Select(l => l.Split('\t')).ToArray();
        if (rows.Any(r => r.Length != count)) throw new InvalidDataException("Malformed evidence table: " + name);
        return rows.ToDictionary(r => r[0] + " " + r[1], StringComparer.Ordinal);
    }
    var scope = Read("admin-api-support-matrix.tsv", 7);
    var live = Read("full-live-acceptance.tsv", 7);
    if (scope.Count != 520 || !scope.Keys.ToHashSet().SetEquals(live.Keys)) throw new InvalidDataException("Expected matching 520-operation inventories.");
    bool Pass(string[] row, int column) => row[column].StartsWith("PASS ", StringComparison.Ordinal);
    foreach (var (key, row) in scope)
    {
        var result = live[key];
        if (Pass(result, 2) != (row[3] == "in-scope") || Pass(result, 3) != (row[3] == "in-scope") || Pass(result, 4) != (row[5] == "in-scope") || Pass(result, 5) != (row[5] == "in-scope")) throw new InvalidDataException("Scope/acceptance mismatch: " + key);
    }
    string Cell(string value) => value.Replace("|", "\\|", StringComparison.Ordinal).Replace('\n', ' ').Replace('\r', ' ');
    string Status(string[] row, int column) => Pass(row, column) ? "通过 " + row[column][5..] : "政策排除";
    string Reason(string[] row) => row[5] != "in-scope" ? row[6].StartsWith("ssf ", StringComparison.Ordinal) ? "SSF：26.8.1 为 EXPERIMENTAL，按要求不做真实验收" : row[6].StartsWith("oid4vc-vci ", StringComparison.Ordinal) ? "OID4VC：26.8.1 为 PREVIEW，按要求不做真实验收" : "Client Types：26.8.1 为 EXPERIMENTAL，按要求不做真实验收" : row[3] != "in-scope" ? "v1 专用管理权限接口：v1 已实测，v2 路线不调用" : "两条路线均已真实验证";
    var md = new StringBuilder("# Keycloak 26.8.1 已落地接口与验证清单\n\n计数单位：HTTP 方法 + 路径模板，共 520 项（官方 OpenAPI 415 项、发布源码补充 105 项）。每项均有 SDK 方法和独立契约单测。\n\n本表整理已有验收证据，不代表本次重新执行全部容器测试。真实验收环境为 Keycloak 26.8.1 + PostgreSQL 18.0，.NET SDK 10.0.403，Native AOT 目标 linux-musl-x64。\n\n| 路线 | 托管已验证 | AOT 已验证 | 未完成 | 政策排除 |\n| --- | --- | --- | --- | --- |\n| v2 正式（默认） | 478 | 478 | 0 | 42 |\n| v1 兼容（显式启用） | 492 | 492 | 0 | 28 |\n\n两条路线的已验证集合有重叠：合计 492 个不同接口已有真实业务验证；28 个接口没有真实容器验收。v2 的 42 项排除 = 28 项预览/实验 + 14 项仅供 v1 兼容的接口。排除不能记为通过。\n\n## 实跑时间（北京时间）\n\n");
    foreach (string route in new[] { "fgap-v2-stable", "fgap-v1-compat" }) foreach (string mode in new[] { "managed", "native-aot" })
    {
        using var manifest = JsonDocument.Parse(File.ReadAllText(Path.Combine(docs, "full-live-evidence/" + route + "-" + mode + ".json")));
        DateTimeOffset finished = DateTimeOffset.Parse(manifest.RootElement.GetProperty("finishedUtc").GetString()!, System.Globalization.CultureInfo.InvariantCulture).ToOffset(TimeSpan.FromHours(8));
        md.AppendLine($"- `{route}` / `{mode}`：{finished:yyyy-MM-dd HH:mm:ss}（UTC+08:00）");
    }
    md.AppendLine("\n## 没有真实容器验收的 28 项\n\n下表项目保留 wire 方法及契约单测；未开启对应预览/实验功能，也未记为业务验收成功。路径均相对于 `/admin/realms/{realm}`。\n\n| 方法 | 路径 | 未验证原因 |\n| --- | --- | --- |");
    foreach (var row in scope.Values.Where(r => r[5] != "in-scope").OrderBy(r => r[1], StringComparer.Ordinal).ThenBy(r => r[0], StringComparer.Ordinal)) md.AppendLine($"| {row[0]} | `{row[1].Replace("/admin/realms/{realm}", "", StringComparison.Ordinal)}` | {Reason(row)} |");
    md.AppendLine("\n## 仅在 v1 兼容路线验证的 14 项\n\n这些接口已通过托管/AOT 实跑，v2 正式路线不调用旧版管理权限接口。\n\n| 方法 | 路径（相对 realm） | v1 托管 | v1 AOT |\n| --- | --- | --- | --- |");
    foreach (var row in scope.Values.Where(r => r[3] != "in-scope" && r[5] == "in-scope").OrderBy(r => r[1], StringComparer.Ordinal).ThenBy(r => r[0], StringComparer.Ordinal)) md.AppendLine($"| {row[0]} | `{row[1].Replace("/admin/realms/{realm}", "", StringComparison.Ordinal)}` | {Status(live[row[0] + " " + row[1]], 4)} | {Status(live[row[0] + " " + row[1]], 5)} |");
    md.AppendLine("\n## 全部 520 项逐接口明细\n\n按 SDK 资源入口分组。通过代表该方法/路径至少一个真实业务场景通过，包含写入后的持久化或协议效果断言、读取已知真实数据等；不代表穷尽该接口的所有参数、权限组合、策略类型和第三方 SPI 行为。业务证明保留测试中的原文。\n");
    foreach (var group in scope.Values.GroupBy(r => r[2].Split('.')[0]).OrderBy(g => g.Key, StringComparer.Ordinal))
    {
        md.AppendLine($"### {group.Key}（{group.Count()} 项）\n\n| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |\n| --- | --- | --- | --- | --- | --- | --- | --- |");
        foreach (var row in group.OrderBy(r => r[1], StringComparer.Ordinal).ThenBy(r => r[0], StringComparer.Ordinal))
        {
            var result = live[row[0] + " " + row[1]];
            string proof = row[5] == "in-scope" ? result[6] : Reason(row);
            md.AppendLine($"| {row[0]} | `{row[1]}` | `{row[2]}` | {Status(result, 2)} | {Status(result, 3)} | {Status(result, 4)} | {Status(result, 5)} | {Cell(proof)} |");
        }
        md.AppendLine();
    }
    md.AppendLine("## 证据与边界\n\n- [逐接口原始业务表](full-live-acceptance.tsv)、[支持范围及原因](admin-api-support-matrix.tsv)、[接口到发布源码位置](endpoint-inventory.md)。\n- [验收汇总及证据清单](full-live-acceptance.md)、[单测和覆盖率](test-coverage.md)、[声明式路线](admin-api-routing.md)。\n- 本地实测证明不等于 Windows win-x64 Native AOT 或远端 CI 已通过，也不代表已覆盖所有参数、权限、配置或外部商业服务组合。\n\n重建本清单：`dotnet run --file tools/Generate-ValidationList.cs`。\n");
    await File.WriteAllTextAsync(Path.Combine(docs, "admin-api-validation-list.md"), md.ToString().TrimEnd() + "\n", ct);
    Console.WriteLine("Generated 520-operation Markdown list: 492 real-verified unique operations; 28 without real acceptance; 14 v1-only verified.");
});
