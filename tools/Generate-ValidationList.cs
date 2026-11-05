#!/usr/bin/env -S dotnet --
#:property TargetFramework=net10.0
#:property PublishAot=false
#:include ScriptSupport.cs
#:include TargetBaseline.cs

using System.Text;

return await ScriptHost.ExecuteAsync(args, "dotnet run --file tools/Generate-ValidationList.cs", [], async ct =>
{
    string root = ScriptHost.RepositoryRoot(), docs = Path.Combine(root, "docs/contracts");
    Dictionary<string, string[]> Read(string name, int count)
    {
        var rows = File.ReadAllLines(Path.Combine(docs, name)).Skip(1).Select(l => l.Split('\t')).ToArray();
        if (rows.Any(r => r.Length != count)) throw new InvalidDataException("Malformed evidence table: " + name);
        return rows.ToDictionary(r => r[0] + " " + r[1], StringComparer.Ordinal);
    }
    var target = TargetBaseline.Load(root);
    var scope = Read("admin-api-support-matrix.tsv", 7);
    var live = Read("full-live-acceptance.tsv", 7);
    if (scope.Count != target.Endpoints || !scope.Keys.ToHashSet().SetEquals(live.Keys)) throw new InvalidDataException("Expected matching current-target operation inventories.");
    bool Pass(string[] row, int column) => row[column].StartsWith("PASS ", StringComparison.Ordinal);
    foreach (var (key, row) in scope)
    {
        var result = live[key];
        if (Pass(result, 2) != (row[3] == "in-scope") || Pass(result, 3) != (row[3] == "in-scope") || Pass(result, 4) != (row[5] == "in-scope") || Pass(result, 5) != (row[5] == "in-scope")) throw new InvalidDataException("Scope/acceptance mismatch: " + key);
    }
    string Cell(string value) => value.Replace("|", "\\|", StringComparison.Ordinal).Replace('\n', ' ').Replace('\r', ' ');
    int v2 = scope.Values.Count(r => r[3] == "in-scope"), v1 = scope.Values.Count(r => r[5] == "in-scope");
    var md = new StringBuilder($"# Keycloak {target.Version} 接口验证索引\n\n由 `tools/Generate-ValidationList.cs` 从支持矩阵与真实业务表生成，共 {target.Endpoints} 个 HTTP 方法 + 路径。v2 正式范围 {v2} 项，v1 兼容范围 {v1} 项，两者均有托管及 Linux Native AOT 业务证明。执行时间和环境见 [验收汇总](full-live-acceptance.md)。\n\n## 按资源入口\n\n下表汇总各 SDK 资源；完整路径、方法、四种执行结果和业务断言保留在 [逐接口业务表](full-live-acceptance.tsv)，此处不重复展开。\n\n| SDK 资源 | wire 操作 | v2 已验证 | v1 已验证 | 两路线均排除 |\n| --- | --- | --- | --- | --- |\n");
    foreach (var group in scope.Values.GroupBy(r => r[2].Split('.')[0]).OrderBy(g => g.Key, StringComparer.Ordinal))
        md.AppendLine($"| {group.Key} | {group.Count()} | {group.Count(r => r[3] == "in-scope")} | {group.Count(r => r[5] == "in-scope")} | {group.Count(r => r[3] != "in-scope" && r[5] != "in-scope")} |");
    md.AppendLine("\n## 政策排除\n\n排除项仍保留 wire 方法和契约单测，不计为真实业务通过。逐项分类见 [支持矩阵](admin-api-support-matrix.tsv)。\n\n| 适用范围 | 操作数 | 原因 |\n| --- | --- | --- |");
    foreach (var group in scope.Values.Where(r => r[5] != "in-scope").GroupBy(r => r[6]).OrderBy(g => g.Key, StringComparer.Ordinal))
        md.AppendLine($"| 两条路线 | {group.Count()} | {Cell(group.Key)} |");
    foreach (var group in scope.Values.Where(r => r[3] != "in-scope" && r[5] == "in-scope").GroupBy(r => r[4]).OrderBy(g => g.Key, StringComparer.Ordinal))
        md.AppendLine($"| 仅 v2 | {group.Count()} | {Cell(group.Key)} |");
    md.AppendLine("\n## 详细证据\n\n- [端点及发布源码位置](endpoint-inventory.md) · [独立单测映射](admin-api-test-matrix.md) · [覆盖率](test-coverage.md)。\n- [路线声明与校验](admin-api-routing.md) · [发布边界](verification.md)。\n\n重建：`dotnet run --file tools/Generate-ValidationList.cs`。\n");
    await File.WriteAllTextAsync(Path.Combine(docs, "admin-api-validation-list.md"), md.ToString().TrimEnd() + "\n", ct);
    Console.WriteLine($"Generated {target.Endpoints}-operation verification index for {target.Version}.");
});
