#!/usr/bin/env -S dotnet --
#:property TargetFramework=net10.0
#:property PublishAot=false
#:include ScriptSupport.cs
#:project ../src/Keycloak.Admin.Sdk/Keycloak.Admin.Sdk.csproj

using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Keycloak.Admin.Sdk;

return await ScriptHost.ExecuteAsync(args, "dotnet run --file tools/Check-Coverage.cs -- [--results=artifacts/test-results] [--self-test]",
    ["--self-test", .. args.Where(a => a.StartsWith("--results=", StringComparison.Ordinal))], async ct =>
{
    string root = ScriptHost.RepositoryRoot();
    using var policy = JsonDocument.Parse(await File.ReadAllTextAsync(Path.Combine(root, "tests/coverage-policy.json"), ct));
    if (args.Contains("--self-test"))
    {
        GateSelfTests(policy.RootElement);
        Console.WriteLine("PASS: coverage gate rejects missing, duplicate, skipped/failed matrix tests and every under-threshold metric.");
        return;
    }
    string relative = args.FirstOrDefault(a => a.StartsWith("--results=", StringComparison.Ordinal))?["--results=".Length..] ?? "artifacts/test-results";
    string results = ScriptHost.Within(root, relative);
    var trx = XDocument.Load(Path.Combine(results, "contracts.trx"));
    XNamespace ns = trx.Root!.Name.Namespace;
    var definitions = trx.Descendants(ns + "UnitTest").ToDictionary(e => (string)e.Attribute("id")!, e => e.Element(ns + "TestMethod")!);
    var outcomes = trx.Descendants(ns + "UnitTestResult").ToArray();
    var matrixResults = outcomes.Where(e => definitions[(string)e.Attribute("testId")!].Attribute("className")!.Value.Split(',')[0] == "EndpointMatrixTests")
        .Select(e => (Name: definitions[(string)e.Attribute("testId")!].Attribute("name")!.Value, Passed: (string?)e.Attribute("outcome") == "Passed")).ToArray();
    var contracts = JsonNode.Parse(await File.ReadAllTextAsync(Path.Combine(root, "contracts/admin-api-test-matrix.json"), ct))!.AsArray();
    using var baseline = ScriptHost.Baseline(root);
    if (contracts.Count != baseline.RootElement.GetProperty("discoveredEndpoints").GetInt32()) throw new InvalidDataException("The matrix must cover the pinned release operation count.");
    string Key(string method, string path) => method + " " + Regex.Replace(path.TrimEnd('/'), @"\{[^}]+\}", "{}");
    var contractKeys = contracts.Select(c => Key(c!["method"]!.GetValue<string>(), c["path"]!.GetValue<string>())).ToArray();
    if (contractKeys.Distinct().Count() != contracts.Count || contracts.Count != AdminEndpointCatalog.All.Count
        || !contractKeys.ToHashSet().SetEquals(AdminEndpointCatalog.All.Select(e => Key(e.Method, e.Path))))
        throw new InvalidDataException("Matrix contracts and compiled SDK operations must form a bijection.");
    ValidateResults(contracts.Count, matrixResults);
    if (outcomes.Length == 0 || outcomes.Any(e => (string?)e.Attribute("outcome") != "Passed")) throw new InvalidDataException("All tests must pass; skipped/not-executed tests are rejected.");
    // Resolve the current TRX attachment, never a stale or best-looking coverage file.
    var attachments = trx.Descendants(ns + "UriAttachment").Select(e => e.Element(ns + "A")?.Attribute("href")?.Value)
        .OfType<string>().Where(p => p.EndsWith("coverage.cobertura.xml", StringComparison.OrdinalIgnoreCase)).ToArray();
    if (attachments.Length != 1) throw new InvalidDataException("Expected exactly one Cobertura attachment in current TRX.");
    string attachment = attachments[0].Replace('\\', Path.DirectorySeparatorChar);
    string coveragePath = ScriptHost.Within(results, attachment);
    if (!File.Exists(coveragePath))
    {
        string deployment = trx.Descendants(ns + "Deployment").Single().Attribute("runDeploymentRoot")!.Value;
        coveragePath = ScriptHost.Within(results, Path.Combine(deployment, "In", attachment));
    }
    var coverage = XDocument.Load(coveragePath);
    var packages = coverage.Descendants("package").Where(p => (string?)p.Attribute("name") == "Keycloak.Admin.Sdk").ToArray();
    if (packages.Length != 1) throw new InvalidDataException("Missing or duplicate SDK coverage package.");
    var classes = packages[0].Descendants("class").ToArray();
    var source = classes.Where(e => !FileName(e).StartsWith("obj/", StringComparison.Ordinal)).ToArray();
    var sdk = Measure(source);
    var api = Measure(source.Where(e => Regex.IsMatch(FileName(e), @"^Generated/.*Api\.g\.cs$")));
    var models = Measure(source.Where(e => FileName(e) == "Generated/Models.g.cs"));
    var raw = Measure(classes);
    var metrics = new Dictionary<string, double>
    {
        ["matrixOperationPercent"] = Percent(matrixResults.Length, contracts.Count),
        ["sdkSourceMethodPercent"] = Percent(sdk.MethodsCovered, sdk.Methods), ["sdkSourceLinePercent"] = Percent(sdk.LinesCovered, sdk.Lines),
        ["sdkSourceBranchPercent"] = Percent(sdk.BranchesCovered, sdk.Branches),
        ["apiWrapperLinePercent"] = Percent(api.LinesCovered, api.Lines), ["apiWrapperBranchPercent"] = Percent(api.BranchesCovered, api.Branches),
        ["modelLinePercent"] = Percent(models.LinesCovered, models.Lines),
        ["rawLinePercent"] = Percent(raw.LinesCovered, raw.Lines), ["rawBranchPercent"] = Percent(raw.BranchesCovered, raw.Branches)
    };
    ValidateThresholds(policy.RootElement, metrics);
    var summary = new JsonObject { ["operations"] = contracts.Count, ["passedTests"] = outcomes.Length, ["matrixPassed"] = matrixResults.Length };
    var report = new StringBuilder("# Admin API 单元测试覆盖率门禁\n\n所有 Admin API SDK 操作已有独立发现且通过的功能契约单元测试。此结论指 SDK 请求/响应契约及客户端行为，真实 Keycloak 的业务/权限场景覆盖另见 [验证记录](verification.md)。\n\n| 指标 | 实测 | 门槛 |\n| --- | --- | --- |\n");
    foreach (var (key, value) in metrics)
    {
        summary[key] = value;
        report.AppendLine($"| `{key}` | {value.ToString("F4", CultureInfo.InvariantCulture)}% | {policy.RootElement.GetProperty(key).GetDouble().ToString("0.####", CultureInfo.InvariantCulture)}% |");
        Console.WriteLine($"PASS {key}: {value:F4}%");
    }
    report.AppendLine($"\nMSTest {outcomes.Length}/{outcomes.Length} 通过；矩阵 {matrixResults.Length}/{contracts.Count}，无缺失、重复、跳过或失败。SDK 自有源码覆盖 {sdk.MethodsCovered}/{sdk.Methods} 个可执行方法、{sdk.LinesCovered}/{sdk.Lines} 行、{sdk.BranchesCovered}/{sdk.Branches} 个分支。\n");
    report.AppendLine("`sdkSource*` 保留仓库中的全部 SDK 生成 API、DTO 和手写代码，仅把 `obj/` 下 .NET SDK 生成的 JSON/正则实现另列为 raw 指标；原始 Cobertura 不删减。当前剩余一行是 token 方法 try 块的结束括号（所有路径 return/throw），PDB 将其计为零命中序列点，因此源码行门槛为 99.9%，分支及可执行方法门槛为 100%。框架生成实现的未执行分支不代表某个 Admin API 没有测试。\n");
    report.AppendLine("门禁读取本次 TRX 指向的 Cobertura，核验编译后 SDK、冻结契约矩阵和已执行测试的一一对应。任何操作缺少测试、跳过、失败或指标低于 [coverage-policy.json](../../tests/coverage-policy.json) 都返回非零。矩阵断言见 [操作清单](admin-api-test-matrix.md)；输入来自独立 Java token 索引和固定发布定义，不从 SDK 请求实现推导期望值。\n");
    await File.WriteAllTextAsync(Path.Combine(root, "artifacts/test-matrix-summary.json"), summary.ToJsonString(), ct);
    await File.WriteAllTextAsync(Path.Combine(root, "docs/contracts/test-coverage.md"), report.ToString().TrimEnd() + "\n", ct);
});

static string FileName(XElement e) => e.Attribute("filename")!.Value.Replace('\\', '/');
static double Percent(int covered, int total) => total > 0 && covered >= 0 && covered <= total ? covered * 100.0 / total : throw new InvalidDataException("Empty or invalid coverage counts are not accepted.");
static Coverage Measure(IEnumerable<XElement> classes)
{
    int lines = 0, covered = 0, branches = 0, branchesCovered = 0, methods = 0, methodsCovered = 0;
    foreach (var c in classes)
    {
        foreach (var line in c.Element("lines")!.Elements("line"))
        {
            lines++; if ((int)line.Attribute("hits")! > 0) covered++;
            if ((string?)line.Attribute("branch") == "true" || (string?)line.Attribute("branch") == "True")
            {
                var match = Regex.Match((string?)line.Attribute("condition-coverage") ?? "", @"\((\d+)/(\d+)\)");
                if (!match.Success) throw new InvalidDataException("Missing branch counts.");
                branchesCovered += int.Parse(match.Groups[1].Value, CultureInfo.InvariantCulture); branches += int.Parse(match.Groups[2].Value, CultureInfo.InvariantCulture);
            }
        }
        foreach (var method in c.Element("methods")!.Elements("method"))
        {
            var sequence = method.Element("lines")!.Elements("line").ToArray();
            if (sequence.Length == 0) continue;
            methods++; if (sequence.Any(e => (int)e.Attribute("hits")! > 0)) methodsCovered++;
        }
    }
    return new(covered, lines, branchesCovered, branches, methodsCovered, methods);
}
static void ValidateResults(int expected, (string Name, bool Passed)[] results)
{
    var names = Enumerable.Range(0, expected).Select(i => "Operation" + i.ToString("D3", CultureInfo.InvariantCulture)).ToHashSet();
    if (results.Length != expected || results.Any(r => !r.Passed) || results.Select(r => r.Name).Distinct().Count() != expected || !names.SetEquals(results.Select(r => r.Name)))
        throw new InvalidDataException("Every operation must have exactly one passing, non-skipped matrix test.");
}
static void ValidateThresholds(JsonElement policy, IReadOnlyDictionary<string, double> metrics)
{
    foreach (var threshold in policy.EnumerateObject())
        if (!metrics.TryGetValue(threshold.Name, out double value) || !double.IsFinite(value) || value < threshold.Value.GetDouble())
            throw new InvalidDataException("Coverage threshold failed: " + threshold.Name);
}
static void GateSelfTests(JsonElement policy)
{
    static void Reject(Action action)
    {
        try { action(); } catch (InvalidDataException) { return; }
        throw new InvalidOperationException("Coverage gate accepted a negative control.");
    }
    ValidateResults(2, [("Operation000", true), ("Operation001", true)]);
    Reject(() => ValidateResults(2, [("Operation000", true)]));
    Reject(() => ValidateResults(2, [("Operation000", true), ("Operation000", true)]));
    Reject(() => ValidateResults(2, [("Operation000", true), ("Operation001", false)]));
    Reject(() => ValidateResults(2, [("Operation000", true), ("Operation002", true)]));
    var metrics = policy.EnumerateObject().ToDictionary(p => p.Name, _ => 100d);
    ValidateThresholds(policy, metrics);
    foreach (var threshold in policy.EnumerateObject())
    {
        metrics[threshold.Name] = threshold.Value.GetDouble() - 0.001;
        Reject(() => ValidateThresholds(policy, metrics)); metrics[threshold.Name] = 100;
    }
    Reject(() => Percent(0, 0));
    Reject(() => Percent(-1, 2));
    Reject(() => Percent(3, 2));
}
sealed record Coverage(int LinesCovered, int Lines, int BranchesCovered, int Branches, int MethodsCovered, int Methods);
