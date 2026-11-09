#!/usr/bin/env -S dotnet --
#:property TargetFramework=net10.0
#:property PublishAot=false
#:include Shared/ScriptSupport.cs
using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;

return await ScriptHost.ExecuteAsync(args,
    "dotnet run --file tools/Check-ModuleCoverage.cs -- --module=platform|hosting --results=<directory>",
    args.Where(a => a.StartsWith("--module=", StringComparison.Ordinal) || a.StartsWith("--results=", StringComparison.Ordinal)).ToArray(), async ct =>
{
    string root = ScriptHost.RepositoryRoot();
    string module = args.Single(a => a.StartsWith("--module=", StringComparison.Ordinal))[9..];
    using var policies = JsonDocument.Parse(File.ReadAllText(Path.Combine(root, "tests/module-coverage-policy.json")));
    var policy = policies.RootElement.GetProperty(module);
    string results = ScriptHost.Within(root, args.Single(a => a.StartsWith("--results=", StringComparison.Ordinal))[10..]);
    var trx = XDocument.Load(Path.Combine(results, module + ".trx"));
    XNamespace ns = trx.Root!.Name.Namespace;
    var outcomes = trx.Descendants(ns + "UnitTestResult").ToArray();
    if (outcomes.Length < policy.GetProperty("minimumTests").GetInt32() || outcomes.Any(r => (string?)r.Attribute("outcome") != "Passed"))
        throw new InvalidDataException("All module tests must pass without skips; missing test results are rejected.");
    var attachments = trx.Descendants(ns + "UriAttachment").Select(e => e.Element(ns + "A")?.Attribute("href")?.Value)
        .OfType<string>().Where(p => p.EndsWith("coverage.cobertura.xml", StringComparison.OrdinalIgnoreCase)).ToArray();
    if (attachments.Length != 1) throw new InvalidDataException("Expected exactly one current TRX coverage attachment.");
    string attachment = attachments[0].Replace('\\', Path.DirectorySeparatorChar);
    string path = ScriptHost.Within(results, attachment);
    if (!File.Exists(path)) path = ScriptHost.Within(results, Path.Combine(trx.Descendants(ns + "Deployment").Single().Attribute("runDeploymentRoot")!.Value, "In", attachment));
    var coverage = XDocument.Load(path);
    string assembly = policy.GetProperty("assembly").GetString()!;
    var package = coverage.Descendants("package").Single(e => (string?)e.Attribute("name") == assembly);
    var classes = package.Descendants("class").Where(e => !((string?)e.Attribute("filename") ?? "").Replace('\\', '/').Split('/').Contains("obj", StringComparer.Ordinal)).ToArray();
    var lines = classes.SelectMany(c => c.Element("lines")!.Elements("line")).ToArray();
    var methods = classes.SelectMany(c => c.Element("methods")!.Elements("method"))
        .Select(m => m.Element("lines")!.Elements("line").ToArray()).Where(m => m.Length > 0).ToArray();
    int branches = 0, hitBranches = 0;
    foreach (var line in lines.Where(l => string.Equals((string?)l.Attribute("branch"), "true", StringComparison.OrdinalIgnoreCase)))
    {
        var match = Regex.Match((string?)line.Attribute("condition-coverage") ?? "", @"\((\d+)/(\d+)\)");
        if (!match.Success) throw new InvalidDataException("Missing branch counts.");
        hitBranches += int.Parse(match.Groups[1].Value, CultureInfo.InvariantCulture);
        branches += int.Parse(match.Groups[2].Value, CultureInfo.InvariantCulture);
    }
    var metrics = new Dictionary<string, double>
    {
        ["methodPercent"] = Percent(methods.Count(m => m.Any(l => (int)l.Attribute("hits")! > 0)), methods.Length),
        ["linePercent"] = Percent(lines.Count(l => (int)l.Attribute("hits")! > 0), lines.Length),
        ["branchPercent"] = Percent(hitBranches, branches)
    };
    foreach (var (key, value) in metrics)
        if (value < policy.GetProperty(key).GetDouble())
            throw new InvalidDataException($"{module} {key}: {value:F4}% below {policy.GetProperty(key).GetDouble()}%.");
    var rows = metrics.Select(kv => $"| `{kv.Key}` | {kv.Value.ToString("F4", CultureInfo.InvariantCulture)}% | {policy.GetProperty(kv.Key).GetDouble().ToString(CultureInfo.InvariantCulture)}% |");
    string report = $"# {assembly} 单元覆盖率\n\nMSTest {outcomes.Length}/{outcomes.Length}，无跳过或失败。只统计本包自有源码，排除 `obj/` 生成代码。\n\n"
        + "| 指标 | 实测 | 门槛 |\n| --- | --- | --- |\n" + string.Join('\n', rows)
        + "\n\n由本次 TRX 关联的 Cobertura 生成；门槛见 [module-coverage-policy.json](../../tests/module-coverage-policy.json)。单元覆盖率不等于真实服务器、浏览器或 Azure 云端验收。\n";
    await File.WriteAllTextAsync(Path.Combine(root, "docs/contracts/" + module + "-coverage.md"), report, ct);
    Console.WriteLine($"PASS {module}: {outcomes.Length} tests; " + string.Join(", ", metrics.Select(kv => $"{kv.Key}={kv.Value:F4}%")));
});

static double Percent(int covered, int total) => total > 0 && covered >= 0 && covered <= total
    ? covered * 100d / total : throw new InvalidDataException("Empty or invalid coverage counts are rejected.");
