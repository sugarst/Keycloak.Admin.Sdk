#!/usr/bin/env -S dotnet --
#:property TargetFramework=net10.0
#:property PublishAot=false
#:include ScriptSupport.cs
using System.Xml.Linq;

return await ScriptHost.ExecuteAsync(args, "dotnet run --file tools/Check-ProtocolCoverage.cs -- --results=<directory>",
    args.Where(a => a.StartsWith("--results=", StringComparison.Ordinal)).ToArray(), async ct =>
{
    string root = ScriptHost.RepositoryRoot();
    string results = ScriptHost.Within(root, args.Single(a => a.StartsWith("--results=", StringComparison.Ordinal))[10..]);
    var trx = XDocument.Load(Path.Combine(results, "protocols.trx")); XNamespace ns = trx.Root!.Name.Namespace;
    var outcomes = trx.Descendants(ns + "UnitTestResult").ToArray();
    if (outcomes.Length < 105 || outcomes.Any(r => (string?)r.Attribute("outcome") != "Passed"))
        throw new InvalidDataException("Complete protocol and platform tests must pass without skips.");
    var attachments = trx.Descendants(ns + "UriAttachment").Select(e => e.Element(ns + "A")?.Attribute("href")?.Value)
        .OfType<string>().Where(p => p.EndsWith("coverage.cobertura.xml", StringComparison.OrdinalIgnoreCase)).ToArray();
    if (attachments.Length != 1) throw new InvalidDataException("Expected one current TRX coverage attachment.");
    string attachment = attachments[0].Replace('\\', Path.DirectorySeparatorChar);
    string path = ScriptHost.Within(results, attachment);
    if (!File.Exists(path)) path = ScriptHost.Within(results, Path.Combine(trx.Descendants(ns + "Deployment").Single().Attribute("runDeploymentRoot")!.Value, "In", attachment));
    var coverage = XDocument.Load(path);
    var package = coverage.Descendants("package").Single(e => (string?)e.Attribute("name") == "Keycloak.Admin.Sdk.Protocols");
    var classes = package.Descendants("class").Where(e => !((string?)e.Attribute("filename") ?? "").Replace('\\', '/').Contains("/obj/", StringComparison.Ordinal)).ToArray();
    var lines = classes.SelectMany(c => c.Element("lines")!.Elements("line")).ToArray();
    if (lines.Length == 0 || lines.Any(l => (int)l.Attribute("hits")! <= 0)
        || lines.Any(l => (string?)l.Attribute("branch") == "true" && !((string?)l.Attribute("condition-coverage") ?? "").StartsWith("100%", StringComparison.Ordinal)))
        throw new InvalidDataException("Protocol source line and branch coverage must be 100%.");
    string report = "# 应用协议模块契约覆盖率\n\n" + $"MSTest {outcomes.Length}/{outcomes.Length}；协议源码行与分支覆盖均为 100%。\n\n"
        + "涵盖协议客户端、登录事务、ID Token 验签、轮询状态机及其安全失败场景。单元覆盖率不表示全部应用能力或浏览器互操作已验收，也不继承 Admin API 验收。真实支持状态见 [全能力矩阵](platform-capability-matrix.md)。\n";
    await File.WriteAllTextAsync(Path.Combine(root, "docs/contracts/protocol-coverage.md"), report, ct);
    Console.WriteLine($"PASS protocol tests {outcomes.Length}/{outcomes.Length}; source lines and branches 100%; independent from Admin API support.");
});
