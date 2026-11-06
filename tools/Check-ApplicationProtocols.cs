#!/usr/bin/env -S dotnet --
#:property TargetFramework=net10.0
#:property PublishAot=false
#:include ScriptSupport.cs
#:include TargetBaseline.cs
#:include ApplicationAcceptance.cs
#:include ../tests/Keycloak.Admin.Sdk.IntegrationTests/LiveEvidence.cs
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;

return await ScriptHost.ExecuteAsync(args, "dotnet run --file tools/Check-ApplicationProtocols.cs -- [--archive] [--legacy]", ["--archive", "--legacy"], async ct =>
{
    string root = ScriptHost.RepositoryRoot(); var baseline = TargetBaseline.Load(root); string fingerprint = LiveEvidence.ValidationFingerprint(root);
    var rows = new List<string>();
    string suffix = args.Contains("--legacy") ? "-legacy" : "";
    foreach (string mode in new[] { "managed", "native-aot" })
    {
        string source = Path.Combine(root, "artifacts/application-protocols", mode + suffix + ".json");
        byte[] bytes = await File.ReadAllBytesAsync(source, ct); using var document = JsonDocument.Parse(bytes); var report = document.RootElement;
        ApplicationAcceptance.Validate(root, JsonNode.Parse(bytes)!.AsObject());
        string Text(string name) => report.GetProperty(name).GetString()!;
        bool native = mode == "native-aot";
        var checks = report.GetProperty("checks").EnumerateArray().Select(c => c.GetString()!).ToArray();
        if (Text("runtime") != mode) throw new InvalidDataException("Protocol workflow report is stored under the wrong runtime.");
        if ((report.TryGetProperty("serverProfile", out var profile) ? profile.GetString() : "standard") != (suffix.Length == 0 ? "standard" : "legacy"))
            throw new InvalidDataException("Protocol workflow report is stored under the wrong server profile.");
        string binary = Path.Combine(root, native ? "artifacts/aot/application-protocols/Keycloak.Admin.Sdk.IntegrationTests" : "tests/Keycloak.Admin.Sdk.IntegrationTests/bin/Release/net10.0/Keycloak.Admin.Sdk.IntegrationTests.dll");
        if (Text("executableSha256") != Convert.ToHexStringLower(SHA256.HashData(await File.ReadAllBytesAsync(binary, ct))))
            throw new InvalidDataException("Protocol workflow executable differs from its evidence: " + mode);
        string hash = Convert.ToHexStringLower(SHA256.HashData(bytes));
        string relative = "docs/contracts/application-protocol-evidence/" + hash + ".json";
        if (args.Contains("--archive"))
        {
            string destination = Path.Combine(root, relative); Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
            if (File.Exists(destination) && !File.ReadAllBytes(destination).SequenceEqual(bytes)) throw new IOException("Immutable evidence collision.");
            await File.WriteAllBytesAsync(destination, bytes, ct);
        }
        rows.Add($"| {mode} | {checks.Length}/{checks.Length} | [{hash[..12]}](application-protocol-evidence/{hash}.json) |");
        Console.WriteLine($"PASS application workflows: {mode}, {checks.Length}/{checks.Length}; family support requires independent complete criteria.");
    }
    if (args.Contains("--archive"))
    {
        foreach (string mode in new[] { "managed", "native-aot" }) ApplicationAcceptance.Promote(root, Path.Combine(root, "artifacts/application-protocols", mode + suffix + ".json"));
        await ScriptHost.RunCheckedAsync(root, "dotnet", ["run", "--file", "tools/Generate-PlatformMatrix.cs"], ct);
        string markdown = "# 应用协议选定工作流验收\n\n" + $"固定 Keycloak {baseline.Version}；验证输入指纹 `{fingerprint}`。\n\n"
            + "| 运行模式 | 业务断言 | 不可变证据 |\n| --- | --- | --- |\n" + string.Join('\n', rows)
            + "\n\n覆盖安全登录、PAR、客户端委托、AuthZen、SCIM、账户、注册、UMA 共享与授权、Client Admin v2、管理端 OpenAPI、Docker 令牌、DPoP、身份代理和 SSF 的选定流程。两个运行模式均在隔离容器网络实际调用固定服务端；未验证能力不会继承这些结果。\n\n"
            + "报告不自行晋升（`promoted=false`）。独立工具依据审阅计划、全部验收标准和当前输入，为明确运行模式/RID 生成支持配置。稳定与非稳定能力分别晋升。当前应用覆盖与责任边界由 [全能力矩阵](platform-capability-matrix.md) 和完整发布门禁共同确定。\n";
        await File.WriteAllTextAsync(Path.Combine(root, "docs/contracts/application-protocol" + suffix + "-workflows.md"), markdown, ct);
    }
});
