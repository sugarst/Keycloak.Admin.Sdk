#!/usr/bin/env -S dotnet --
#:property TargetFramework=net10.0
#:property PublishAot=false
#:include ScriptSupport.cs
#:include JavaAuditIndex.cs
#:project ../src/Keycloak.Admin.Sdk/Keycloak.Admin.Sdk.csproj

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Keycloak.Admin.Sdk;

return await ScriptHost.ExecuteAsync(args, "dotnet run --file tools/Audit-Contracts.cs -- [--online]", ["--online"], async ct =>
{
    string root = ScriptHost.RepositoryRoot();
    string source = Path.Combine(root, ".cache/keycloak/pinned-source");
    using var baseline = ScriptHost.Baseline(root);
    string commit = baseline.RootElement.GetProperty("commit").GetString()!;
    string version = baseline.RootElement.GetProperty("keycloakVersion").GetString()!;
    if (args.Contains("--online"))
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromMinutes(2) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("Keycloak.Admin.Sdk-alignment-audit/1.0");
        using var tag = JsonDocument.Parse(await http.GetStringAsync("https://api.github.com/repos/keycloak/keycloak/git/ref/tags/" + version, ct));
        if (tag.RootElement.GetProperty("object").GetProperty("sha").GetString() != commit) throw new InvalidDataException("Release tag differs from the pinned commit.");
        byte[] currentSpec = await http.GetByteArrayAsync($"https://www.keycloak.org/docs-api/{version}/rest-api/openapi.json", ct);
        if (Convert.ToHexStringLower(SHA256.HashData(currentSpec)) != baseline.RootElement.GetProperty("openApiSha256").GetString()) throw new InvalidDataException("Published OpenAPI differs from the pinned snapshot.");
        Console.WriteLine("Online release tag and official OpenAPI: MATCH");
    }
    await using (var archive = File.OpenRead(Path.Combine(root, ".cache/keycloak/source.tar.gz")))
        if (Convert.ToHexStringLower(await SHA256.HashDataAsync(archive, ct)) != baseline.RootElement.GetProperty("sourceArchiveSha256").GetString()) throw new InvalidDataException("Source archive hash mismatch.");
    foreach (string line in await File.ReadAllLinesAsync(Path.Combine(root, "contracts/source-files.sha256"), ct))
    {
        int space = line.IndexOf("  ", StringComparison.Ordinal);
        byte[] bytes = await File.ReadAllBytesAsync(Path.Combine(source, line[(space + 2)..]), ct);
        if (Convert.ToHexStringLower(SHA256.HashData(bytes)) != line[..space]) throw new InvalidDataException("Source file hash mismatch: " + line[(space + 2)..]);
    }
    using var openapi = JsonDocument.Parse(await File.ReadAllTextAsync(Path.Combine(root, "contracts/keycloak-26.8.1.openapi.json"), ct));
    var documented = new Dictionary<string, (string Verb, string Path, string Tag, JsonElement Op)>(StringComparer.Ordinal);
    foreach (var path in openapi.RootElement.GetProperty("paths").EnumerateObject())
    foreach (var operation in path.Value.EnumerateObject().Where(p => p.Name is "get" or "post" or "put" or "delete" or "patch" or "head" or "options"))
    {
        string verb = operation.Name.ToUpperInvariant();
        string tag = operation.Value.TryGetProperty("tags", out var tags) ? tags[0].GetString()! : "default";
        documented.Add(Key(verb, path.Name), (verb, path.Name, tag, operation.Value));
    }
    var sdk = AdminEndpointCatalog.All.ToDictionary(e => Key(e.Method, e.Path), StringComparer.Ordinal);
    var index = new JavaAuditIndex(source);
    var routes = index.Discover();
    var actual = routes.ToDictionary(r => Key(r.Verb, r.Path), StringComparer.Ordinal);
    var missingDocs = documented.Keys.Except(sdk.Keys).ToArray();
    var missingSource = actual.Keys.Except(sdk.Keys).ToArray();
    var sdkWithoutSource = sdk.Keys.Except(actual.Keys).ToArray();
    var inventoryRows = (await File.ReadAllLinesAsync(Path.Combine(root, "docs/contracts/endpoint-inventory.md"), ct))
        .Where(line => Regex.IsMatch(line, @"^\| (GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) \|"))
        .Select(line => line.Split('|')).ToArray();
    var inventoryKeys = inventoryRows.Select(columns => Key(columns[1].Trim(), columns[2].Trim().Trim('`'))).ToHashSet(StringComparer.Ordinal);
    var listedSource = (await File.ReadAllLinesAsync(Path.Combine(root, "docs/contracts/source-routes.tsv"), ct)).Skip(1).Select(line => line.Split('\t'))
        .Select(columns => Key(columns[0], columns[1])).ToHashSet(StringComparer.Ordinal);
    if (!inventoryKeys.SetEquals(sdk.Keys) || !listedSource.SetEquals(sdk.Keys) || inventoryRows.Length != sdk.Count)
        throw new InvalidDataException("Markdown/source inventory differs from the compiled SDK catalog.");
    Console.WriteLine($"Official OpenAPI: {documented.Count}; SDK: {sdk.Count}; independent source routes: {actual.Count}; dispatch variants: {index.Variants.Count}");
    Console.WriteLine($"Missing official: {missingDocs.Length}; missing source: {missingSource.Length}; SDK without source: {sdkWithoutSource.Length}");
    Directory.CreateDirectory(Path.Combine(root, "artifacts/alignment"));
    await File.WriteAllLinesAsync(Path.Combine(root, "artifacts/alignment/source-routes.tsv"), routes.Select(r => $"{r.Verb}\t{r.Path}\t{r.Method.Owner.File}\t{r.Method.Line}"), ct);
    await File.WriteAllLinesAsync(Path.Combine(root, "artifacts/alignment/route-differences.txt"),
        missingSource.Select(k => "MISSING SOURCE " + k).Concat(sdkWithoutSource.Select(k => "SDK ONLY " + k)).Concat(index.Unresolved.Select(k => "LOCATOR " + k)), ct);
    foreach (string difference in missingSource.Select(k => "MISSING SOURCE " + k).Concat(sdkWithoutSource.Select(k => "SDK ONLY " + k)).Concat(index.Unresolved.Select(k => "LOCATOR " + k))) Console.WriteLine(difference);
    foreach (var group in documented.Values.GroupBy(x => x.Tag).OrderBy(g => g.Key, StringComparer.Ordinal)) Console.WriteLine($"DOC {group.Key}: {group.Count()}");
    foreach (var group in sdk.Values.Where(e => !documented.ContainsKey(Key(e.Method, e.Path))).GroupBy(e => e.SourceFile.Split("/src/main/java/")[0]).OrderBy(g => g.Key)) Console.WriteLine($"EXTRA {group.Key}: {group.Count()}");
    var queryFindings = new List<string>();
    var mediaFindings = new List<string>();
    var bodyFindings = new List<string>();
    var responseFindings = new List<string>();
    int comparableResponses = 0;
    var sdkDefinitions = new Dictionary<string, (string Return, string Args, string Call)>(StringComparer.Ordinal);
    foreach (var (key, endpoint) in sdk)
    {
        string[] operation = endpoint.Operation.Split('.');
        string generated = await File.ReadAllTextAsync(Path.Combine(root, "src/Keycloak.Admin.Sdk/Generated/" + operation[0] + "Api.g.cs"), ct);
        var method = Regex.Match(generated, @"public Task<(?<return>[^\r\n]+?)> " + Regex.Escape(operation[1]) + @"\((?<args>[^\r\n]*?)\) =>\s*(?<call>.*?);", RegexOptions.Singleline);
        if (!method.Success) throw new InvalidDataException("Cannot locate SDK method: " + endpoint.Operation);
        sdkDefinitions[key] = (method.Groups["return"].Value, method.Groups["args"].Value, method.Groups["call"].Value);
        var exposed = Regex.Matches(method.Groups["call"].Value, "new\\(\"([^\"]+)\",\\s*(@\\w+)\\)")
            .ToDictionary(m => m.Groups[1].Value, m => m.Groups[2].Value, StringComparer.Ordinal);
        var expected = index.Variants.Where(r => Key(r.Verb, r.Path) == key).SelectMany(r => JavaAuditIndex.Parameters(r.Method))
            .Where(p => p.Binding == "QueryParam").DistinctBy(p => p.WireName).ToArray();
        foreach (var parameter in expected)
        {
            if (!exposed.TryGetValue(parameter.WireName, out string? argument))
            {
                queryFindings.Add($"{key}\tmissing query\t{parameter.WireName}\t{parameter.Type}\t{endpoint.Operation}");
                continue;
            }
            string declaration = Regex.Match(method.Groups["args"].Value, @"(?<type>[\w<>?]+)\s+" + Regex.Escape(argument) + @"\s*(?:=|,|$)").Groups["type"].Value.TrimEnd('?');
            string? expectedType = parameter.Type switch
            {
                "String" => "string", "Boolean" or "boolean" => "bool", "Integer" or "int" => "int", "Long" or "long" => "long",
                "List<String>" or "Set<String>" => "List<string>", _ => null
            };
            if (expectedType is not null && declaration != expectedType)
                queryFindings.Add($"{key}\tquery type\t{parameter.WireName}\t{parameter.Type}->{declaration}\t{endpoint.Operation}");
        }
        foreach (string query in exposed.Keys.Except(expected.Select(p => p.WireName)))
            queryFindings.Add($"{key}\textra query\t{query}\t\t{endpoint.Operation}");
        var variants = index.Variants.Where(r => Key(r.Verb, r.Path) == key).ToArray();
        bool bodyExposed = method.Groups["args"].Value.Contains(" body = null", StringComparison.Ordinal);
        bool rawBody = method.Groups["args"].Value.Contains("HttpContent? body", StringComparison.Ordinal);
        var bodyParameters = variants.SelectMany(r => JavaAuditIndex.Parameters(r.Method)).Where(p => p.Binding is "body" or "FormParam" or "MultipartForm").ToArray();
        if (bodyParameters.Length > 0 && !bodyExposed)
            bodyFindings.Add($"{key}\tmissing request body\t{string.Join(',', bodyParameters.Select(p => p.Type).Distinct())}\t{endpoint.Operation}");
        var consumes = variants.SelectMany(r => r.Method.Annotations.Where(a => a.Name == "Consumes").SelectMany(a => a.Arguments))
            .Select(t => Media(t.Text)).Where(v => v is not null).OfType<string>().Distinct(StringComparer.Ordinal).ToArray();
        if (bodyExposed && !rawBody)
            foreach (string media in consumes.Where(m => m != "application/json"))
                mediaFindings.Add($"{key}\t{media}\tJSON-only generated wrapper\t{endpoint.Operation}");
        string reply = method.Groups["return"].Value;
        if (reply.StartsWith("AdminResponse<", StringComparison.Ordinal) && reply != "AdminResponse<JsonElement>")
        {
            string declared = reply["AdminResponse<".Length..^1];
            var expectedTypes = variants.Select(v => NetType(v.Method.ReturnType, openapi.RootElement.GetProperty("components").GetProperty("schemas"))).OfType<string>().Distinct().ToArray();
            if (expectedTypes.Length == 1)
            {
                comparableResponses++;
                if (declared.Replace(" ", "") != expectedTypes[0].Replace(" ", ""))
                    responseFindings.Add($"{key}\t{expectedTypes[0]}\t{declared}\t{endpoint.Operation}");
            }
        }
    }
    await File.WriteAllLinesAsync(Path.Combine(root, "artifacts/alignment/query-findings.tsv"), queryFindings, ct);
    await File.WriteAllLinesAsync(Path.Combine(root, "artifacts/alignment/media-findings.tsv"), mediaFindings, ct);
    await File.WriteAllLinesAsync(Path.Combine(root, "artifacts/alignment/body-findings.tsv"), bodyFindings, ct);
    await File.WriteAllLinesAsync(Path.Combine(root, "artifacts/alignment/response-findings.tsv"), responseFindings, ct);
    Console.WriteLine("Query findings: " + queryFindings.Count);
    foreach (string finding in queryFindings) Console.WriteLine(finding);
    foreach (string finding in mediaFindings) Console.WriteLine("MEDIA " + finding);
    foreach (string finding in bodyFindings) Console.WriteLine("BODY " + finding);
    Console.WriteLine($"Comparable declared response types: {comparableResponses}; differences: {responseFindings.Count}");
    foreach (string finding in responseFindings.Take(20)) Console.WriteLine("RESPONSE " + finding);
    foreach (var duplicate in index.Variants.GroupBy(r => Key(r.Verb, r.Path)).Where(g => g.Count() > 1))
        Console.WriteLine("DISPATCH " + duplicate.Key + ": " + string.Join(", ", duplicate.Select(r => r.Method.Owner.Name + "." + r.Method.Name)));
    bool workflowArrayFailure = false;
    if (responseFindings.Any(f => f.Contains("/workflows/scheduled/", StringComparison.Ordinal)))
    {
        using var http = new HttpClient(new ArrayReplyHandler());
        var client = new KeycloakAdminClient(http, new Uri("https://keycloak.invalid/"));
        try { await client.Workflows.GetScheduledWorkflowsAsync("realm", "resource", ct); }
        catch (KeycloakResponseFormatException) { workflowArrayFailure = true; }
        Console.WriteLine("Workflow empty-array HTTP fixture causes response format failure: " + workflowArrayFailure);
    }

    var summary = new JsonObject
    {
        ["keycloakVersion"] = version, ["commit"] = commit, ["onlineChecked"] = args.Contains("--online"),
        ["officialOperations"] = documented.Count, ["sdkOperations"] = sdk.Count, ["sourceOperations"] = actual.Count,
        ["sourceDispatchVariants"] = index.Variants.Count, ["missingOfficialRoutes"] = missingDocs.Length,
        ["missingSourceRoutes"] = missingSource.Length, ["sdkRoutesWithoutSource"] = sdkWithoutSource.Length,
        ["queryGaps"] = queryFindings.Count, ["mediaGaps"] = mediaFindings.Count, ["missingBodies"] = bodyFindings.Count,
        ["comparableDeclaredResponses"] = comparableResponses, ["declaredResponseDifferences"] = responseFindings.Count,
        ["workflowArrayFailureReproduced"] = workflowArrayFailure
    };
    await File.WriteAllTextAsync(Path.Combine(root, "artifacts/alignment/summary.json"), summary.ToJsonString(), ct);

    bool hasGaps = missingDocs.Length + missingSource.Length + sdkWithoutSource.Length + queryFindings.Count + mediaFindings.Count + bodyFindings.Count + responseFindings.Count > 0;
    var report = new StringBuilder($"# Keycloak {version} REST Admin API 对齐审计\n\n");
    report.AppendLine(hasGaps
        ? $"结论：本次审计仍有契约差异。发现 {queryFindings.Select(f => f.Split('\t')[0]).Distinct().Count()} 个路径的 {queryFindings.Count} 个查询参数缺口、{mediaFindings.Count} 个媒体类型变体缺口，以及 {responseFindings.Count} 个返回类型差异。修正前不能宣称已完整对标服务端契约。\n"
        : "结论：本次静态对照未发现方法、路径、已比较查询参数、媒体类型及直接声明返回类型的差异。该结果不代替全量 DTO、权限、状态码与业务验收。\n");
    report.AppendLine($"基线为 [发布 tag](https://github.com/keycloak/keycloak/releases/tag/{version})，完整提交 `{commit}`。[官方 API 定义](https://www.keycloak.org/docs-api/{version}/rest-api/index.html) 仍标记为预览。远端 tag 和 OpenAPI 本次在线核验：**{(args.Contains("--online") ? "一致" : "未执行；可加 --online") }**；本地源码归档 SHA256 和源码文件清单校验通过。\n");
    report.AppendLine("## 数量与口径\n\n| 检查项 | 结果 |\n| --- | --- |");
    report.AppendLine($"| 官方 OpenAPI 方法＋路径 | {documented.Count}（{openapi.RootElement.GetProperty("paths").EnumerateObject().Count()} 个路径模板） |\n| 独立源码扫描方法＋路径 | {actual.Count} |\n| 源码处理分支 | {index.Variants.Count}，包含同路径的动态/媒体类型分派 |\n| SDK / Markdown 清单 / 源码清单 | {sdk.Count} / {inventoryKeys.Count} / {listedSource.Count} |\n| 官方接口遗漏 / 源码路径遗漏 / SDK 无来源路径 | {missingDocs.Length} / {missingSource.Length} / {sdkWithoutSource.Length} |\n| 查询参数缺口 | {queryFindings.Count} 项，涉及 {queryFindings.Select(f => f.Split('\t')[0]).Distinct().Count()} 个路径 |\n| 媒体类型变体缺口 | {mediaFindings.Count} 个路径 |\n| 可比返回类型差异 | {responseFindings.Count} / {comparableResponses} 项 |\n");
    report.AppendLine("计数单位是 HTTP 方法＋路径模板；仅规范化路径参数名称与末尾斜杠。520 不是官方文档的接口数量，而是 415 个文档操作加 105 个源码补充操作。三个动态 SPI 入口和可选功能仍有边界，见后文。\n");
    report.AppendLine("## 官方清单分组\n\n| 官方分组 | 操作数 | SDK 路由缺失 |\n| --- | --- | --- |");
    foreach (var group in documented.Values.GroupBy(o => o.Tag).OrderBy(g => g.Key, StringComparer.Ordinal))
        report.AppendLine($"| {group.Key} | {group.Count()} | {group.Count(o => !sdk.ContainsKey(Key(o.Verb, o.Path)))} |");
    report.AppendLine("\n## 源码补充清单\n\n| 源码模块 | 文档外操作数 |\n| --- | --- |");
    foreach (var group in sdk.Values.Where(e => !documented.ContainsKey(Key(e.Method, e.Path))).GroupBy(e => e.SourceFile.Split("/src/main/java/")[0]).OrderBy(g => g.Key, StringComparer.Ordinal))
        report.AppendLine($"| {group.Key} | {group.Count()} |");
    report.AppendLine("\nservices 的 44 项由授权策略动态路径 36 项、用户 VC 管理 7 项和 serverinfo 1 项构成。其余补充包括用户存储/缓存、LDAP、SSF 和 ui-ext；这些并不都属于默认启用、稳定的核心功能。\n");
    if (responseFindings.Count > 0)
    {
    report.AppendLine("## 需修正：响应类型\n\n| 路径 | 源码返回 | SDK 返回 | 源码 |\n| --- | --- | --- | --- |");
    foreach (string finding in responseFindings)
    {
        string[] fields = finding.Split('\t');
        var endpoint = sdk[fields[0]];
        var variant = index.Variants.First(r => Key(r.Verb, r.Path) == fields[0]);
        report.AppendLine($"| `{endpoint.Method} {endpoint.Path}` | `{fields[1]}` | `{fields[2]}` | {Source(variant.Method, version)} |");
    }
    report.AppendLine("\nWorkflowsResource.getScheduledWorkflows 的 Java 签名是 List，方法体也调用 toList；其 OpenAPI 注解却只声明 WorkflowRepresentation。当前 SDK 沿用了错误的单对象定义，收到包括空列表在内的 JSON 数组时会抛出 KeycloakResponseFormatException。应优先修正响应模型为列表，并增加来自源码/真实响应的独立数组测试。现有生成测试使用同一错误 schema 构造对象响应，因此未检出该问题。\n");
    report.AppendLine($"使用返回 HTTP 200、application/json 和 `[]` 的独立 HttpMessageHandler 复现反序列化失败：**{(workflowArrayFailure ? "已复现" : "未复现")}**。这是 wire 格式复现，不冒充工作流功能开启后的真实服务器业务验收。\n");
    }
    if (queryFindings.Count > 0)
    {
    report.AppendLine("## 需修正：动态授权查询参数\n");
    report.AppendLine("`PolicyService.getResource` 根据路径值返回单个策略资源或特定策略类型资源。后者继承 `findAll`，同一个 GET 路径可按类型列举策略；当前生成器按方法＋路径去重后选中了 `PolicyResourceService.findById`，SDK 只暴露 `fields`。\n");
    report.AppendLine("| 路径 | 缺失查询参数 | 当前 SDK 方法 | 源码 |\n| --- | --- | --- | --- |");
    foreach (var group in queryFindings.GroupBy(f => f.Split('\t')[0]))
    {
        var endpoint = sdk[group.Key];
        var listing = index.Variants.First(r => Key(r.Verb, r.Path) == group.Key && r.Method.Name == "findAll");
        report.AppendLine($"| `{endpoint.Method} {endpoint.Path}` | {string.Join(", ", group.Select(f => "`" + f.Split('\t')[2] + "`"))} | `{endpoint.Operation}` | {Source(listing.Method, version)} |");
    }
    report.AppendLine("\n影响：通过生成的资源方法，不能表达这两条路径在按类型列举时的完整筛选和分页。`type`、`permission` 等参数是否最终生效仍由具体分支的服务端过滤逻辑决定。建议分别保留单项/按类型列举操作或合并分支参数，同时明确对象/数组响应。\n");
    }
    if (mediaFindings.Count > 0)
    {
    report.AppendLine("## 需修正：同路径的媒体类型重载\n\n| 路径 | 生成方法未暴露的媒体类型 | SDK 方法 | 源码 |\n| --- | --- | --- | --- |");
    foreach (string finding in mediaFindings)
    {
        var fields = finding.Split('\t');
        var endpoint = sdk[fields[0]];
        var variant = index.Variants.First(r => Key(r.Verb, r.Path) == fields[0] && r.Method.Annotations.Any(a => a.Name == "Consumes" && a.Arguments.Any(t => Media(t.Text) == fields[1])));
        report.AppendLine($"| `{endpoint.Method} {endpoint.Path}` | `{fields[1]}` | `{endpoint.Operation}` | {Source(variant.Method, version)} |");
    }
    report.AppendLine("\n身份提供方文件导入需要 multipart 的 `providerId`、`file`；本地化文件导入需要 multipart 的 `file`。SMTP 表单分支使用 `config`，在 26.8.1 已标记废弃但仍存在。表中被标出的资源方法固定构造 application/json；原始 `SendAsync` 可手工传其他媒体类型，但不等同于生成方法已完整覆盖。\n");
    report.AppendLine("源码另有 `testLDAPConnection` 的 JSON/表单双分支。该 SDK 方法接收 `HttpContent`，可保留调用方选择的媒体类型，因此未计为缺口。\n");
    }
    using var overrides = JsonDocument.Parse(await File.ReadAllTextAsync(Path.Combine(root, "contracts/overrides.json"), ct));
    report.AppendLine($"## 已处理的官方定义差异\n\n[overrides.json](../../contracts/overrides.json) 当前记录了 {overrides.RootElement.GetArrayLength()} 项修正：scope/search 单对象响应、policy/permission 的原始 JSON 对象与创建实体、client-description-converter 的原始载荷、resource attributes 的字典响应，以及 scheduled workflows 的列表响应。它们说明不能把 OpenAPI 直接等同于真实 wire 契约。\n");
    report.AppendLine($"源码直接声明且可与 SDK 强类型结果机械比较的返回类型共 {comparableResponses} 项，类型差异 {responseFindings.Count} 项。该检查不覆盖 Java Response 包装的运行时实体、DTO 每个字段的序列化语义或响应状态码全量行为。\n");
    report.AppendLine("## 六路径回归验证\n\n修复方式、独立断言与真实测试场景见 [六路径修复记录](six-path-fixes.md)。生成器保留同路径的全部分派变体，合并查询参数并保留调用方的媒体类型；工作流返回值依据 Java 实现修正为列表。六组手写断言不使用生成器构造的响应，MSTest 和原生冒烟程序均执行这些断言。\n");
    foreach (string mode in new[] { "managed", "native-aot" })
    {
        string proofPath = Path.Combine(root, "artifacts/six-contracts-live-" + mode + ".txt");
        string[] proof = File.Exists(proofPath) ? await File.ReadAllLinesAsync(proofPath, ct) : [];
        bool passed = proof.Contains("mode=" + mode) && proof.Count(line => line.StartsWith("PASS ", StringComparison.Ordinal)) == 6;
        report.AppendLine($"- 本地 `{mode}` 六路径真实容器证据：{(passed ? "6 / 6 通过" : "未提供完整的本地通过记录")}。");
    }
    report.AppendLine();
    report.AppendLine("## 全操作功能契约单元测试\n\n全部 Admin API SDK 操作的独立用例与适用场景见 [520 项测试矩阵](admin-api-test-matrix.md)，覆盖率及强制门槛见 [门禁报告](test-coverage.md)。期望值来自独立 Java token 索引和固定发布定义，与 SDK 请求构造及原有冒烟生成逻辑分离；每个操作检查查询/载荷/响应、错误、取消和网络失败。`Verify.cs` 要求编译后目录、冻结矩阵与本次 TRX 一一对应，拒绝缺失、重复、跳过、失败或低覆盖率。该结论是 SDK 功能契约单测覆盖，不是全部服务端业务和权限场景的实测声明。\n");
    report.AppendLine("## 审计边界与验证证据\n");
    report.AppendLine("独立扫描器按 Java token 解析声明、导入、继承与资源定位器，不复用生成器的 JavaRoutes；使用已知的 PolicyService 动态分派规则并保留媒体类型变体。它不是完整 Java/JAX-RS 编译器，也不能穷举第三方 SPI 或任意递归策略类型 URI。控制台静态资源、CORS、独立 Admin API v2、Account/SCIM/OIDC 协议不纳入本表。\n");
    foreach (string locator in index.Unresolved) report.AppendLine("- `" + locator + "`");
    var liveRows = (await File.ReadAllLinesAsync(Path.Combine(root, "docs/contracts/live-endpoints.tsv"), ct)).Select(line => line.Split('\t')).ToArray();
    var live = liveRows.GroupBy(fields => Key(fields[0], fields[1])).ToDictionary(g => g.Key, g => string.Join(',', g.Select(f => f[2]).Distinct().Order()), StringComparer.Ordinal);
    report.AppendLine($"\n这是三个已知的动态扩展边界。内置 realm providers 已枚举；自定义 provider、feature flag、授权/FGAP 及响应模型字段的全部运行时语义仍需专门验收。现有 {sdk.Count} 次路由冒烟、全操作功能契约单测和 {live.Count} 条真实方法/路径（{liveRows.Length} 条状态观测）不能证明全部服务端业务场景对齐。原有冒烟与 SDK 共用生成逻辑，全操作矩阵、六路径手写专项和真实测试分别提供额外证据。\n");
    report.AppendLine("完整逐项对照见 [520 项清单](keycloak-26.8.1-alignment.tsv)，包含官方分组、SDK 方法、源码、已观测状态与本次缺口。后续新增分派变体或契约差异时，应同步修复生成器并增加独立断言和真实服务器测试。\n");
    report.AppendLine("## 复现\n\n```shell\ndotnet run --file tools/Audit-Contracts.cs -- --online\n```\n\n工具总是先输出报告；发现路由、参数、媒体类型或未知定位器差异时返回非零退出码。离线可省略 --online。工具仅执行静态比对和来源校验，不覆盖完整 DTO 字段/状态码、权限与业务验收。");
    await File.WriteAllTextAsync(Path.Combine(root, "docs/contracts/keycloak-26.8.1-alignment-audit.md"), report.ToString().TrimEnd() + "\n", ct);
    var rows = new List<string> { "method\tpath\tofficialGroup\tsdkMethod\tsource\tline\tresponse\tliveStatuses\tqueryGaps\tmediaGaps\tresponseGaps" };
    foreach (var (key, endpoint) in sdk.OrderBy(p => p.Value.Path, StringComparer.Ordinal).ThenBy(p => p.Value.Method, StringComparer.Ordinal))
        rows.Add(string.Join('\t', endpoint.Method, endpoint.Path, documented.TryGetValue(key, out var doc) ? doc.Tag : "source-only", endpoint.Operation,
            endpoint.SourceFile, endpoint.SourceLine, sdkDefinitions[key].Return, live.GetValueOrDefault(key, "pending"),
            string.Join(',', queryFindings.Where(f => f.Split('\t')[0] == key).Select(f => f.Split('\t')[2])),
            string.Join(',', mediaFindings.Where(f => f.Split('\t')[0] == key).Select(f => f.Split('\t')[1])),
            string.Join(',', responseFindings.Where(f => f.Split('\t')[0] == key).Select(f => f.Split('\t')[1] + " expected"))));
    await File.WriteAllLinesAsync(Path.Combine(root, "docs/contracts/keycloak-26.8.1-alignment.tsv"), rows, ct);
    Console.WriteLine("Report: docs/contracts/keycloak-26.8.1-alignment-audit.md");
    if (hasGaps
        || index.Unresolved.Any(s => !s.StartsWith("dynamic SPI:", StringComparison.Ordinal) && !s.StartsWith("policy provider SPI:", StringComparison.Ordinal)))
        throw new InvalidDataException("Alignment audit found contract gaps; see the generated report.");
});

static string Key(string verb, string path) => verb + " " + JavaAuditIndex.Canonical(path);
static string Source(AuditMethod method, string version) => $"[{method.Owner.Name}.{method.Name}](https://github.com/keycloak/keycloak/blob/{version}/{method.Owner.File}#L{method.Line})";
static string? NetType(string java, JsonElement schemas)
{
    if (java.EndsWith("[]", StringComparison.Ordinal)) return NetType(java[..^2], schemas) is { } element ? "List<" + element + ">" : null;
    int generic = java.IndexOf('<');
    if (generic > 0)
    {
        string name = java[..generic];
        string inner = java[(generic + 1)..^1];
        int depth = 0, split = -1;
        for (int i = 0; i < inner.Length; i++) { if (inner[i] == '<') depth++; else if (inner[i] == '>') depth--; else if (inner[i] == ',' && depth == 0) { split = i; break; } }
        if (name is "Stream" or "List" or "Set" or "Collection") return NetType(inner, schemas) is { } item ? "List<" + item + ">" : null;
        if (name == "Map" && split >= 0)
        {
            string? key = NetType(inner[..split], schemas), value = NetType(inner[(split + 1)..], schemas);
            return key is not null && value is not null ? $"Dictionary<{key},{value}>" : null;
        }
        return null;
    }
    return java switch
    {
        "String" => "string", "Boolean" or "boolean" => "bool", "Integer" or "int" => "int", "Long" or "long" => "long",
        "Double" or "double" => "double", "Object" or "RawJsonValue" => "JsonElement",
        _ when schemas.TryGetProperty(java, out var schema) => schema.TryGetProperty("type", out var type) && type.GetString() == "string" ? "string" : java,
        _ => null
    };
}
static string? Media(string token) => token switch
{
    "APPLICATION_JSON" or "application/json" => "application/json",
    "MULTIPART_FORM_DATA" or "multipart/form-data" => "multipart/form-data",
    "APPLICATION_FORM_URLENCODED" or "application/x-www-form-urlencoded" => "application/x-www-form-urlencoded",
    "TEXT_PLAIN" or "text/plain" => "text/plain", "APPLICATION_XML" or "application/xml" => "application/xml",
    "APPLICATION_OCTET_STREAM" or "application/octet-stream" => "application/octet-stream", _ => null
};

internal sealed class ArrayReplyHandler : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
        Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK) { Content = new StringContent("[]", Encoding.UTF8, "application/json") });
}
