#!/usr/bin/env -S dotnet --
#:property TargetFramework=net10.0
#:property PublishAot=false
#:include Shared/ScriptSupport.cs
#:include Shared/TargetBaseline.cs
#:include JavaAuditIndex.cs
#:project ../src/Keycloak.Admin.Sdk/Keycloak.Admin.Sdk.csproj

using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Security.Cryptography;
using Keycloak.Admin.Sdk;

return await ScriptHost.ExecuteAsync(args, "dotnet run --file tools/Generate-TestMatrix.cs -- [--refresh-contracts | --check]", ["--refresh-contracts", "--check"], async ct =>
{
    if (args.Length > 1) throw new ArgumentException("Choose one option.");
    string root = ScriptHost.RepositoryRoot();
    string matrixPath = Path.Combine(root, "contracts/admin-api-test-matrix.json");
    using var baseline = ScriptHost.Baseline(root);
    byte[] specBytes = await File.ReadAllBytesAsync(Path.Combine(root, "contracts/openapi.json"), ct);
    if (Convert.ToHexStringLower(SHA256.HashData(specBytes)) != baseline.RootElement.GetProperty("openApiSha256").GetString())
        throw new InvalidDataException("Test oracle OpenAPI differs from the pinned publication.");
    var spec = JsonNode.Parse(specBytes)!;
    var schemas = spec["components"]!["schemas"]!.AsObject();
    var catalog = AdminEndpointCatalog.All.OrderBy(e => e.Method + " " + e.Path, StringComparer.Ordinal).ToArray();
    if (catalog.Length != baseline.RootElement.GetProperty("discoveredEndpoints").GetInt32()) throw new InvalidDataException("SDK operation count differs from the pinned release.");
    JsonArray matrix;
    if (args.Contains("--refresh-contracts"))
    {
        // Expectations come from a separate token-level Java index and published definitions,
        // never the SDK generator's JavaRoutes, request builder, or generated smoke fixtures.
        string sourceRoot = TargetBaseline.Load(root).Source(root);
        foreach (string line in await File.ReadAllLinesAsync(Path.Combine(root, "contracts/source-files.sha256"), ct))
        {
            int separator = line.IndexOf("  ", StringComparison.Ordinal);
            byte[] sourceBytes = await File.ReadAllBytesAsync(Path.Combine(sourceRoot, line[(separator + 2)..]), ct);
            if (Convert.ToHexStringLower(SHA256.HashData(sourceBytes)) != line[..separator]) throw new InvalidDataException("Test oracle source hash mismatch.");
        }
        var java = new JavaAuditIndex(sourceRoot);
        var source = java.Discover();
        if (!source.Select(e => Key(e.Verb, e.Path)).ToHashSet().SetEquals(catalog.Select(e => Key(e.Method, e.Path))))
            throw new InvalidDataException("Independent source routes differ from SDK catalog.");
        var corrections = JsonNode.Parse(await File.ReadAllTextAsync(Path.Combine(root, "contracts/overrides.json"), ct))!.AsArray();
        matrix = [];
        foreach (var endpoint in catalog)
        {
            var variants = java.Variants.Where(r => Key(r.Verb, r.Path) == Key(endpoint.Method, endpoint.Path)).ToArray();
            var officialPath = spec["paths"]!.AsObject().FirstOrDefault(p => Canonical(p.Key) == Canonical(endpoint.Path)).Value;
            var operation = officialPath?[endpoint.Method.ToLowerInvariant()];
            var correction = corrections.FirstOrDefault(p => p!["method"]!.GetValue<string>() == endpoint.Method && Canonical(p["path"]!.GetValue<string>()) == Canonical(endpoint.Path));
            var queries = new JsonArray();
            foreach (var p in variants.SelectMany(v => JavaAuditIndex.Parameters(v.Method)).Where(p => p.Binding == "QueryParam").DistinctBy(p => p.WireName))
            {
                string kind = p.Type switch { "boolean" or "Boolean" => "bool", "int" or "Integer" => "int", "long" or "Long" => "long", "double" or "Double" => "double", "List<String>" or "Set<String>" => "list", "String" or "SessionType" => "string", _ => throw new InvalidDataException("Review query type: " + p.Type) };
                queries.Add(new JsonObject { ["name"] = p.WireName, ["kind"] = kind });
            }
            var responses = operation?["responses"]?.AsObject();
            var success = responses?.Where(r => r.Key.StartsWith('2')).Select(r => int.Parse(r.Key, System.Globalization.CultureInfo.InvariantCulture)).ToArray() ?? [200];
            var responseContent = responses?.Where(r => r.Key.StartsWith('2')).SelectMany(r => r.Value?["content"]?.AsObject() ?? []).FirstOrDefault();
            var requestContent = operation?["requestBody"]?["content"]?.AsObject().FirstOrDefault();
            JsonNode? responseSchema = correction?["responseSchema"] ?? responseContent?.Value?["schema"];
            JsonNode? requestSchema = correction?["requestSchema"] ?? requestContent?.Value?["schema"];
            var media = variants.SelectMany(v => v.Method.Annotations.Where(a => a.Name == "Consumes").SelectMany(a => a.Arguments)).Select(t => Media(t.Text)).OfType<string>()
                .Concat(operation?["requestBody"]?["content"]?.AsObject().Select(p => p.Key) ?? []).Distinct().ToArray();
            matrix.Add(new JsonObject
            {
                ["method"] = endpoint.Method, ["path"] = endpoint.Path, ["sdkMethod"] = endpoint.Operation,
                ["queries"] = queries, ["successStatuses"] = new JsonArray(success.Select(s => JsonValue.Create(s)).ToArray()),
                ["requestJson"] = Fixture(requestSchema), ["responseJson"] = Fixture(responseSchema),
                ["mediaTypes"] = new JsonArray(media.Select(m => JsonValue.Create(m)).ToArray()),
                ["sources"] = new JsonArray(variants.Select(v => JsonValue.Create(v.Method.Owner.File + ":" + v.Method.Line)).ToArray())
            });
        }
        await File.WriteAllTextAsync(matrixPath, matrix.ToJsonString(new JsonSerializerOptions(ToolJson.Options) { WriteIndented = true }), ct);
    }
    else matrix = JsonNode.Parse(await File.ReadAllTextAsync(matrixPath, ct))!.AsArray();
    if (matrix.Count != catalog.Length || !matrix.Select(m => Key(S(m!, "method"), S(m!, "path"))).ToHashSet().SetEquals(catalog.Select(e => Key(e.Method, e.Path))))
        throw new InvalidDataException("Every SDK operation must have exactly one independent matrix contract.");

    var code = new StringBuilder("// <auto-generated by Generate-TestMatrix.cs; contract expectations are frozen separately />\nusing System.Text.Json;\nusing Keycloak.Admin.Sdk;\npublic static class EndpointMatrix\n{\n    public static IReadOnlyList<EndpointCase> Cases { get; } = [\n");
    var adapters = new StringBuilder("// <auto-generated />\nusing Microsoft.VisualStudio.TestTools.UnitTesting;\n[TestClass]\npublic sealed class EndpointMatrixTests\n{\n");
    var inventory = new StringBuilder("# Admin API 单元测试矩阵\n\n由 `tools/Generate-TestMatrix.cs` 生成，每项对应独立 MSTest 入口。共同场景：成功、缺省/替代参数、空响应、400/401/403/404/409/415/500、取消和网络失败；JSON 响应另测非法 JSON，raw 请求另测声明媒体类型。\n\n下表仅列各项的请求/响应类型：none 为无请求体，json 为源生成 JSON，raw 为原始内容。期望来源、覆盖率及执行命令见 [测试说明](../testing.md)；真实业务证明见 [验收报告](full-live-acceptance.md)。\n\n| HTTP | 路径 | SDK 方法 | MSTest | 请求 / 响应 |\n| --- | --- | --- | --- | --- |\n");
    int number = 0;
    foreach (var row in matrix)
    {
        var item = row!;
        var endpoint = catalog.Single(e => e.Method == S(item, "method") && e.Path == S(item, "path"));
        string[] name = endpoint.Operation.Split('.');
        string generated = await File.ReadAllTextAsync(Path.Combine(root, "src/Keycloak.Admin.Sdk/Generated/" + name[0] + "Api.g.cs"), ct);
        var method = Regex.Match(generated, @"public Task<(?<return>[^\r\n]+?)> " + Regex.Escape(name[1]) + @"\((?<args>[^\r\n]*?)\) =>");
        if (!method.Success) throw new InvalidDataException("SDK method missing: " + endpoint.Operation);
        var declarations = Split(method.Groups["args"].Value).Select(p => Regex.Match(p.Trim(), @"^(?<type>.*?)\s+(?<name>@?\w+)(?:\s*=.*)?$")).ToArray();
        int pathCount = Regex.Matches(endpoint.Path, @"\{[^}]+\}").Count;
        var arguments = declarations.Take(pathCount).Select((_, i) => L("p" + i + " /%+&中")).ToList();
        var body = declarations.FirstOrDefault(d => d.Groups["name"].Value == "body");
        string bodyKind = body is null ? "none" : body.Groups["type"].Value == "HttpContent?" ? "raw" : "json";
        if (bodyKind == "json" && item["mediaTypes"]!.AsArray().Any(m => m!.GetValue<string>() != "application/json"))
            throw new InvalidDataException("A JSON-only wrapper cannot cover declared non-JSON media: " + endpoint.Operation);
        if (body is not null)
        {
            string type = body.Groups["type"].Value.TrimEnd('?');
            arguments.Add("body: " + (bodyKind == "raw" ? "input.RawContent" : "input.HasBody ? MatrixJson.Read<" + type + ">(input.RequestJson) : null"));
        }
        var queries = item["queries"]!.AsArray();
        foreach (var q in queries)
        {
            string wire = S(q!, "name"), arg = Arg(wire);
            if (declarations.Take(pathCount).Any(d => d.Groups["name"].Value == arg)) arg += "Query";
            if (!declarations.Any(d => d.Groups["name"].Value == arg)) throw new InvalidDataException("Missing query argument: " + endpoint.Operation + " " + wire);
            string value = S(q!, "kind") switch
            {
                "bool" => "input.BooleanFor", "int" => "input.IntegerFor", "long" => "input.LongFor", "double" => "input.NumberFor", "list" => "input.ListFor", _ => "input.TextFor"
            };
            arguments.Add(arg + ": " + value + "(" + L(wire) + ")");
        }
        if (declarations.Length != pathCount + queries.Count + (body is null ? 0 : 1) + 1)
            throw new InvalidDataException("Unexpected SDK parameters: " + endpoint.Operation);
        arguments.Add("cancellationToken: input.CancellationToken");
        string reply = method.Groups["return"].Value;
        string responseKind = reply == "AdminResponse" ? "raw" : "json";
        string result = responseKind == "raw" ? "MatrixResult.From(reply)" : "MatrixResult.From(reply, MatrixJson.Info<" + reply["AdminResponse<".Length..^1] + ">())";
        string caseName = "Operation" + number.ToString("D3", System.Globalization.CultureInfo.InvariantCulture);
        code.AppendLine($"        new({L(endpoint.Method)}, {L(endpoint.Path)}, {L(endpoint.Operation)}, {L(caseName)}, {L(bodyKind)}, {L(responseKind)}, {L(S(item, "requestJson"))}, {L(S(item, "responseJson"))}, [{string.Join(", ", queries.Select(q => "new(" + L(S(q!, "name")) + ", " + L(S(q!, "kind")) + ")"))}], [{string.Join(", ", item["successStatuses"]!.AsArray().Select(s => s!.ToString()))}], [{string.Join(", ", item["mediaTypes"]!.AsArray().Select(s => L(s!.GetValue<string>())))}], async (sdk, input) =>\n        {{\n            var reply = await sdk.{endpoint.Operation}({string.Join(", ", arguments)});\n            return {result};\n        }}),");
        adapters.AppendLine($"    [TestMethod]\n    public Task {caseName}() => EndpointMatrix.Cases[{number}].RunAsync();\n");
        inventory.AppendLine($"| {endpoint.Method} | `{endpoint.Path}` | `{endpoint.Operation}` | `{caseName}` | {bodyKind} / {responseKind} |");
        number++;
    }
    code.AppendLine("    ];\n}"); adapters.AppendLine("}");
    await Output("tests/Keycloak.Admin.Sdk.Tests/EndpointMatrix.g.cs", code.ToString());
    await Output("tests/Keycloak.Admin.Sdk.Tests/EndpointMatrixTests.g.cs", adapters.ToString());
    await Output("docs/contracts/admin-api-test-matrix.md", inventory.ToString());

    var models = new StringBuilder("// <auto-generated from published schemas />\nusing Keycloak.Admin.Sdk;\npublic static class ModelMatrix\n{\n    public static void Run()\n    {\n");
    var modelMethods = new StringBuilder();
    foreach (var (name, schema) in schemas.OrderBy(p => p.Key, StringComparer.Ordinal))
        if (name != "RawJsonValue" && schema?["type"]?.GetValue<string>() != "string")
        {
            models.AppendLine($"        Check{name}();");
            modelMethods.AppendLine($"    private static void Check{name}()\n    {{\n        string sample = {L(Fixture(new JsonObject { ["$ref"] = "#/components/schemas/" + name }))};\n        MatrixJson.RoundTrip<{name}>(sample);");
            if (schema?["properties"] is JsonObject properties)
            {
                modelMethods.AppendLine($"        var full = MatrixJson.Read<{name}>(sample);");
                foreach (var (wire, _) in properties)
                {
                    string property = Id(wire); if (property == name) property += "Value";
                    modelMethods.AppendLine($"        MatrixJson.SingleProperty(new {name} {{ {property} = full.{property} }}, {L(wire)}, sample);");
                }
            }
            modelMethods.AppendLine("    }");
        }
    models.AppendLine("    }"); models.Append(modelMethods); models.AppendLine("}");
    await Output("tests/Keycloak.Admin.Sdk.Tests/ModelMatrix.g.cs", models.ToString());
    Console.WriteLine($"Matrix: {number} independently discovered operation tests generated/checked.");

    async Task Output(string path, string contents)
    {
        contents = contents.Replace("\r\n", "\n");
        string full = Path.Combine(root, path);
        if (args.Contains("--check"))
        {
            if (!File.Exists(full) || (await File.ReadAllTextAsync(full, ct)).Replace("\r\n", "\n") != contents) throw new InvalidDataException("Stale matrix output: " + path);
        }
        else await File.WriteAllTextAsync(full, contents, new UTF8Encoding(false), ct);
    }
    string Fixture(JsonNode? node) => Value(node, [], 0).ToJsonString(ToolJson.Options);
    JsonNode Value(JsonNode? node, HashSet<string> chain, int depth)
    {
        if (node?["$ref"] is JsonValue reference)
        {
            string name = reference.GetValue<string>().Split('/').Last();
            if (name == "RawJsonValue") return new JsonObject { ["value"] = "中 +&" };
            if (!chain.Add(name)) return new JsonObject();
            return Value(schemas[name], chain, depth + 1);
        }
        switch (node?["type"]?.GetValue<string>())
        {
            case "string": return JsonValue.Create("value 中 +&")!;
            case "boolean": return JsonValue.Create(false)!;
            case "integer": return JsonValue.Create(7)!;
            case "number": return JsonValue.Create(1.25)!;
            case "array": return new JsonArray(Value(node["items"], new(chain), depth + 1));
            case "object":
                var obj = new JsonObject();
                if (node["properties"] is JsonObject properties)
                {
                    foreach (var (key, property) in properties) obj[key] = Value(property, new(chain), depth + 1);
                    obj["futureField"] = new JsonObject { ["nested"] = "preserved" };
                }
                else obj["entry"] = Value(node["additionalProperties"] as JsonObject, new(chain), depth + 1);
                return obj;
            default: return new JsonObject { ["raw"] = "中 +&" };
        }
    }
});

static string S(JsonNode node, string key) => node[key]!.GetValue<string>();
static string L(string value) => JsonSerializer.Serialize(value, ToolJson.Options);
static string Arg(string value) => "@" + char.ToLowerInvariant(Id(value)[0]) + Id(value)[1..];
static string Id(string value) => string.Concat(Regex.Matches(value, @"[A-Za-z0-9]+").Select(m => char.ToUpperInvariant(m.Value[0]) + m.Value[1..]));
static string Canonical(string value) => Regex.Replace(value.TrimEnd('/'), @"\{[^}]+\}", "{}");
static string Key(string method, string path) => method + " " + Canonical(path);
static IEnumerable<string> Split(string value)
{
    int start = 0, depth = 0;
    for (int i = 0; i < value.Length; i++)
    {
        if (value[i] == '<') depth++; else if (value[i] == '>') depth--;
        else if (value[i] == ',' && depth == 0) { yield return value[start..i]; start = i + 1; }
    }
    yield return value[start..];
}
static string? Media(string value) => value switch
{
    "APPLICATION_JSON" or "MediaType.APPLICATION_JSON" => "application/json", "APPLICATION_FORM_URLENCODED" or "MediaType.APPLICATION_FORM_URLENCODED" => "application/x-www-form-urlencoded",
    "MULTIPART_FORM_DATA" or "MediaType.MULTIPART_FORM_DATA" => "multipart/form-data", "APPLICATION_XML" or "MediaType.APPLICATION_XML" => "application/xml", "TEXT_PLAIN" or "MediaType.TEXT_PLAIN" => "text/plain",
    "APPLICATION_JACKSON_YAML" => "application/yaml", // Also declared in pinned workflow OpenAPI content.
    "APPLICATION_OCTET_STREAM" => "application/octet-stream",
    _ when value.Contains('/') => value.Trim('"'),
    _ when Regex.IsMatch(value, @"^[A-Z][A-Z0-9_]*_[A-Z0-9_]+$") => throw new InvalidDataException("Review media constant: " + value), _ => null
};

// Reflection is confined to this JIT-only authoring tool, never SDK/test executables.
static class ToolJson
{
    public static readonly JsonSerializerOptions Options = new() { TypeInfoResolver = new System.Text.Json.Serialization.Metadata.DefaultJsonTypeInfoResolver() };
}
