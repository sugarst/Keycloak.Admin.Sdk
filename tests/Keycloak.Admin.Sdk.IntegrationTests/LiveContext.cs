using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Keycloak.Admin.Sdk;

internal sealed record LiveInput(string Key, string[] Paths, JsonNode? Body, JsonObject? Query, HttpContent? Raw, CancellationToken Cancellation)
{
    public HttpContent? Content() => Raw ?? (Body is null ? null : new StringContent(LiveJson.String(Body), Encoding.UTF8, "application/json"));
    public string? Text(string name) => Query?[name]?.GetValue<string>();
    public bool? Boolean(string name) => Query?[name]?.GetValue<bool>();
    public int? Integer(string name) => Query?[name]?.GetValue<int>();
    public long? Long(string name) => Query?[name]?.GetValue<long>();
    public double? Number(string name) => Query?[name]?.GetValue<double>();
    public List<string>? Strings(string name) => Query?[name]?.AsArray().Select(n => n!.GetValue<string>()).ToList();
}
internal sealed record LiveReply(string Key, string Template, AdminResponse Response)
{
    public JsonNode? J => Response.Content.IsEmpty ? null : JsonNode.Parse(Response.Content.Span);
    public string Id => Uri.UnescapeDataString(Response.Location!.OriginalString.TrimEnd('/').Split('/').Last());
}
internal sealed class LiveContext(KeycloakAdminClient sdk, string realm, LiveLedger ledger, CancellationToken cancellationToken = default)
{
    public string Realm { get; } = realm;
    public string RealmId { get; set; } = realm;
    public KeycloakAdminClient Sdk { get; } = sdk;
    public CancellationToken Cancellation { get; } = cancellationToken;
    public LiveContext WithCancellation(CancellationToken token) => new(Sdk, Realm, ledger, token) { RealmId = RealmId };
    public KeycloakRoute Route { get; } = KeycloakRoute.Load(Directory.GetCurrentDirectory());
    public void Evidence(string name, JsonNode? value) => ledger.Evidence[name] = value;
    public Task<LiveReply> Get(string route, JsonObject? query = null, params (string, string)[] paths) => Call("GET", route, null, query, null, paths);
    public Task<LiveReply> Post(string route, JsonNode? body = null, JsonObject? query = null, params (string, string)[] paths) => Call("POST", route, body, query, null, paths);
    public Task<LiveReply> Put(string route, JsonNode? body = null, params (string, string)[] paths) => Call("PUT", route, body, null, null, paths);
    public Task<LiveReply> Delete(string route, params (string, string)[] paths) => Call("DELETE", route, null, null, null, paths);
    public async Task<LiveReply> Call(string method, string route, JsonNode? body = null, JsonObject? query = null, HttpContent? raw = null, params (string, string)[] paths)
    {
        string template = route.StartsWith("/admin/", StringComparison.Ordinal) ? route : "/admin/realms/{realm}" + (route.Length == 0 ? "" : "/" + route.Trim('/'));
        if (Route.Exclusion(template) is { } exclusion) throw new NotSupportedException("Route " + Route.Id + " excludes " + template + ": " + exclusion);
        var values = paths.ToDictionary(p => p.Item1, p => p.Item2); values.TryAdd("realm", Realm);
        string[] args = Regex.Matches(template, @"\{([^}]+)\}").Select(m => values.TryGetValue(m.Groups[1].Value, out string? v) ? v : throw new InvalidOperationException("Missing live fixture ID: " + m.Value)).ToArray();
        string key = LiveLedger.Key(method, template);
        try
        {
            var response = await LiveRoutes.Invoke(Sdk, new(key, args, body, query, raw, Cancellation));
            ledger.Observe(key, (int)response.StatusCode);
            return new(key, template, response);
        }
        catch (KeycloakAdminException error)
        {
            ledger.Observe(key, (int)error.StatusCode!);
            throw new InvalidOperationException($"Live request failed: {method} {template} => {(int)error.StatusCode!}", error);
        }
    }
    public void Prove(bool condition, string proof, params LiveReply[] replies)
    {
        if (!condition) throw new InvalidOperationException("Business assertion failed: " + proof);
        foreach (var reply in replies) ledger.Accept(reply.Key, proof, (int)reply.Response.StatusCode);
    }
    public async Task<bool> Missing(string route, params (string, string)[] paths)
    {
        try { await Get(route, null, paths); return false; }
        catch (InvalidOperationException e) when (e.InnerException is KeycloakAdminException { StatusCode: HttpStatusCode.NotFound }) { return true; }
    }
    public static JsonObject O(string json = "{}") => JsonNode.Parse(json)!.AsObject();
    public static string S(JsonNode? node, string key) => node?[key]?.GetValue<string>() ?? "";
    public static bool Has(JsonNode? node, string key, string value) => node is JsonArray a && a.Any(n => S(n, key) == value);
}
internal sealed class LiveLedger
{
    public JsonObject Evidence { get; } = new();
    private readonly DateTimeOffset started = DateTimeOffset.UtcNow;
    private readonly Dictionary<string, (int Status, string Proof)> accepted = new(StringComparer.Ordinal);
    private readonly Dictionary<string, HashSet<int>> observed = new(StringComparer.Ordinal);
    public static string Key(string method, string path) => method + " " + Regex.Replace(path.TrimEnd('/'), @"\{[^}]+\}", "{}");
    public void Observe(string key, int status) { if (!observed.TryGetValue(key, out var values)) observed[key] = values = []; values.Add(status); }
    public void Accept(string key, string proof, int status)
    {
        if (status is < 200 or >= 300 || !observed.TryGetValue(key, out var values) || !values.Contains(status)) throw new InvalidOperationException("Acceptance requires a successful real SDK response.");
        accepted[key] = (status, proof);
    }
    public async Task Write(bool requireAll, CancellationToken cancellationToken = default)
    {
        string mode = System.Runtime.CompilerServices.RuntimeFeature.IsDynamicCodeSupported ? "managed" : "native-aot";
        var route = KeycloakRoute.Load(Directory.GetCurrentDirectory());
        Directory.CreateDirectory("artifacts/full-live");
        var lines = new List<string> { "method\tpath\tstatus\tproof" };
        var missing = new List<string>();
        var excluded = new List<string> { "method\tpath\treason" };
        foreach (var endpoint in AdminEndpointCatalog.All.OrderBy(e => e.Method + e.Path, StringComparer.Ordinal))
        {
            string key = Key(endpoint.Method, endpoint.Path);
            if (route.Exclusion(endpoint.Path) is { } reason) { excluded.Add(endpoint.Method + "\t" + endpoint.Path + "\t" + reason); continue; }
            if (accepted.TryGetValue(key, out var proof)) lines.Add($"{endpoint.Method}\t{endpoint.Path}\t{proof.Status}\t{proof.Proof}");
            else missing.Add(endpoint.Method + "\t" + endpoint.Path);
        }
        string prefix = "artifacts/full-live/" + route.Id + "-" + mode;
        await File.WriteAllLinesAsync(prefix + ".tsv", lines, cancellationToken);
        await File.WriteAllLinesAsync(prefix + "-missing.tsv", missing, cancellationToken);
        await File.WriteAllLinesAsync(prefix + "-excluded.tsv", excluded, cancellationToken);
        string executable = System.Runtime.CompilerServices.RuntimeFeature.IsDynamicCodeSupported
            ? Path.Combine(AppContext.BaseDirectory, "Keycloak.Admin.Sdk.IntegrationTests.dll") : Environment.ProcessPath!;
        var manifest = new JsonObject
        {
            ["route"] = route.Id, ["mode"] = mode, ["startedUtc"] = started.ToString("O"), ["finishedUtc"] = DateTimeOffset.UtcNow.ToString("O"),
            ["completed"] = requireAll && missing.Count == 0, ["accepted"] = lines.Count - 1, ["expected"] = AdminEndpointCatalog.All.Count - excluded.Count + 1,
            ["missing"] = missing.Count, ["excluded"] = excluded.Count - 1,
            ["sourceFingerprint"] = LiveEvidence.Fingerprint(Directory.GetCurrentDirectory()),
            ["executableSha256"] = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(await File.ReadAllBytesAsync(executable, cancellationToken))).ToLowerInvariant(),
            ["ledgerSha256"] = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(await File.ReadAllBytesAsync(prefix + ".tsv", cancellationToken))).ToLowerInvariant(),
            ["evidence"] = Evidence.DeepClone()
        };
        await File.WriteAllTextAsync(prefix + ".json", LiveJson.String(manifest), cancellationToken);
        Console.WriteLine($"Business-verified real operations ({route.Id}/{mode}): {accepted.Count}/{AdminEndpointCatalog.All.Count - excluded.Count + 1}; missing {missing.Count}; explicitly excluded {excluded.Count - 1}.");
        if (requireAll && missing.Count > 0) throw new InvalidOperationException("Full real-container acceptance is incomplete; see " + prefix + "-missing.tsv");
    }
}
internal static class LiveJson
{
    public static string String(JsonNode value) => JsonSerializer.Serialize(value, LiveJsonContext.Default.JsonNode);
    public static T Read<T>(JsonNode value) => JsonSerializer.Deserialize(String(value), (System.Text.Json.Serialization.Metadata.JsonTypeInfo<T>)KeycloakJsonContext.Default.GetTypeInfo(typeof(T))!)!;
}
[JsonSerializable(typeof(JsonNode))]
internal partial class LiveJsonContext : JsonSerializerContext;
