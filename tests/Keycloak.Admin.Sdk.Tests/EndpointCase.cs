using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using System.Text.RegularExpressions;
using Keycloak.Admin.Sdk;

public sealed record MatrixQuery(string Name, string Kind);
public sealed record MatrixResult(AdminResponse Response, bool? HasBody, JsonElement? Body)
{
    public static MatrixResult From(AdminResponse response) => new(response, null, null);
    public static MatrixResult From<T>(AdminResponse<T> response, JsonTypeInfo<T> info) =>
        new(response, response.HasBody, response.HasBody ? JsonSerializer.SerializeToElement(response.Body!, info) : null);
}

public sealed class MatrixInput(int variant, bool hasBody, CancellationToken cancellationToken = default)
{
    public bool HasBody { get; } = hasBody;
    public string RequestJson { get; init; } = "{}";
    public HttpContent? RawContent { get; init; }
    public string? SelectedQuery { get; init; }
    public CancellationToken CancellationToken { get; } = cancellationToken;
    public bool? Boolean => variant == 0 ? null : variant == 2;
    public int? Integer => variant == 0 ? null : variant == 2 ? 7 : 0;
    public long? Long => Integer;
    public double? Number => variant == 0 ? null : variant == 2 ? 1.25 : 0;
    public string? Text => variant == 0 ? null : variant == 3 ? "" : "q +&中";
    public List<string>? List => variant == 0 ? null : variant == 3 ? [] : ["one+&", "二"];
    public bool? BooleanFor(string name) => Includes(name) ? Boolean : null;
    public int? IntegerFor(string name) => Includes(name) ? Integer : null;
    public long? LongFor(string name) => Includes(name) ? Long : null;
    public double? NumberFor(string name) => Includes(name) ? Number : null;
    public string? TextFor(string name) => Includes(name) ? Text : null;
    public List<string>? ListFor(string name) => Includes(name) ? List : null;
    private bool Includes(string name) => SelectedQuery is null || SelectedQuery == name;
}

public sealed record EndpointCase(string Method, string Path, string Operation, string TestName, string RequestKind,
    string ResponseKind, string RequestJson, string ResponseJson, MatrixQuery[] Queries, int[] SuccessStatuses,
    string[] MediaTypes, Func<KeycloakAdminClient, MatrixInput, Task<MatrixResult>> Invoke)
{
    public async Task RunAsync()
    {
        try
        {
            foreach (int status in SuccessStatuses)
                await SuccessAsync(status, 1, RequestKind != "none", status == 204 ? "" : ResponseJson);
            await SuccessAsync(200, 0, false, ResponseJson);
            await SuccessAsync(200, 2, RequestKind != "none", AlternateResponse());
            await SuccessAsync(200, 3, RequestKind != "none", ResponseJson);
            await SuccessAsync(200, 1, false, "");
            foreach (var query in Queries)
                await SuccessAsync(200, 2, false, ResponseJson, selectedQuery: query.Name);
            if (RequestKind == "raw")
                foreach (string media in MediaTypes.Append("application/octet-stream").Distinct())
                    await SuccessAsync(200, 1, true, ResponseJson, media);
            foreach (int status in new[] { 400, 401, 403, 404, 409, 415, 500 }) await FailureAsync(status);
            if (ResponseKind == "json") await MalformedAsync();
            await CancelledAsync();
            await NetworkFailureAsync();
        }
        catch (Exception error) { throw new InvalidOperationException(Method + " " + Path + " (" + Operation + ") matrix failed: " + error.Message, error); }
    }

    private string AlternateResponse()
    {
        using var json = JsonDocument.Parse(ResponseJson);
        return json.RootElement.ValueKind switch
        {
            JsonValueKind.Array => "[]", JsonValueKind.Object => "{}", JsonValueKind.String => "\"\"",
            JsonValueKind.Number => "0", JsonValueKind.False => "true", JsonValueKind.True => "false", _ => ResponseJson
        };
    }

    private async Task SuccessAsync(int status, int variant, bool body, string reply, string media = "application/json", string? selectedQuery = null)
    {
        TrackingPayload? raw = RequestKind == "raw" && body ? new(media, RequestJson) : null;
        var input = new MatrixInput(variant, body) { RequestJson = RequestJson, RawContent = raw, SelectedQuery = selectedQuery };
        using var responseContent = new TrackingPayload("application/json", reply);
        using var handler = new MatrixHandler(async (request, ct) =>
        {
            await AssertRequestAsync(request, input, media, ct);
            var response = new HttpResponseMessage((HttpStatusCode)status) { Content = responseContent };
            response.Headers.Location = new Uri("/admin/created/resource", UriKind.Relative);
            response.Headers.Add("X-Matrix", "preserved");
            return response;
        });
        using var http = new HttpClient(handler);
        var result = await Invoke(Client(http), input);
        Check(handler.Count == 1, "exactly one request; no implicit replay");
        Check(result.Response.StatusCode == (HttpStatusCode)status, "status preserved");
        Check(result.Response.Location?.OriginalString == "/admin/created/resource", "Location preserved without follow");
        Check(result.Response.Headers["X-Matrix"].Single() == "preserved", "response headers preserved");
        Check(Encoding.UTF8.GetString(result.Response.Content.Span) == reply, "raw response bytes preserved");
        if (ResponseKind == "json")
        {
            Check(result.HasBody == (reply.Length > 0), "empty response distinguished from JSON body");
            if (reply.Length > 0) MatrixJson.Equal(reply, result.Body!.Value.GetRawText());
        }
        Check(responseContent.Disposed, "buffered response disposed");
        Check(raw is null || raw.Disposed, "caller content consumed and disposed");
        Check(http.DefaultRequestHeaders.Authorization is null, "no shared header mutation");
    }

    private async Task AssertRequestAsync(HttpRequestMessage request, MatrixInput input, string media, CancellationToken ct)
    {
        int pathIndex = 0;
        string expected = Regex.Replace(Path, @"\{[^}]+\}", _ => Uri.EscapeDataString("p" + pathIndex++ + " /%+&中"));
        Check(request.Method.Method == Method && request.RequestUri!.AbsolutePath == "/context" + expected, "HTTP method and each distinct escaped path binding");
        Check(request.Headers.Authorization?.ToString() == "Bearer matrix-token", "request-local bearer");
        var expectedQuery = new List<KeyValuePair<string, string>>();
        foreach (var query in Queries)
        {
            IEnumerable<string> values = query.Kind switch
            {
                "bool" => input.BooleanFor(query.Name) is { } b ? [b ? "true" : "false"] : [],
                "int" or "long" => input.IntegerFor(query.Name) is { } i ? [i.ToString(System.Globalization.CultureInfo.InvariantCulture)] : [],
                "double" => input.NumberFor(query.Name) is { } d ? [d.ToString(System.Globalization.CultureInfo.InvariantCulture)] : [],
                "list" => input.ListFor(query.Name) ?? [], _ => input.TextFor(query.Name) is { } s ? [s] : []
            };
            expectedQuery.AddRange(values.Select(v => new KeyValuePair<string, string>(query.Name, v)));
        }
        var actual = request.RequestUri!.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(p => p.Split('=', 2)).Select(p => new KeyValuePair<string, string>(Uri.UnescapeDataString(p[0]), Uri.UnescapeDataString(p[1]))).ToArray();
        Check(actual.OrderBy(p => p.Key).ThenBy(p => p.Value).SequenceEqual(expectedQuery.OrderBy(p => p.Key).ThenBy(p => p.Value)), "all query bindings, omissions, true/false, zero, empty and repeated list values");
        if (RequestKind == "none" || !input.HasBody) Check(request.Content is null, "absent request body stays absent");
        else
        {
            Check(request.Content is not null, "request body present");
            Check(request.Content!.Headers.ContentType?.MediaType == (RequestKind == "json" ? "application/json" : media), "request media type preserved");
            string payload = await request.Content.ReadAsStringAsync(ct);
            if (RequestKind == "json") MatrixJson.Equal(RequestJson, payload);
            else Check(payload == RequestJson, "raw content passes through unchanged");
        }
    }

    private async Task FailureAsync(int status)
    {
        using var content = new TrackingPayload("application/json", "secret-personal-data");
        using var handler = new MatrixHandler((_, _) => Task.FromResult(new HttpResponseMessage((HttpStatusCode)status) { Content = content }));
        using var http = new HttpClient(handler);
        try { await Invoke(Client(http), new(0, false)); throw new Exception("Expected HTTP failure " + status); }
        catch (KeycloakAdminException error)
        {
            Check(error.StatusCode == (HttpStatusCode)status && error.Method == Method, "HTTP failure preserves status and method");
            Check(!error.ToString().Contains("secret-personal-data", StringComparison.Ordinal), "error content redacted");
        }
        Check(handler.Count == 1 && content.Disposed, "failed response disposed without retries");
    }
    private async Task MalformedAsync()
    {
        using var handler = new MatrixHandler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{invalid-json") }));
        using var http = new HttpClient(handler);
        try { await Invoke(Client(http), new(0, false)); throw new Exception("Expected JSON format failure"); }
        catch (KeycloakResponseFormatException error) { Check(error.StatusCode == HttpStatusCode.OK && error.InnerException is JsonException, "JSON error retains HTTP status and cause"); }
    }
    private async Task CancelledAsync()
    {
        using var handler = new MatrixHandler((_, _) => throw new Exception("Cancelled request must not be sent"));
        using var http = new HttpClient(handler);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        try { await Invoke(Client(http), new(0, false, cancellation.Token)); throw new Exception("Expected cancellation"); }
        catch (OperationCanceledException) { Check(handler.Count == 0, "pre-cancel does not send"); }
    }
    private async Task NetworkFailureAsync()
    {
        var failure = new HttpRequestException("connection-failure");
        using var handler = new MatrixHandler((_, _) => throw failure);
        using var http = new HttpClient(handler);
        try { await Invoke(Client(http), new(0, false)); throw new Exception("Expected network failure"); }
        catch (HttpRequestException error) { Check(ReferenceEquals(error, failure) && handler.Count == 1, "network exception propagated without replay"); }
    }
    private static KeycloakAdminClient Client(HttpClient http) => new(http, new Uri("https://keycloak.invalid/context/"), new StaticAccessTokenProvider("matrix-token"));
    private static void Check(bool value, string message) { if (!value) throw new InvalidOperationException(message); }
    private sealed class TrackingPayload : ByteArrayContent
    {
        public TrackingPayload(string media, string payload) : base(Encoding.UTF8.GetBytes(payload)) => Headers.ContentType = new(media);
        public bool Disposed { get; private set; }
        protected override void Dispose(bool disposing) { Disposed = true; base.Dispose(disposing); }
    }
    private sealed class MatrixHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> action) : HttpMessageHandler
    {
        public int Count { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) { Count++; return action(request, cancellationToken); }
    }
}

public static class MatrixJson
{
    public static JsonTypeInfo<T> Info<T>() => (JsonTypeInfo<T>)KeycloakJsonContext.Default.GetTypeInfo(typeof(T))!;
    public static T Read<T>(string json) => JsonSerializer.Deserialize(json, Info<T>())!;
    public static void RoundTrip<T>(string json)
    {
        var value = Read<T>(json);
        Equal(json, JsonSerializer.Serialize(value, Info<T>()));
    }
    public static void SingleProperty<T>(T value, string name, string sample)
    {
        using var expected = JsonDocument.Parse(sample);
        string single = "{" + JsonSerializer.Serialize(name, Info<string>()) + ":" + expected.RootElement.GetProperty(name).GetRawText() + "}";
        Equal(single, JsonSerializer.Serialize(value, Info<T>()));
    }
    public static void Equal(string expected, string actual)
    {
        using var left = JsonDocument.Parse(expected); using var right = JsonDocument.Parse(actual);
        if (!JsonElement.DeepEquals(left.RootElement, right.RootElement)) throw new InvalidOperationException("JSON contract differs. Expected: " + expected + "; Actual: " + actual);
    }
}
