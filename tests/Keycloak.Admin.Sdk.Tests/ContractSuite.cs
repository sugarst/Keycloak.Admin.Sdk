using System.Net;
using System.Text;
using System.Text.Json;
using Keycloak.Admin.Sdk;

public static partial class ContractSuite
{
    public static async Task RunAsync()
    {
        if (JsonSerializer.IsReflectionEnabledByDefault) throw new Exception("Reflection JSON must be disabled.");
        await AllEndpointsAsync();
        await SemanticsAsync();
        await TokenCacheAsync();
        await StreamOwnershipAsync();
        await AlignmentContracts.RunAsync();
        await RuntimeContracts.RunAsync();
        await RecoveryContracts.RunAsync();
        await DependencyInjectionContracts.RunAsync();
        await InterfaceContracts.RawTransportsAsync();
        await ResilienceContracts.RunAsync();
        await CapabilityContracts.RunAsync();
        await RuntimeCapabilityContracts.RunAsync();
        await PlatformContracts.RunAsync();
        ModelMatrix.Run();
        foreach (var operation in EndpointMatrix.Cases) await operation.RunAsync();
        Console.WriteLine($"PASS: {EndpointMatrix.Cases.Count} API operation matrices and all published DTO contracts.");
        Directory.CreateDirectory("artifacts");
        await File.WriteAllLinesAsync("artifacts/routing-verified.tsv", AdminEndpointCatalog.All.Select(x => x.Method + "\t" + x.Path));
        Console.WriteLine($"PASS: {AdminEndpointCatalog.All.Count} generated endpoint calls, JSON reflection disabled, HTTP semantics, token concurrency/expiry.");
    }

    public static async Task SemanticsAsync()
    {
        using var handler = new DelegateHandler(async (r, ct) =>
        {
            Check(r.RequestUri!.AbsoluteUri == "https://keycloak.invalid/auth/admin/realms/demo/users?enabled=false&first=0&search=", "Query omission/default values");
            await Task.Yield();
            return new(HttpStatusCode.OK) { Content = new StringContent("[{\"id\":\"u1\",\"enabled\":false,\"attributes\":{\"team\":[\"dev\"]},\"future\":7}]") };
        });
        using var http = new HttpClient(handler);
        var sdk = new KeycloakAdminClient(http, new Uri("https://keycloak.invalid/auth"));
        var users = await sdk.Users.GetUsersAsync("demo", enabled: false, first: 0, search: "");
        Check(users.Body![0].AdditionalProperties!["future"].GetInt32() == 7 && users.Body[0].Attributes!["team"][0] == "dev", "Unknown fields and dynamic attributes");

        handler.Action = async (r, ct) =>
        {
            string body = await r.Content!.ReadAsStringAsync(ct);
            Check(body.Contains("\"enabled\":false") && !body.Contains("email"), "Omission and explicit false serialization");
            var response = new HttpResponseMessage(HttpStatusCode.Created) { Content = new ByteArrayContent([]) };
            response.Headers.Location = new Uri("/admin/realms/demo/users/u1", UriKind.Relative);
            return response;
        };
        var created = await sdk.Users.CreateUserAsync("demo", new UserRepresentation { Username = "test", Enabled = false });
        Check(created.StatusCode == HttpStatusCode.Created && created.Location!.OriginalString.EndsWith("u1"), "Created Location");
        handler.Action = (r, _) =>
        {
            Check(r.RequestUri!.Query == "?operationTypes=CREATE&operationTypes=UPDATE", "Repeated array query parameters");
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("[]") });
        };
        await sdk.RealmAdmin.GetEventsAsync("demo", operationTypes: ["CREATE", "UPDATE"]);
        handler.Action = (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.Unauthorized) { Content = new StringContent("secret password") });
        try { await sdk.Users.CreateUserAsync("demo", new()); throw new Exception("Expected failure"); }
        catch (KeycloakAdminException ex) { Check(ex.StatusCode == HttpStatusCode.Unauthorized && !ex.ToString().Contains("secret"), "Sanitized HTTP failure"); }
        handler.Action = (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("not json") });
        try { await sdk.Users.GetUsersAsync("demo"); throw new Exception("Expected JSON failure"); }
        catch (KeycloakResponseFormatException ex) { Check(ex.StatusCode == HttpStatusCode.OK, "Format status"); }
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        try { await sdk.Users.GetUsersAsync("demo", cancellationToken: cts.Token); throw new Exception("Expected cancellation"); }
        catch (OperationCanceledException) { }
        Check(http.DefaultRequestHeaders.Authorization is null, "Shared headers unchanged");
    }

    public static async Task TokenCacheAsync()
    {
        int count = 0;
        var clock = new TestClock();
        using var handler = new DelegateHandler(async (r, ct) =>
        {
            Check(r.RequestUri!.AbsolutePath == "/auth/realms/master/protocol/openid-connect/token", "Authentication realm");
            Check((await r.Content!.ReadAsStringAsync(ct)).Contains("client_secret=s%2B%26"), "Form encoding");
            await Task.Delay(10, ct);
            Interlocked.Increment(ref count);
            return new(HttpStatusCode.OK) { Content = new StringContent("{\"access_token\":\"token\",\"expires_in\":60,\"token_type\":\"Bearer\"}") };
        });
        using var http = new HttpClient(handler);
        using var provider = new ClientCredentialsTokenProvider(http, new Uri("https://keycloak.invalid/auth"), "master", "service", _ => ValueTask.FromResult("s+&"), clock);
        await Task.WhenAll(Enumerable.Range(0, 30).Select(async _ => await provider.GetAccessTokenAsync()));
        Check(count == 1, "Concurrent cache miss coalescing");
        clock.Now = clock.Now.AddSeconds(55);
        await provider.GetAccessTokenAsync();
        Check(count == 2, "Expiry refresh");
    }

    public static async Task StreamOwnershipAsync()
    {
        var content = new TrackingContent();
        using var handler = new DelegateHandler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = content }));
        using var http = new HttpClient(handler);
        var sdk = new KeycloakAdminClient(http, new Uri("https://keycloak.invalid/"));
        using (var download = await sdk.OpenStreamAsync(HttpMethod.Get, "/admin/realms/demo/partial-export"))
        {
            Check(!content.Disposed && download.Content.ReadByte() == 1, "Stream ownership while reading");
        }
        Check(content.Disposed, "Stream response disposal");
    }

    private sealed class TrackingContent() : ByteArrayContent([1, 2, 3])
    {
        public bool Disposed { get; private set; }
        protected override void Dispose(bool disposing) { Disposed = true; base.Dispose(disposing); }
    }

    private static void Check(bool condition, string message) { if (!condition) throw new Exception(message); }

    private sealed class TestClock : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = DateTimeOffset.UnixEpoch;
        public override DateTimeOffset GetUtcNow() => Now;
    }

    private sealed class DelegateHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> action) : HttpMessageHandler
    {
        public Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> Action { get; set; } = action;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => Action(request, cancellationToken);
    }

    private sealed class CaptureHandler : HttpMessageHandler
    {
        public string ExpectedMethod { get; set; } = "";
        public string ExpectedPath { get; set; } = "";
        public string ResponseBody { get; set; } = "";
        private bool called;
        public void AssertCalled() { Check(called, "Generated method did not send a request"); called = false; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Check(request.Method.Method == ExpectedMethod, "Method " + ExpectedPath);
            Check(request.RequestUri!.AbsolutePath == ExpectedPath, "Path " + request.RequestUri.AbsolutePath + " expected " + ExpectedPath);
            Check(request.Headers.Authorization?.ToString() == "Bearer test-token", "Request-local authorization");
            called = true;
            return Task.FromResult(new HttpResponseMessage(ResponseBody.Length == 0 ? HttpStatusCode.NoContent : HttpStatusCode.OK)
            { Content = new StringContent(ResponseBody, Encoding.UTF8, "application/json") });
        }
    }
}
