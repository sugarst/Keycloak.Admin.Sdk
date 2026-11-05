using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Keycloak.Admin.Sdk;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Polly.CircuitBreaker;
using Polly.Timeout;

public static class ResilienceContracts
{
    private static readonly Uri Server = new("https://keycloak.invalid/auth/");
    private static KeycloakHttpResilienceOptions Fast => new() { Enabled = true, MaxRetryAttempts = 1, RetryDelay = TimeSpan.Zero, UseJitter = false, EnableCircuitBreaker = false };
    public static async Task RunAsync()
    {
        await ReadsAsync(); await BypassAsync(); await AuthenticationAsync(); await TimeoutsAsync();
        await CircuitAsync(); await StreamsAsync(); Validation();
    }

    public static async Task ReadsAsync()
    {
        using (var disabled = new Rig((_, _) => Task.FromResult(Response(HttpStatusCode.ServiceUnavailable)), new()))
        {
            await Expect<KeycloakAdminException>(() => disabled.Sdk.Users.GetUsersAsync("demo"));
            Check(disabled.Calls == 1, "disabled by default");
        }
        foreach (var status in new[] { HttpStatusCode.RequestTimeout, HttpStatusCode.TooManyRequests, HttpStatusCode.InternalServerError, HttpStatusCode.ServiceUnavailable })
        {
            int calls = 0;
            using var rejected = new Payload("discarded");
            using var rig = new Rig((r, _) =>
            {
                Check(r.RequestUri!.Query == "?first=0&max=10", "query retained across attempts");
                if (++calls == 1) return Task.FromResult(new HttpResponseMessage(status) { Content = rejected });
                Check(rejected.Disposed, "retry disposes rejected response");
                return Task.FromResult(Response(HttpStatusCode.OK));
            }, Fast);
            await rig.Sdk.Users.GetUsersAsync("demo", first: 0, max: 10);
            Check(rig.Calls == 2 && rig.TokenCalls == 1, "transient read retries once without refreshing token");
        }
        using (var exhausted = new Rig((_, _) => Task.FromResult(Response(HttpStatusCode.ServiceUnavailable)),
            new() { Enabled = true, MaxRetryAttempts = 2, RetryDelay = TimeSpan.Zero, EnableCircuitBreaker = false }))
        {
            var error = await Expect<KeycloakAdminException>(() => exhausted.Sdk.Users.GetUsersAsync("demo"));
            Check(exhausted.Calls == 3 && error.Operation == "Users.GetUsersAsync" && error.StatusCode == HttpStatusCode.ServiceUnavailable, "retry budget and final error");
        }
        int count = 0;
        using var network = new Rig((_, _) => ++count == 1 ? throw new HttpRequestException("temporary connection failure") : Task.FromResult(Response(HttpStatusCode.OK)), Fast);
        await network.Sdk.Users.GetUsersAsync("demo");
        Check(network.Calls == 2, "transient network failure retries");
    }

    public static async Task BypassAsync()
    {
        foreach (var method in new[] { HttpMethod.Post, HttpMethod.Put, HttpMethod.Patch, HttpMethod.Delete, HttpMethod.Get, HttpMethod.Head })
        {
            using var rig = new Rig((_, _) => Task.FromResult(Response(HttpStatusCode.ServiceUnavailable)), Fast);
            using var content = new StringContent("one-shot content");
            await Expect<KeycloakAdminException>(() => rig.Sdk.SendAsync(method, "/admin/serverinfo", content: content));
            Check(rig.Calls == 1, "content bypasses pipeline");
            if (method != HttpMethod.Get && method != HttpMethod.Head)
            {
                await Expect<KeycloakAdminException>(() => rig.Sdk.SendAsync(method, "/admin/serverinfo"));
                Check(rig.Calls == 2, "bodyless writes bypass pipeline");
            }
        }
        using var tokenFailure = new Rig((_, _) => throw new InvalidOperationException("business request must not run"), Fast, tokenStatus: HttpStatusCode.ServiceUnavailable);
        var error = await Expect<KeycloakAdminException>(() => tokenFailure.Sdk.Users.GetUsersAsync("demo"));
        Check(tokenFailure.TokenCalls == 1 && tokenFailure.Calls == 0 && error.Stage == KeycloakFailureStage.TokenEndpoint, "token POST never retried");
    }

    public static async Task AuthenticationAsync()
    {
        int calls = 0;
        var policy = new Policy();
        using var combined = new Rig((r, _) =>
        {
            int attempt = ++calls;
            Check(r.Headers.Authorization!.Parameter == (attempt <= 2 ? "token-1" : "token-2"), "token changes only after 401");
            return Task.FromResult(Response(attempt switch { 1 or 3 => HttpStatusCode.ServiceUnavailable, 2 => HttpStatusCode.Unauthorized, _ => HttpStatusCode.OK }));
        }, Fast, recovery: true, policy: policy);
        await combined.Sdk.Users.GetUsersAsync("demo");
        Check(combined.Calls == 4 && combined.TokenCalls == 2 && policy.Calls == 1, "two bounded HTTP sends, one policy evaluation");

        foreach (var status in new[] { HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden, HttpStatusCode.NotFound, HttpStatusCode.Conflict })
        {
            using var rig = new Rig((_, _) => Task.FromResult(Response(status)), Fast, recovery: true);
            await Expect<KeycloakAdminException>(() => rig.Sdk.Users.GetUsersAsync("demo"));
            int expected = status == HttpStatusCode.Unauthorized ? 2 : 1;
            Check(rig.Calls == expected && rig.TokenCalls == expected, "authentication and business errors not transient");
        }
    }

    public static async Task TimeoutsAsync()
    {
        using (var attempts = new Rig(async (_, ct) => { await Task.Delay(Timeout.InfiniteTimeSpan, ct); return Response(HttpStatusCode.OK); },
            new() { Enabled = true, MaxRetryAttempts = 1, RetryDelay = TimeSpan.Zero, EnableCircuitBreaker = false, AttemptTimeout = TimeSpan.FromMilliseconds(30), TotalRequestTimeout = TimeSpan.FromSeconds(5) }))
        {
            await Expect<TimeoutRejectedException>(() => attempts.Sdk.Users.GetUsersAsync("demo"));
            Check(attempts.Calls == 2, "attempt timeout is retryable within total budget");
        }
        using (var total = new Rig((_, _) =>
        {
            var response = Response(HttpStatusCode.TooManyRequests);
            response.Headers.RetryAfter = new RetryConditionHeaderValue(TimeSpan.FromHours(1));
            return Task.FromResult(response);
        }, new() { Enabled = true, MaxRetryAttempts = 1, EnableCircuitBreaker = false, AttemptTimeout = TimeSpan.FromMilliseconds(50), TotalRequestTimeout = TimeSpan.FromMilliseconds(100) }))
        {
            await Expect<TimeoutRejectedException>(() => total.Sdk.Users.GetUsersAsync("demo"));
            Check(total.Calls == 1, "total timeout bounds Retry-After wait");
        }
        using var cancellation = new CancellationTokenSource();
        using var cancelled = new Rig((_, _) =>
        {
            cancellation.CancelAfter(TimeSpan.FromMilliseconds(30));
            return Task.FromResult(Response(HttpStatusCode.ServiceUnavailable));
        }, new() { Enabled = true, MaxRetryAttempts = 1, RetryDelay = TimeSpan.FromSeconds(1), EnableCircuitBreaker = false });
        await Expect<OperationCanceledException>(() => cancelled.Sdk.Users.GetUsersAsync("demo", cancellationToken: cancellation.Token));
        Check(cancelled.Calls == 1, "caller cancellation never retries");
    }

    public static async Task CircuitAsync()
    {
        var options = new KeycloakHttpResilienceOptions { Enabled = true, MaxRetryAttempts = 0, CircuitBreakerMinimumThroughput = 2 };
        using var rig = new Rig((r, _) => Task.FromResult(Response(r.Method == HttpMethod.Get ? HttpStatusCode.ServiceUnavailable : HttpStatusCode.OK)), options);
        for (int i = 0; i < 2; i++) await Expect<KeycloakAdminException>(() => rig.Sdk.Users.GetUsersAsync("demo"));
        await Expect<BrokenCircuitException>(() => rig.Sdk.Users.GetUsersAsync("demo"));
        Check(rig.Calls == 2, "open read circuit blocks physical send");
        await rig.Sdk.SendAsync(HttpMethod.Post, "/admin/serverinfo");
        Check(rig.Calls == 3, "writes bypass open read circuit");
        var tokens = rig.Services.GetRequiredKeyedService<ClientCredentialsTokenProvider>("test");
        await tokens.InvalidateAsync("token-1");
        Check(await tokens.GetAccessTokenAsync() == "token-2" && rig.TokenCalls == 2, "token acquisition bypasses open circuit");

        var services = new ServiceCollection();
        services.AddKeycloakAdminSdk("a", o => Configure(o, options)).ConfigurePrimaryHttpMessageHandler(() => new Handler((_, _) => Task.FromResult(Response(HttpStatusCode.ServiceUnavailable))));
        services.AddKeycloakAdminSdk("b", o => Configure(o, options)).ConfigurePrimaryHttpMessageHandler(() => new Handler((_, _) => Task.FromResult(Response(HttpStatusCode.OK))));
        using var provider = services.BuildServiceProvider();
        var a = provider.GetRequiredKeyedService<HttpClient>("a");
        for (int i = 0; i < 2; i++) using (await a.GetAsync(Server)) { }
        await Expect<BrokenCircuitException>(() => a.GetAsync(Server));
        using var independent = await provider.GetRequiredKeyedService<HttpClient>("b").GetAsync(Server);
        Check(independent.IsSuccessStatusCode, "named clients have independent circuits");
    }

    public static async Task StreamsAsync()
    {
        int calls = 0;
        using var rig = new Rig((_, _) => Task.FromResult(Response(++calls == 1 ? HttpStatusCode.ServiceUnavailable : HttpStatusCode.OK, "download")), Fast);
        using var stream = await rig.Sdk.OpenStreamAsync(HttpMethod.Head, "/admin/serverinfo");
        Check(stream.Content.ReadByte() == 'd' && rig.Calls == 2, "stream retries before delivery");
        using var broken = new Rig((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new BrokenContent() }), Fast);
        using var delivered = await broken.Sdk.OpenStreamAsync(HttpMethod.Get, "/admin/serverinfo");
        await Expect<IOException>(async () => { _ = await delivered.Content.ReadAsync(new byte[1]); });
        Check(broken.Calls == 1, "no transparent retry after stream delivery");
    }

    public static void Validation()
    {
        KeycloakHttpResilienceOptions?[] invalid = [null, new() { MaxRetryAttempts = -1 }, new() { MaxRetryAttempts = 11 },
            new() { RetryDelay = TimeSpan.FromTicks(-1) }, new() { RetryDelay = TimeSpan.FromMinutes(2) },
            new() { AttemptTimeout = TimeSpan.Zero }, new() { AttemptTimeout = TimeSpan.FromMinutes(1) },
            new() { TotalRequestTimeout = TimeSpan.FromDays(2) }, new() { CircuitBreakerFailureRatio = 0 }, new() { CircuitBreakerFailureRatio = 1.1 },
            new() { CircuitBreakerFailureRatio = double.NaN }, new() { CircuitBreakerMinimumThroughput = 1 },
            new() { CircuitBreakerSamplingDuration = TimeSpan.Zero }, new() { CircuitBreakerSamplingDuration = TimeSpan.FromDays(2) },
            new() { CircuitBreakerBreakDuration = TimeSpan.Zero }, new() { CircuitBreakerBreakDuration = TimeSpan.FromDays(2) }];
        foreach (var options in invalid)
        {
            var services = new ServiceCollection();
            services.AddKeycloakAdminSdk(o => Configure(o, options!));
            using var provider = services.BuildServiceProvider();
            try { provider.GetRequiredService<KeycloakAdminClient>(); }
            catch (OptionsValidationException) { continue; }
            throw new InvalidOperationException("Invalid resilience settings accepted");
        }
    }

    private static void Configure(KeycloakAdminSdkOptions options, KeycloakHttpResilienceOptions resilience)
    {
        options.Server = Server; options.ClientId = "service";
        options.ClientSecret = (_, _) => ValueTask.FromResult("secret"); options.Resilience = resilience;
    }
    private static HttpResponseMessage Response(HttpStatusCode status, string body = "[]") => new(status) { Content = new StringContent(body) };
    private static void Check(bool value, string message) { if (!value) throw new InvalidOperationException(message); }
    private static async Task<T> Expect<T>(Func<Task> action) where T : Exception
    {
        try { await action(); } catch (T error) { return error; }
        throw new InvalidOperationException("Expected " + typeof(T).Name);
    }
    private sealed class Rig : IDisposable
    {
        public ServiceProvider Services { get; }
        public KeycloakAdminClient Sdk { get; }
        public int Calls { get; private set; }
        public int TokenCalls { get; private set; }
        public Rig(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send, KeycloakHttpResilienceOptions options,
            bool recovery = false, HttpStatusCode tokenStatus = HttpStatusCode.OK, IKeycloakAdminRequestPolicy? policy = null)
        {
            var services = new ServiceCollection();
            services.AddKeycloakAdminSdk("test", o =>
            {
                Configure(o, options);
                o.Client = new() { EnableUnauthorizedRecovery = recovery, RequestPolicy = policy };
            }).ConfigurePrimaryHttpMessageHandler(() => new Handler((request, ct) =>
            {
                if (request.RequestUri!.AbsolutePath.EndsWith("/token", StringComparison.Ordinal))
                {
                    TokenCalls++;
                    return Task.FromResult(Response(tokenStatus, "{\"access_token\":\"token-" + TokenCalls + "\",\"expires_in\":60,\"token_type\":\"Bearer\"}"));
                }
                Calls++; return send(request, ct);
            }));
            Services = services.BuildServiceProvider(); Sdk = Services.GetRequiredKeyedService<KeycloakAdminClient>("test");
        }
        public void Dispose() => Services.Dispose();
    }
    private sealed class Policy : IKeycloakAdminRequestPolicy
    {
        public int Calls { get; private set; }
        public ValueTask EnsureAllowedAsync(HttpMethod method, Uri target, string? operation, CancellationToken ct) { Calls++; return ValueTask.CompletedTask; }
    }
    private sealed class Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) => send(request, ct);
    }
    private sealed class Payload(string value) : ByteArrayContent(Encoding.UTF8.GetBytes(value))
    {
        public bool Disposed { get; private set; }
        protected override void Dispose(bool disposing) { Disposed = true; base.Dispose(disposing); }
    }
    private sealed class BrokenContent : HttpContent
    {
        protected override bool TryComputeLength(out long length) { length = 0; return false; }
        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) => throw new IOException("failed after headers");
        protected override Task<Stream> CreateContentReadStreamAsync() => Task.FromResult<Stream>(new BrokenStream());
    }
    private sealed class BrokenStream : MemoryStream
    {
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default) => ValueTask.FromException<int>(new IOException("failed after delivery"));
    }
}
