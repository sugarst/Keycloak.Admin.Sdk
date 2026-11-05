using System.Net;
using System.Text;
using Keycloak.Admin.Sdk;

public static class RecoveryContracts
{
    private static readonly Uri Server = new("https://keycloak.invalid/auth/");
    private static readonly KeycloakRequestOptions Replay = new() { AllowUnauthorizedReplay = true };
    public static async Task RunAsync()
    {
        await ErrorsAsync(); await ReplayAsync(); await StreamAsync(); await ConcurrencyAsync(); await FailuresAsync();
    }

    public static async Task ErrorsAsync()
    {
        foreach (var (status, kind) in new[] { (400, KeycloakErrorKind.BadRequest), (401, KeycloakErrorKind.Unauthorized),
            (403, KeycloakErrorKind.Forbidden), (404, KeycloakErrorKind.NotFound), (409, KeycloakErrorKind.Conflict), (500, KeycloakErrorKind.Unknown) })
        {
            using var body = new UnreadableContent();
            using var http = new HttpClient(new Handler((_, _) => Task.FromResult(new HttpResponseMessage((HttpStatusCode)status) { Content = body })));
            var sdk = new KeycloakAdminClient(http, Server);
            var error = await Expect<KeycloakAdminException>(() => sdk.Users.CreateUserAsync("private-realm", new() { Username = "secret-user" }));
            Check(error.ErrorKind == kind && error.Stage == KeycloakFailureStage.AdminApi && error.Operation == "Users.CreateUserAsync", "structured classification");
            Check(error.ErrorCode is null && error.Method == "POST" && body.Disposed && !body.Read, "errors never read bodies");
            Check(!error.ToString().Contains("secret-user") && !error.ToString().Contains("private-realm") && error.InnerException is null && error.Data.Count == 0, "safe exception");
        }
        var legacy = new KeycloakAdminException(HttpStatusCode.Conflict, "POST");
        Check(legacy.Stage == KeycloakFailureStage.Unknown && legacy.Operation is null && legacy.StatusCode == HttpStatusCode.Conflict, "legacy exception constructor");
    }

    public static async Task ReplayAsync()
    {
        var tokens = new Tokens();
        int calls = 0;
        using var firstBody = new UnreadableContent();
        HttpRequestMessage? firstRequest = null;
        using var handler = new Handler((r, _) =>
        {
            calls++;
            if (calls == 1)
            {
                firstRequest = r;
                Check(r.Headers.Authorization?.Parameter == "old", "initial token");
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Unauthorized) { Content = firstBody });
            }
            Check(firstBody.Disposed && r != firstRequest && r.Headers.Authorization?.Parameter == "new", "fresh request/token after disposal");
            return Task.FromResult(Ok("[]"));
        });
        using var http = new HttpClient(handler);
        var sdk = Client(http, tokens);
        await sdk.Users.GetUsersAsync("demo");
        Check(calls == 2 && tokens.Invalidated.SequenceEqual(["old"]) && http.DefaultRequestHeaders.Authorization is null, "one recovery");

        foreach (var method in new[] { HttpMethod.Post, HttpMethod.Put, HttpMethod.Patch, HttpMethod.Delete, HttpMethod.Get, HttpMethod.Head })
        {
            calls = 0; tokens = new(); sdk = Client(http, tokens);
            using var body = new StringContent("one-shot");
            handler.Action = (_, _) => { calls++; return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Unauthorized)); };
            await Expect<KeycloakAdminException>(() => sdk.SendAsync(Replay, method, "/admin/serverinfo", content: body));
            Check(calls == 1 && tokens.Invalidated.Count == 1, "content and writes are not replayed");
        }
        foreach (var method in new[] { HttpMethod.Post, HttpMethod.Put, HttpMethod.Patch, HttpMethod.Delete })
        {
            calls = 0; tokens = new(); sdk = Client(http, tokens);
            await Expect<KeycloakAdminException>(() => sdk.SendAsync(Replay, method, "/admin/serverinfo"));
            Check(calls == 1 && tokens.Invalidated.Count == 1, "bodyless writes are not replayed either");
        }
        using (var cancellation = new CancellationTokenSource())
        {
            calls = 0; tokens = new() { OnInvalidate = cancellation.Cancel }; sdk = Client(http, tokens);
            await Expect<OperationCanceledException>(() => sdk.Users.GetUsersAsync("demo", cancellationToken: cancellation.Token));
            Check(calls == 1, "cancellation between attempts prevents replay");
        }
        calls = 0; tokens = new(); sdk = Client(http, tokens);
        var twice = await Expect<KeycloakAdminException>(() => sdk.Users.GetUsersAsync("demo"));
        Check(calls == 2 && tokens.Invalidated.SequenceEqual(["old", "new"]) && twice.Operation == "Users.GetUsersAsync", "final 401 invalidates and stops");

        foreach (var provider in new IAccessTokenProvider?[] { null, new StaticAccessTokenProvider("static") })
        {
            calls = 0; sdk = Client(http, provider);
            await Expect<KeycloakAdminException>(() => sdk.Users.GetUsersAsync("demo"));
            Check(calls == 1, "nonrefreshable provider");
        }
        calls = 0; tokens = new(); sdk = new(http, Server, tokens);
        await Expect<KeycloakAdminException>(() => sdk.Users.GetUsersAsync("demo"));
        Check(calls == 1 && tokens.Invalidated.Count == 0, "default recovery disabled");

        foreach (string path in new[] { "/admin/serverinfo", "/realms/master/protocol/openid-connect/token" })
        {
            calls = 0; tokens = new(); sdk = Client(http, tokens);
            var error = await Expect<KeycloakAdminException>(() => sdk.SendAsync(HttpMethod.Get, path));
            Check(calls == 1 && error.Operation is null, "raw requests require replay opt in");
            Check(tokens.Invalidated.Count == (path.StartsWith("/admin/") ? 1 : 0), "token path excluded");
        }
        calls = 0; tokens = new(); sdk = Client(http, tokens);
        await Expect<KeycloakAdminException>(() => sdk.SendAsync(new KeycloakRequestOptions(), HttpMethod.Get, "/admin/serverinfo"));
        Check(calls == 1, "raw option false");
        calls = 0;
        await Expect<KeycloakAdminException>(() => sdk.SendAsync(Replay, HttpMethod.Get, "/realms/master/protocol/openid-connect/token"));
        Check(calls == 1, "token endpoint cannot replay even with explicit permission");

        handler.Action = (_, _) => { calls++; return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Forbidden)); };
        calls = 0; tokens = new(); sdk = Client(http, tokens);
        await Expect<KeycloakAdminException>(() => sdk.Users.GetUsersAsync("demo"));
        Check(calls == 1 && tokens.Invalidated.Count == 0, "403 never refreshes");

        var enumerationCount = 0;
        IEnumerable<KeyValuePair<string, string?>> Query()
        {
            Check(++enumerationCount == 1, "query evaluated once");
            yield return new("search", "x +&");
        }
        calls = 0;
        handler.Action = (r, _) => { Check(r.RequestUri!.Query == "?search=x%20%2B%26", "stable query"); return Task.FromResult(++calls == 1 ? new HttpResponseMessage(HttpStatusCode.Unauthorized) : Ok("[]")); };
        await sdk.SendAsync(Replay, HttpMethod.Head, "/admin/serverinfo", Query());
        calls = 0;
        handler.Action = (_, _) => Task.FromResult(++calls == 1 ? new HttpResponseMessage(HttpStatusCode.Unauthorized) : Ok("[]"));
        var json = await sdk.SendJsonAsync(Replay, HttpMethod.Get, "/admin/serverinfo", query: null, content: null, responseType: KeycloakJsonContext.Default.JsonElement);
        Check(json.HasBody, "raw JSON replay overload");
    }

    public static async Task StreamAsync()
    {
        int calls = 0;
        using var firstBody = new UnreadableContent();
        using var http = new HttpClient(new Handler((_, _) => Task.FromResult(++calls == 1
            ? new HttpResponseMessage(HttpStatusCode.Unauthorized) { Content = firstBody } : Ok("download"))));
        var sdk = Client(http, new Tokens());
        using (var response = await sdk.OpenStreamAsync(Replay, HttpMethod.Get, "/admin/serverinfo"))
            Check(calls == 2 && firstBody.Disposed && response.Content.ReadByte() == 'd', "stream recovery before delivery");
        Check(calls == 2, "stream delivery does not replay reads");
        calls = 0;
        await Expect<KeycloakAdminException>(() => sdk.OpenStreamAsync(HttpMethod.Get, "/admin/serverinfo"));
        Check(calls == 1, "raw stream does not implicitly replay");
    }

    public static async Task ConcurrencyAsync()
    {
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        int calls = 0;
        using var http = new HttpClient(new Handler(async (_, ct) => { Interlocked.Increment(ref calls); await release.Task.WaitAsync(ct); return Token("fresh"); }));
        using var provider = Provider(http);
        using var cancelled = new CancellationTokenSource();
        var first = provider.GetAccessTokenAsync(cancelled.Token).AsTask();
        var others = Enumerable.Range(0, 30).Select(_ => provider.GetAccessTokenAsync().AsTask()).ToArray();
        cancelled.Cancel();
        await Expect<OperationCanceledException>(() => first);
        release.SetResult();
        Check((await Task.WhenAll(others)).All(t => t == "fresh") && calls == 1, "shared acquisition survives waiter cancellation");
        await provider.InvalidateAsync("old");
        Check(await provider.GetAccessTokenAsync() == "fresh" && calls == 1, "late rejection preserves new cache");
        await provider.InvalidateAsync("fresh");
        await provider.GetAccessTokenAsync();
        Check(calls == 2, "matching invalidation refreshes");
        await Expect<OperationCanceledException>(async () => await provider.InvalidateAsync("fresh", cancelled.Token));

        // Exercise transport + real provider together: all requests have sent the old token before any 401 returns.
        var allOldSent = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        int tokenCalls = 0, oldCalls = 0, newCalls = 0;
        using var waveHttp = new HttpClient(new Handler(async (r, ct) =>
        {
            if (r.Method == HttpMethod.Post) return Token(Interlocked.Increment(ref tokenCalls) == 1 ? "old" : "new");
            if (r.Headers.Authorization!.Parameter == "old")
            {
                if (Interlocked.Increment(ref oldCalls) == 16) allOldSent.SetResult();
                await allOldSent.Task.WaitAsync(ct);
                return new(HttpStatusCode.Unauthorized);
            }
            Interlocked.Increment(ref newCalls);
            return Ok("[]");
        }));
        using var waveProvider = Provider(waveHttp);
        var waveClient = Client(waveHttp, waveProvider);
        await Task.WhenAll(Enumerable.Range(0, 16).Select(_ => waveClient.Users.GetUsersAsync("demo")));
        Check(tokenCalls == 2 && oldCalls == 16 && newCalls == 16, "one refresh for an actual concurrent 401 wave");
    }

    public static async Task FailuresAsync()
    {
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var clock = new Clock();
        int calls = 0;
        using var body = new UnreadableContent();
        using var handler = new Handler(async (_, ct) => { Interlocked.Increment(ref calls); await release.Task.WaitAsync(ct); return new(HttpStatusCode.Unauthorized) { Content = body }; });
        using var http = new HttpClient(handler);
        using var provider = Provider(http, clock);
        var wave = Enumerable.Range(0, 30).Select(_ => provider.GetAccessTokenAsync().AsTask()).ToArray();
        release.SetResult();
        foreach (var task in wave)
        {
            var error = await Expect<KeycloakAdminException>(() => task);
            Check(error.Stage == KeycloakFailureStage.TokenEndpoint && error.Operation is null && error.Method == "TOKEN POST", "token failure stage");
        }
        await Expect<KeycloakAdminException>(async () => await provider.GetAccessTokenAsync());
        Check(calls == 1 && body.Disposed && !body.Read, "failure shared through cooldown without body reads");
        clock.Now += TimeSpan.FromSeconds(2);
        handler.Action = (_, _) => Task.FromResult(Token("recovered"));
        Check(await provider.GetAccessTokenAsync() == "recovered", "cooldown permits recovery");

        handler.Action = async (_, ct) => { await Task.Delay(Timeout.InfiniteTimeSpan, ct); return Ok(""); };
        using (var timeoutProvider = Provider(http, options: new() { RequestTimeout = TimeSpan.FromMilliseconds(50), FailureCooldown = TimeSpan.Zero }))
            await Expect<OperationCanceledException>(async () => await timeoutProvider.GetAccessTokenAsync());

        provider.Dispose(); provider.Dispose();
        await Expect<ObjectDisposedException>(async () => await provider.GetAccessTokenAsync());
        await Expect<ObjectDisposedException>(async () => await provider.InvalidateAsync("old"));

        foreach (var options in new[] { new ClientCredentialsTokenProviderOptions { RequestTimeout = TimeSpan.Zero },
            new() { RequestTimeout = TimeSpan.FromDays(100) }, new() { FailureCooldown = TimeSpan.FromSeconds(-1) }, new() { FailureCooldown = TimeSpan.MaxValue } })
            await Expect<ArgumentOutOfRangeException>(() => { using var p = Provider(http, options: options); return Task.CompletedTask; });
        await Expect<ArgumentNullException>(() => { using var p = new ClientCredentialsTokenProvider(http, Server, "master", "id", _ => ValueTask.FromResult("secret"), null, null!); return Task.CompletedTask; });
        await Expect<ArgumentNullException>(() => { _ = new KeycloakAdminClient(http, Server, null, null!); return Task.CompletedTask; });
        var sdk = Client(http, new Tokens());
        await Expect<ArgumentNullException>(() => sdk.SendAsync(null!, HttpMethod.Get, "/admin/serverinfo"));
        await Expect<ArgumentNullException>(() => sdk.OpenStreamAsync(null!, HttpMethod.Get, "/admin/serverinfo"));
        await Expect<ArgumentNullException>(() => sdk.SendJsonAsync(null!, HttpMethod.Get, "/admin/serverinfo", null, null, KeycloakJsonContext.Default.JsonElement));
    }

    private static KeycloakAdminClient Client(HttpClient http, IAccessTokenProvider? tokens) => new(http, Server, tokens, new() { EnableUnauthorizedRecovery = true });
    private static ClientCredentialsTokenProvider Provider(HttpClient http, TimeProvider? clock = null, ClientCredentialsTokenProviderOptions? options = null)
        => new(http, Server, "master", "client", _ => ValueTask.FromResult("secret"), clock, options ?? new());
    private static HttpResponseMessage Ok(string body) => new(HttpStatusCode.OK) { Content = new StringContent(body) };
    private static HttpResponseMessage Token(string token) => Ok("{\"access_token\":\"" + token + "\",\"expires_in\":60,\"token_type\":\"Bearer\"}");
    private static void Check(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
    private static async Task<T> Expect<T>(Func<Task> action) where T : Exception
    {
        try { await action(); } catch (T error) { return error; }
        throw new InvalidOperationException("Expected " + typeof(T).Name);
    }
    private sealed class Clock : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow() => Now;
    }
    private sealed class Tokens : IRefreshableAccessTokenProvider
    {
        public Action? OnInvalidate { get; init; }
        public List<string> Invalidated { get; } = [];
        public ValueTask<string> GetAccessTokenAsync(CancellationToken cancellationToken = default) => ValueTask.FromResult(Invalidated.Count == 0 ? "old" : "new");
        public ValueTask InvalidateAsync(string rejectedToken, CancellationToken cancellationToken = default) { Invalidated.Add(rejectedToken); OnInvalidate?.Invoke(); return ValueTask.CompletedTask; }
    }
    private sealed class Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> action) : HttpMessageHandler
    {
        public Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> Action { get; set; } = action;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => Action(request, cancellationToken);
    }
    private sealed class UnreadableContent : HttpContent
    {
        public bool Read { get; private set; }
        public bool Disposed { get; private set; }
        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) { Read = true; throw new InvalidOperationException("sensitive body must not be read"); }
        protected override bool TryComputeLength(out long length) { length = 0; return false; }
        protected override void Dispose(bool disposing) { Disposed = true; base.Dispose(disposing); }
    }
}
