using System.Net;
using System.Text;
using Keycloak.Admin.Sdk;

public static class RuntimeContracts
{
    public static Task UriAndMetadataAsync()
    {
        foreach (var uri in new[] { new Uri("relative", UriKind.Relative), new Uri("ftp://host/"), new Uri("https://host/?x=y"), new Uri("https://host/#fragment"), new Uri("https://user:password@host/") })
            Throws<ArgumentException>(() => AdminUri.Base(uri));
        Throws<ArgumentNullException>(() => AdminUri.Base(null!));
        Check(AdminUri.Base(new Uri("http://host/path")).AbsoluteUri == "http://host/path/", "HTTP base");
        Check(AdminUri.Base(new Uri("https://host/path/")).AbsoluteUri == "https://host/path/", "HTTPS base");
        foreach (string segment in new[] { ".", "..", "", " ", null! }) Throws<ArgumentException>(() => AdminUri.Path("/{0}", [segment]));
        Check(AdminUri.Path("/{0}", ["x/y"]) == "/x%2Fy", "segment escape");
        Throws<ArgumentException>(() => AdminUri.QueryValue(new object()));
        Check(AdminUri.QueryValue(true) == "true" && AdminUri.QueryValue(false) == "false", "boolean wire values");
        Check(AdminUri.QueryValue(1.25m) == "1.25" && AdminUri.QueryValue(null) is null, "invariant number and absence");
        Throws<ArgumentException>(() => AdminUri.Combine(new Uri("https://host/"), "/untrusted", []));
        Check(AdminUri.Combine(new Uri("https://host/"), "/realms/master/token", []).AbsolutePath == "/realms/master/token", "token-relative path");
        Throws<NotSupportedException>(() => AdminJson.TypeInfo<UnregisteredContract>());
        return Task.CompletedTask;
    }

    public static async Task ConstructorAndTransportAsync()
    {
        using var handler = new Handler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("0") }));
        using var http = new HttpClient(handler);
        var server = new Uri("https://keycloak.invalid/");
        Throws<ArgumentNullException>(() => new KeycloakAdminClient(null!, server));
        Throws<ArgumentNullException>(() => new ClientCredentialsTokenProvider(null!, server, "master", "client", _ => ValueTask.FromResult("secret")));
        Throws<ArgumentNullException>(() => new ClientCredentialsTokenProvider(http, server, "master", "client", null!));
        Throws<ArgumentException>(() => new ClientCredentialsTokenProvider(http, server, "master", "", _ => ValueTask.FromResult("secret")));
        Throws<ArgumentException>(() => new StaticAccessTokenProvider(" "));
        var sdk = new KeycloakAdminClient(http, server);
        await sdk.SendAsync(HttpMethod.Get, "/admin/serverinfo");
        await ExpectAsync<ArgumentNullException>(() => sdk.SendJsonAsync<int>(HttpMethod.Get, "/admin/serverinfo", null, null, null!));
        using var cancellation = new CancellationTokenSource(); cancellation.Cancel();
        var content = new Payload("caller content");
        await ExpectAsync<OperationCanceledException>(() => sdk.SendAsync(HttpMethod.Post, "/admin/serverinfo", content: content, cancellationToken: cancellation.Token));
        Check(content.Disposed, "pre-cancel disposes request content");
        await ExpectAsync<OperationCanceledException>(async () => await new StaticAccessTokenProvider("token").GetAccessTokenAsync(cancellation.Token));
    }

    public static async Task TokenFailuresAndRecoveryAsync()
    {
        foreach (string json in new[] { "null", "{}", "{\"access_token\":\"\",\"expires_in\":60,\"token_type\":\"Bearer\"}", "{\"access_token\":\"t\",\"expires_in\":0,\"token_type\":\"Bearer\"}", "{\"access_token\":\"t\",\"expires_in\":-1,\"token_type\":\"Bearer\"}", "{\"access_token\":\"t\",\"expires_in\":60,\"token_type\":\"Basic\"}" })
        {
            using var handler = new Handler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(json) }));
            using var http = new HttpClient(handler);
            using var provider = Provider(http);
            await ExpectAsync<KeycloakResponseFormatException>(async () => await provider.GetAccessTokenAsync());
            handler.Action = (_, _) => Task.FromResult(Token("bEaReR", long.MaxValue));
            Check(await provider.GetAccessTokenAsync() == "recovered", "invalid token does not poison cache or hold semaphore");
            Check(await provider.GetAccessTokenAsync() == "recovered" && handler.Count == 2, "successful token cached; oversized lifetime bounded");
        }
        using var failedResponse = new Payload("do-not-log-secret");
        using var failures = new Handler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.Unauthorized) { Content = failedResponse }));
        using var failedHttp = new HttpClient(failures);
        using var failedProvider = Provider(failedHttp);
        var error = await ExpectAsync<KeycloakAdminException>(async () => await failedProvider.GetAccessTokenAsync());
        Check(error.StatusCode == HttpStatusCode.Unauthorized && error.Method == "TOKEN POST" && !error.ToString().Contains("do-not-log-secret", StringComparison.Ordinal) && failedResponse.Disposed, "token HTTP error redacted and disposed");
        failures.Action = (_, _) => Task.FromResult(Token("Bearer", 1));
        Check(await failedProvider.GetAccessTokenAsync() == "recovered", "token HTTP error releases semaphore");
        using var cancellation = new CancellationTokenSource(); cancellation.Cancel();
        await ExpectAsync<OperationCanceledException>(async () => await failedProvider.GetAccessTokenAsync(cancellation.Token));
    }

    public static async Task StreamFailuresAndOwnershipAsync()
    {
        using var handler = new Handler((_, _) =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new Payload("stream") };
            response.Headers.Location = new Uri("/stream", UriKind.Relative);
            return Task.FromResult(response);
        });
        using var http = new HttpClient(handler);
        var sdk = new KeycloakAdminClient(http, new Uri("https://keycloak.invalid/"), new StaticAccessTokenProvider("stream-token"));
        using (var stream = await sdk.OpenStreamAsync(HttpMethod.Get, "/admin/serverinfo", [new("name", "value")]))
            Check(stream.StatusCode == HttpStatusCode.OK && stream.Location?.OriginalString == "/stream" && stream.Content.ReadByte() == (byte)'s', "stream headers and content preserved");
        using var failure = new Payload("secret");
        handler.Action = (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.Forbidden) { Content = failure });
        await ExpectAsync<KeycloakAdminException>(() => sdk.OpenStreamAsync(HttpMethod.Get, "/admin/serverinfo"));
        Check(failure.Disposed, "failed streaming response disposed");
        using var broken = new BrokenStreamContent();
        handler.Action = (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = broken });
        await ExpectAsync<IOException>(() => sdk.OpenStreamAsync(HttpMethod.Get, "/admin/serverinfo"));
        Check(broken.Disposed, "stream creation failure disposes response");
        using var cancellation = new CancellationTokenSource(); cancellation.Cancel();
        await ExpectAsync<OperationCanceledException>(() => sdk.OpenStreamAsync(HttpMethod.Get, "/admin/serverinfo", cancellationToken: cancellation.Token));
    }

    public static async Task RunAsync()
    {
        await UriAndMetadataAsync(); await ConstructorAndTransportAsync();
        await TokenFailuresAndRecoveryAsync(); await StreamFailuresAndOwnershipAsync();
    }
    private static ClientCredentialsTokenProvider Provider(HttpClient http) => new(http, new Uri("https://keycloak.invalid/"), "master", "client", _ => ValueTask.FromResult("secret"), null, new() { FailureCooldown = TimeSpan.Zero });
    private static HttpResponseMessage Token(string type, long expires) => new(HttpStatusCode.OK) { Content = new StringContent("{\"access_token\":\"recovered\",\"expires_in\":" + expires.ToString(System.Globalization.CultureInfo.InvariantCulture) + ",\"token_type\":\"" + type + "\"}") };
    private static void Check(bool value, string message) { if (!value) throw new InvalidOperationException(message); }
    private static void Throws<T>(Action action) where T : Exception
    {
        try { action(); } catch (T) { return; }
        throw new InvalidOperationException("Expected " + typeof(T).Name);
    }
    private static async Task<T> ExpectAsync<T>(Func<Task> action) where T : Exception
    {
        try { await action(); } catch (T error) { return error; }
        throw new InvalidOperationException("Expected " + typeof(T).Name);
    }
    private sealed class UnregisteredContract;
    private sealed class Payload(string value) : ByteArrayContent(Encoding.UTF8.GetBytes(value))
    {
        public bool Disposed { get; private set; }
        protected override void Dispose(bool disposing) { Disposed = true; base.Dispose(disposing); }
    }
    private sealed class BrokenStreamContent : HttpContent
    {
        public bool Disposed { get; private set; }
        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) => throw new IOException("cannot read stream");
        protected override Task<Stream> CreateContentReadStreamAsync() => throw new IOException("cannot create stream");
        protected override bool TryComputeLength(out long length) { length = 0; return false; }
        protected override void Dispose(bool disposing) { Disposed = true; base.Dispose(disposing); }
    }
    private sealed class Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> action) : HttpMessageHandler
    {
        public Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> Action { get; set; } = action;
        public int Count { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) { Count++; return Action(request, cancellationToken); }
    }
}
