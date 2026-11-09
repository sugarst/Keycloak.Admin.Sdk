using System.Net;
using System.Net.Sockets;
using System.Text;
using Keycloak.Admin.Sdk;
using Microsoft.VisualStudio.TestTools.UnitTesting;

[TestClass, DoNotParallelize]
public sealed class CancellationTests
{
    [TestMethod]
    public async Task LiveContextCancelsInFlightRequestAndAllowsIndependentCleanup()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var cancellation = new CancellationTokenSource();
        using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        int calls = 0;
        using var handler = new Handler(async ct =>
        {
            if (++calls == 1)
            {
                started.SetResult();
                await Task.Delay(Timeout.InfiniteTimeSpan, ct);
            }
            return new(HttpStatusCode.OK) { Content = new StringContent("[]") };
        });
        using var http = new HttpClient(handler);
        using var directory = new CurrentDirectory(ScriptHost.RepositoryRoot());
        var context = new LiveContext(new KeycloakAdminClient(http, new Uri("https://keycloak.invalid/")), "test", new LiveLedger(), cancellation.Token)
        { RealmId = "persisted-realm-id" };

        var request = context.Get("users");
        await started.Task.WaitAsync(timeout.Token);
        cancellation.Cancel();
        await AssertCancelledAsync(request, cancellation.Token, timeout.Token);

        var cleanupContext = context.WithCancellation(cleanup.Token);
        Assert.AreEqual(context.RealmId, cleanupContext.RealmId);
        Assert.AreEqual(HttpStatusCode.OK, (await cleanupContext.Get("users")).Response.StatusCode);
        Assert.AreEqual(2, calls);
    }

    [TestMethod]
    [DataRow("LDAP")]
    [DataRow("PG")]
    public async Task ProtocolFixtureCancellationInterruptsHandshakeAndClosesSocket(string protocol)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var cancellation = new CancellationTokenSource();
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        string prefix = "KC_TEST_" + protocol + "_";
        using var environment = new Variables(new()
        {
            [prefix + "HOST"] = "127.0.0.1",
            [prefix + "PORT"] = ((IPEndPoint)listener.LocalEndpoint).Port.ToString(System.Globalization.CultureInfo.InvariantCulture),
            [prefix + "PASSWORD"] = "test-password"
        });
        Task connection = protocol == "LDAP" ? LdapFixture.Connect(cancellation.Token) : PostgresFixture.Connect(cancellation.Token);
        using var accepted = await listener.AcceptTcpClientAsync(timeout.Token);
        var stream = accepted.GetStream();
        var buffer = new byte[4096];
        Assert.IsGreaterThan(0, await stream.ReadAsync(buffer, timeout.Token));
        cancellation.Cancel();
        await AssertCancelledAsync(connection, cancellation.Token, timeout.Token);
        await AssertClosedAsync(stream, timeout.Token);
    }

    [TestMethod]
    [DataRow(true)]
    [DataRow(false)]
    public async Task LdapCleanupUsesIndependentTokenAndOnlyIgnoresMissingWhenRequested(bool ignoreMissing)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var cancellation = new CancellationTokenSource();
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var environment = new Variables(new()
        {
            ["KC_TEST_LDAP_HOST"] = "127.0.0.1",
            ["KC_TEST_LDAP_PORT"] = ((IPEndPoint)listener.LocalEndpoint).Port.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["KC_TEST_LDAP_PASSWORD"] = "test-password"
        });
        var connection = LdapFixture.Connect(cancellation.Token);
        using var accepted = await listener.AcceptTcpClientAsync(timeout.Token);
        var stream = accepted.GetStream();
        await ReadLdapFrameAsync(stream, timeout.Token);
        await stream.WriteAsync((byte[])[0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00], timeout.Token);
        await using var ldap = await connection.WaitAsync(timeout.Token);
        cancellation.Cancel();
        var deletion = ldap.Delete("cn=missing", timeout.Token, ignoreMissing);
        await ReadLdapFrameAsync(stream, timeout.Token);
        await stream.WriteAsync((byte[])[0x30, 0x0c, 0x02, 0x01, 0x02, 0x6b, 0x07, 0x0a, 0x01, 0x20, 0x04, 0x00, 0x04, 0x00], timeout.Token);
        if (ignoreMissing) await deletion.WaitAsync(timeout.Token);
        else await Assert.ThrowsAsync<IOException>(() => deletion.WaitAsync(timeout.Token));
    }

    [TestMethod]
    public async Task CallbackCancellationClosesIdleSmtpAndIncompleteHttpConnections()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var cancellation = new CancellationTokenSource();
        var fixture = new CallbackFixture(cancellation.Token);
        try
        {
            using var smtp = new TcpClient();
            await smtp.ConnectAsync(IPAddress.Loopback, fixture.SmtpPort, timeout.Token);
            using var reader = new StreamReader(smtp.GetStream(), Encoding.UTF8, leaveOpen: true);
            Assert.AreEqual("220 fixture ESMTP", await reader.ReadLineAsync(timeout.Token));
            using var web = new TcpClient();
            await web.ConnectAsync(IPAddress.Loopback, new Uri(fixture.WebUrl).Port, timeout.Token);
            await web.GetStream().WriteAsync(Encoding.ASCII.GetBytes("POST /metadata HTTP/1.1\r\nContent-Length: 4\r\n\r\nx"), timeout.Token);
            cancellation.Cancel();
            await AssertClosedAsync(smtp.GetStream(), timeout.Token);
            await AssertClosedAsync(web.GetStream(), timeout.Token);
        }
        finally
        {
            await fixture.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(3), timeout.Token);
        }
    }

    [TestMethod]
    [DataRow(true)]
    [DataRow(false)]
    public async Task ScriptCancellationStopsChildWithRedirectedOutput(bool capture)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var cancellation = new CancellationTokenSource();
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var environment = new Dictionary<string, string?>
        {
            ["KC_TEST_URL"] = "http://127.0.0.1:" + ((IPEndPoint)listener.LocalEndpoint).Port + "/",
            ["KC_TEST_PASSWORD"] = "test-password",
            ["KC_TEST_FULL_ADMIN"] = null
        };
        var process = ScriptHost.RunAsync(ScriptHost.RepositoryRoot(), "dotnet", [typeof(LiveContext).Assembly.Location], cancellation.Token, capture, environment);
        using var accepted = await listener.AcceptTcpClientAsync(timeout.Token);
        var stream = accepted.GetStream();
        var buffer = new byte[8192];
        Assert.IsGreaterThan(0, await stream.ReadAsync(buffer, timeout.Token));
        cancellation.Cancel();
        await AssertCancelledAsync(process, cancellation.Token, timeout.Token);
        await AssertClosedAsync(stream, timeout.Token);
    }

    [TestMethod]
    [DataRow(true)]
    [DataRow(false)]
    public async Task ScriptOutputCompletesNormallyWithCancellationEnabled(bool capture)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var result = await ScriptHost.RunCheckedAsync(ScriptHost.RepositoryRoot(), "dotnet", [typeof(LiveContext).Assembly.Location, "--help"], timeout.Token, capture);
        Assert.AreEqual(0, result.ExitCode);
        if (capture) StringAssert.Contains(result.StandardOutput, "dotnet run --project");
    }

    private static async Task AssertCancelledAsync(Task task, CancellationToken expected, CancellationToken timeout)
    {
        var error = await Assert.ThrowsAsync<OperationCanceledException>(() => task.WaitAsync(TimeSpan.FromSeconds(3), timeout));
        Assert.AreEqual(expected, error.CancellationToken);
    }

    private static async Task ReadLdapFrameAsync(NetworkStream stream, CancellationToken cancellationToken)
    {
        var header = new byte[2];
        await stream.ReadExactlyAsync(header, cancellationToken);
        Assert.IsTrue(header[1] < 128, "These small test requests use a single-byte BER length.");
        await stream.ReadExactlyAsync(new byte[header[1]], cancellationToken);
    }

    private static async Task AssertClosedAsync(NetworkStream stream, CancellationToken cancellationToken)
    {
        try
        {
            var buffer = new byte[8192];
            while (await stream.ReadAsync(buffer, cancellationToken) > 0) { }
        }
        catch (IOException error) when (error.InnerException is SocketException { SocketErrorCode: SocketError.ConnectionReset or SocketError.ConnectionAborted })
        {
            // Closing with unread request bytes can reset the connection instead of sending EOF.
        }
    }

    private sealed class Handler(Func<CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => send(cancellationToken);
    }

    private sealed class CurrentDirectory : IDisposable
    {
        private readonly string previous = Directory.GetCurrentDirectory();
        public CurrentDirectory(string path) => Directory.SetCurrentDirectory(path);
        public void Dispose() => Directory.SetCurrentDirectory(previous);
    }

    private sealed class Variables : IDisposable
    {
        private readonly Dictionary<string, string?> previous;
        public Variables(Dictionary<string, string?> values)
        {
            previous = values.Keys.ToDictionary(key => key, Environment.GetEnvironmentVariable);
            foreach (var (key, value) in values) Environment.SetEnvironmentVariable(key, value);
        }
        public void Dispose()
        {
            foreach (var (key, value) in previous) Environment.SetEnvironmentVariable(key, value);
        }
    }
}
