using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;

// .NET-only metadata/SMTP fixtures. No external mail account or identity provider is used.
internal sealed class CallbackFixture : IAsyncDisposable
{
    public const string Metadata = """
        <EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.invalid/entity">
          <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.invalid/sso"/>
          </IDPSSODescriptor>
        </EntityDescriptor>
        """;
    private readonly CancellationTokenSource stopping = new();
    private readonly TcpListener smtp = new(IPAddress.Any, 0);
    private readonly TcpListener web = new(IPAddress.Any, 0);
    private readonly ConcurrentBag<Task> connections = [];
    private readonly Task smtpLoop;
    private readonly Task webLoop;
    private int mails;
    private int metadataRequests;
    public string Host { get; } = Environment.GetEnvironmentVariable("KC_TEST_CALLBACK_HOST") ?? "host.docker.internal";
    public int SmtpPort => ((IPEndPoint)smtp.LocalEndpoint).Port;
    public int MailCount => Volatile.Read(ref mails);
    public int MetadataRequests => Volatile.Read(ref metadataRequests);
    public string MetadataUrl => $"http://{Host}:{((IPEndPoint)web.LocalEndpoint).Port}/metadata";

    public CallbackFixture()
    {
        smtp.Start(); web.Start();
        smtpLoop = AcceptAsync(smtp, SmtpAsync);
        webLoop = AcceptAsync(web, MetadataAsync);
    }

    private async Task AcceptAsync(TcpListener listener, Func<TcpClient, Task> serve)
    {
        try
        {
            while (!stopping.IsCancellationRequested)
            {
                var client = await listener.AcceptTcpClientAsync(stopping.Token);
                connections.Add(serve(client));
            }
        }
        catch (OperationCanceledException) when (stopping.IsCancellationRequested) { }
        catch (SocketException) when (stopping.IsCancellationRequested) { }
    }

    private async Task SmtpAsync(TcpClient client)
    {
        using (client)
        {
            await using var stream = client.GetStream();
            using var input = new StreamReader(stream, Encoding.UTF8, leaveOpen: true);
            await using var output = new StreamWriter(stream, new UTF8Encoding(false), leaveOpen: true) { NewLine = "\r\n", AutoFlush = true };
            await output.WriteLineAsync("220 fixture ESMTP");
            bool data = false;
            while (await input.ReadLineAsync(stopping.Token) is { } line)
            {
                if (data)
                {
                    if (line == ".") { data = false; Interlocked.Increment(ref mails); await output.WriteLineAsync("250 accepted"); }
                    continue;
                }
                string command = line.Split(' ', 2)[0].ToUpperInvariant();
                if (command == "DATA") { data = true; await output.WriteLineAsync("354 end with dot"); }
                else if (command == "QUIT") { await output.WriteLineAsync("221 closing"); break; }
                else await output.WriteLineAsync("250 OK");
            }
        }
    }

    private async Task MetadataAsync(TcpClient client)
    {
        using (client)
        {
            await using var stream = client.GetStream();
            using var input = new StreamReader(stream, Encoding.ASCII, leaveOpen: true);
            if (await input.ReadLineAsync(stopping.Token) is not { } request || !request.StartsWith("GET /metadata ", StringComparison.Ordinal))
                throw new InvalidOperationException("Unexpected metadata fixture request.");
            while (await input.ReadLineAsync(stopping.Token) is { Length: > 0 }) { }
            byte[] body = Encoding.UTF8.GetBytes(Metadata);
            byte[] headers = Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nContent-Type: application/samlmetadata+xml\r\nContent-Length: {body.Length}\r\nConnection: close\r\n\r\n");
            await stream.WriteAsync(headers, stopping.Token);
            await stream.WriteAsync(body, stopping.Token);
            Interlocked.Increment(ref metadataRequests);
        }
    }

    public async ValueTask DisposeAsync()
    {
        await stopping.CancelAsync(); smtp.Stop(); web.Stop();
        await Task.WhenAll(smtpLoop, webLoop);
        try { await Task.WhenAll(connections); }
        catch (OperationCanceledException) when (stopping.IsCancellationRequested) { }
        stopping.Dispose();
    }
}
