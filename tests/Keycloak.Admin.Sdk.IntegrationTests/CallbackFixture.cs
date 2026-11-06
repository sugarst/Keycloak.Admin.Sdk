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
    private readonly CancellationTokenSource stopping;
    private readonly TcpListener smtp = new(IPAddress.Any, 0);
    private readonly TcpListener web = new(IPAddress.Any, 0);
    private readonly ConcurrentBag<Task> connections = [];
    private readonly Task smtpLoop;
    private readonly Task webLoop;
    private int mails;
    private int metadataRequests;
    public ConcurrentQueue<string> Messages { get; } = new();
    public ConcurrentQueue<(string Method, string Path, string Body)> Requests { get; } = new();
    public Func<string, string, string, (int Status, string Type, string Body)>? Responder { get; set; }
    public string Host { get; } = Environment.GetEnvironmentVariable("KC_TEST_CALLBACK_HOST") ?? "host.docker.internal";
    public int SmtpPort => ((IPEndPoint)smtp.LocalEndpoint).Port;
    public int MailCount => Volatile.Read(ref mails);
    public int MetadataRequests => Volatile.Read(ref metadataRequests);
    public string MetadataUrl => $"http://{Host}:{((IPEndPoint)web.LocalEndpoint).Port}/metadata";
    public string WebUrl => $"http://{Host}:{((IPEndPoint)web.LocalEndpoint).Port}";

    public CallbackFixture(CancellationToken cancellationToken = default)
    {
        stopping = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
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
                connections.Add(ServeAsync(client, serve));
            }
        }
        catch (OperationCanceledException) when (stopping.IsCancellationRequested) { }
        catch (SocketException) when (stopping.IsCancellationRequested) { }
    }

    private async Task ServeAsync(TcpClient client, Func<TcpClient, Task> serve)
    {
        using (client)
        using (stopping.Token.Register(client.Dispose))
        {
            try { await serve(client); }
            catch (Exception error) when (stopping.IsCancellationRequested && error is OperationCanceledException or IOException or SocketException or ObjectDisposedException) { }
        }
    }

    private async Task SmtpAsync(TcpClient client)
    {
        using (client)
        {
            await using var stream = client.GetStream();
            using var input = new StreamReader(stream, Encoding.UTF8, leaveOpen: true);
            await using var output = new StreamWriter(stream, new UTF8Encoding(false), leaveOpen: true) { NewLine = "\r\n", AutoFlush = true };
            await output.WriteLineAsync("220 fixture ESMTP".AsMemory(), stopping.Token);
            bool data = false;
            var message = new StringBuilder();
            while (await input.ReadLineAsync(stopping.Token) is { } line)
            {
                if (data)
                {
                    if (line == ".") { data = false; Messages.Enqueue(message.ToString()); message.Clear(); Interlocked.Increment(ref mails); await output.WriteLineAsync("250 accepted".AsMemory(), stopping.Token); }
                    else message.AppendLine(line.StartsWith("..", StringComparison.Ordinal) ? line[1..] : line);
                    continue;
                }
                string command = line.Split(' ', 2)[0].ToUpperInvariant();
                if (command == "DATA") { data = true; await output.WriteLineAsync("354 end with dot".AsMemory(), stopping.Token); }
                else if (command == "QUIT") { await output.WriteLineAsync("221 closing".AsMemory(), stopping.Token); break; }
                else await output.WriteLineAsync("250 OK".AsMemory(), stopping.Token);
            }
        }
    }

    private async Task MetadataAsync(TcpClient client)
    {
        using (client)
        {
            await using var stream = client.GetStream();
            using var input = new StreamReader(stream, Encoding.ASCII, leaveOpen: true);
            if (await input.ReadLineAsync(stopping.Token) is not { } request) throw new IOException("Missing HTTP request.");
            string[] parts = request.Split(' ');
            int length = 0;
            while (await input.ReadLineAsync(stopping.Token) is { Length: > 0 } header)
                if (header.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase)) length = int.Parse(header[15..].Trim(), System.Globalization.CultureInfo.InvariantCulture);
            var chars = new char[length]; int offset = 0;
            while (offset < chars.Length) { int read = await input.ReadAsync(chars.AsMemory(offset), stopping.Token); if (read == 0) throw new IOException("Truncated HTTP entity."); offset += read; }
            string entity = new(chars);
            Requests.Enqueue((parts[0], parts[1], entity));
            var reply = Responder?.Invoke(parts[0], parts[1], entity) ?? (parts[0] == "GET" && parts[1] == "/metadata" ? (200, "application/samlmetadata+xml", Metadata) : (404, "text/plain", "Not found"));
            if (parts[1] == "/metadata") Interlocked.Increment(ref metadataRequests);
            byte[] body = Encoding.UTF8.GetBytes(reply.Item3);
            byte[] headers = Encoding.ASCII.GetBytes($"HTTP/1.1 {reply.Item1} OK\r\nContent-Type: {reply.Item2}\r\nContent-Length: {body.Length}\r\nConnection: close\r\n\r\n");
            await stream.WriteAsync(headers, stopping.Token);
            await stream.WriteAsync(body, stopping.Token);
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
