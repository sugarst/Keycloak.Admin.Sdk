using System.Net;
using System.Text;
using System.Threading.Channels;

// Test-only loopback receiver inside the acceptance server's isolated network namespace.
internal sealed class ProtocolCallbackReceiver : IAsyncDisposable
{
    private readonly HttpListener listener = new();
    private readonly CancellationTokenSource stop = new();
    private readonly Channel<Message> messages = Channel.CreateBounded<Message>(32);
    private readonly Task worker;
    internal ProtocolCallbackReceiver()
    { listener.Prefixes.Add("http://127.0.0.1:18081/"); listener.Start(); worker = RunAsync(); }
    internal async Task<Message> NextAsync(string path, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(15));
        var message = await messages.Reader.ReadAsync(timeout.Token);
        if (message.Path != path) throw new InvalidDataException("Unexpected isolated callback path."); return message;
    }
    private async Task RunAsync()
    {
        try
        {
            while (!stop.IsCancellationRequested)
            {
                var context = await listener.GetContextAsync().WaitAsync(stop.Token);
                using var body = new MemoryStream(); var buffer = new byte[4096]; int length;
                while ((length = await context.Request.InputStream.ReadAsync(buffer, stop.Token)) != 0)
                { if (body.Length + length > 65536) throw new InvalidDataException("Test callback exceeded its bound."); body.Write(buffer, 0, length); }
                string path = context.Request.Url!.AbsolutePath;
                if (context.Request.HttpMethod != "POST") throw new InvalidDataException("Unexpected callback method.");
                var message = new Message(path, context.Request.Headers["Authorization"] ?? "", Encoding.UTF8.GetString(body.ToArray()));
                context.Response.StatusCode = path == "/authenticate" ? 201 : 204; context.Response.ContentLength64 = 0; context.Response.Close();
                await messages.Writer.WriteAsync(message, stop.Token);
            }
        }
        catch (Exception error) when (stop.IsCancellationRequested && error is OperationCanceledException or HttpListenerException or ObjectDisposedException) { }
        finally { messages.Writer.TryComplete(); }
    }
    public async ValueTask DisposeAsync() { stop.Cancel(); listener.Close(); try { await worker; } finally { stop.Dispose(); } }
    internal sealed class Message(string path, string authorization, string body)
    { internal string Path { get; } = path; internal string Authorization { get; } = authorization; internal string Body { get; } = body; }
}
