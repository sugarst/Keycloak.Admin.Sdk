using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading.Channels;
using Keycloak.Admin.Sdk.Protocols;

// Single-process test journal. Production hosts must supply a durable shared business transaction through ISecurityEventInbox.
internal sealed class ProtocolSsfInbox(string path, string issuer) : ISecurityEventInbox
{
    private readonly SemaphoreSlim mutex = new(1);
    internal bool FailNext;
    internal JsonArray ReadEvents() => File.Exists(path) ? JsonNode.Parse(File.ReadAllText(path))!["events"]!.DeepClone().AsArray() : new();
    public async ValueTask ApplyOnceAsync(SecurityEventDelivery delivery, CancellationToken cancellationToken)
    {
        await mutex.WaitAsync(cancellationToken);
        try
        {
            var state = File.Exists(path) ? JsonNode.Parse(await File.ReadAllTextAsync(path, cancellationToken))!.AsObject() : new JsonObject { ["receipts"] = new JsonObject(), ["events"] = new JsonArray() };
            if (state["receipts"]!.AsObject().ContainsKey(delivery.ReceiptKey)) return;
            if (FailNext) { FailNext = false; throw new IOException("simulated receiver storage failure"); }
            foreach (var securityEvent in delivery.Token.Events.EnumerateObject())
            {
                JsonNode? subject = null;
                if (delivery.Token.Claims.TryGetProperty("sub_id", out var modern)) subject = JsonNode.Parse(modern.GetRawText());
                else if (securityEvent.Value.TryGetProperty("subject", out var legacy)) subject = JsonNode.Parse(legacy.GetRawText());
                // The application owns CAEP/RISC subject mapping. Reject foreign namespaces before local business effects.
                if (securityEvent.Name.Contains("/caep/", StringComparison.Ordinal) || securityEvent.Name.Contains("/risc/", StringComparison.Ordinal))
                {
                    var user = subject?["user"] ?? subject;
                    if (user?["format"]?.GetValue<string>() != "iss_sub" || user["iss"]?.GetValue<string>() != issuer || string.IsNullOrWhiteSpace(user["sub"]?.GetValue<string>()))
                        throw new InvalidDataException("Foreign or unsupported test application subject namespace.");
                }
                state["events"]!.AsArray().Add((JsonNode)new JsonObject { ["id"] = delivery.Token.Id, ["type"] = securityEvent.Name, ["subject"] = subject,
                    ["payload"] = JsonNode.Parse(securityEvent.Value.GetRawText()) });
            }
            state["receipts"]![delivery.ReceiptKey] = delivery.RetainUntil.ToUnixTimeSeconds();
            string temporary = path + ".pending";
            await using (var file = new FileStream(temporary, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                await file.WriteAsync(Encoding.UTF8.GetBytes(state.ToJsonString()), cancellationToken); file.Flush(flushToDisk: true);
            }
            File.Move(temporary, path, overwrite: true);
        }
        finally { mutex.Release(); }
    }
}

// A push success means signature validation and the inbox commit have both finished, never merely that bytes arrived.
internal sealed class ProtocolSsfReceiver : IAsyncDisposable
{
    private readonly HttpListener listener = new();
    private readonly CancellationTokenSource stop = new();
    private readonly Channel<VerifiedSecurityEventToken> received = Channel.CreateBounded<VerifiedSecurityEventToken>(32);
    private readonly Task worker;
    private readonly SecurityEventProcessor processor;
    private readonly string authorization;
    private int requests, lastStatus;
    internal ProtocolSsfReceiver(SecurityEventProcessor processor, string authorization)
    {
        this.processor = processor; this.authorization = authorization;
        listener.Prefixes.Add("http://127.0.0.1:18084/"); listener.Start(); worker = RunAsync();
    }
    internal async Task<VerifiedSecurityEventToken> NextAsync(CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(25));
        try { return await received.Reader.ReadAsync(timeout.Token); }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        { throw new InvalidDataException($"SSF push timed out after {requests} requests; last HTTP status {lastStatus}."); }
    }
    private async Task RunAsync()
    {
        try
        {
            while (!stop.IsCancellationRequested)
            {
                var context = await listener.GetContextAsync().WaitAsync(stop.Token); VerifiedSecurityEventToken? verified = null;
                requests++;
                try
                {
                    if (context.Request.HttpMethod != "POST" || context.Request.Url!.AbsolutePath != "/events" || context.Request.ContentType != "application/secevent+jwt"
                        || context.Request.Headers["Authorization"] != authorization) { context.Response.StatusCode = 401; }
                    else
                    {
                        using var body = new MemoryStream(); var buffer = new byte[4096]; int length;
                        while ((length = await context.Request.InputStream.ReadAsync(buffer, stop.Token)) != 0)
                        { if (body.Length + length > 65536) throw new InvalidDataException("Oversized SET."); body.Write(buffer, 0, length); }
                        verified = await processor.ProcessAsync(Encoding.UTF8.GetString(body.ToArray()), cancellationToken: stop.Token);
                        context.Response.StatusCode = 202;
                    }
                }
                catch (InvalidDataException) { context.Response.StatusCode = 400; }
                catch (IOException) { context.Response.StatusCode = 503; }
                finally { lastStatus = context.Response.StatusCode; context.Response.KeepAlive = false; context.Response.ContentLength64 = 0; context.Response.Close(); }
                if (verified is not null) await received.Writer.WriteAsync(verified, stop.Token);
            }
        }
        catch (Exception error) when (stop.IsCancellationRequested && error is OperationCanceledException or HttpListenerException or ObjectDisposedException) { }
        finally { received.Writer.TryComplete(); }
    }
    public async ValueTask DisposeAsync() { stop.Cancel(); listener.Close(); try { await worker; } finally { stop.Dispose(); } }
}
