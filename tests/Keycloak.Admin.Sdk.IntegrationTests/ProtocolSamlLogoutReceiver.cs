#if KEYCLOAK_HOSTING
using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using Keycloak.Admin.Sdk.Hosting;

// Single-process journal fixture. Production hosts implement the same atomic receipt + revocation in their shared session database.
internal sealed class ProtocolSamlLogoutReceiver : IAsyncDisposable, ISamlLogoutSessionStore
{
    internal static readonly Uri Endpoint = new("http://127.0.0.1:18085/logout");
    private readonly HttpListener listener = new(); private readonly CancellationTokenSource stop = new();
    private readonly SemaphoreSlim mutation = new(1); private readonly Task loop;
    private readonly KeycloakSamlServiceProvider provider; private readonly VerifiedSamlSession expected; private readonly string path;
    internal string? CapturedSoap { get; private set; }
    private string? currentSoap;
    internal bool FailStorage { get; set; }
    internal int Failures, Successes;
    internal ProtocolSamlLogoutReceiver(KeycloakSamlServiceProvider provider, VerifiedSamlSession session)
    {
        this.provider = provider; expected = session;
        path = Path.Combine(Directory.GetCurrentDirectory(), "artifacts/application-protocols", "saml-session-" + Guid.NewGuid().ToString("N") + ".json");
        Directory.CreateDirectory(Path.GetDirectoryName(path)!); File.WriteAllText(path, new JsonObject { ["active"] = true, ["effects"] = 0, ["receipts"] = new JsonObject() }.ToJsonString());
        listener.Prefixes.Add("http://127.0.0.1:18085/"); listener.Start(); loop = RunAsync();
    }
    internal (bool Active, int Effects) Persisted() { var state = JsonNode.Parse(File.ReadAllText(path))!; return (state["active"]!.GetValue<bool>(), state["effects"]!.GetValue<int>()); }
    public async ValueTask RevokeOnceAsync(SamlLogoutNotification notification, CancellationToken cancellationToken = default)
    {
        await mutation.WaitAsync(cancellationToken);
        try
        {
            var state = JsonNode.Parse(await File.ReadAllTextAsync(path, cancellationToken))!;
            var receipts = state["receipts"]!.AsObject(); if (receipts.ContainsKey(notification.ReplayKey)) return;
            bool matches = notification.Issuer == expected.Issuer && notification.ServiceProvider == expected.ServiceProvider && notification.NameId == expected.NameId
                && notification.NameIdFormat == expected.NameIdFormat && notification.SessionIndex == expected.SessionIndex;
            if (matches) CapturedSoap ??= currentSoap;
            if (FailStorage) throw new IOException("Simulated session storage failure.");
            if (matches && state["active"]!.GetValue<bool>())
            { state["active"] = false; state["effects"] = state["effects"]!.GetValue<int>() + 1; }
            receipts[notification.ReplayKey] = notification.ExpiresAt.ToString("O");
            string temporary = path + ".tmp";
            try
            {
                await using (var file = new FileStream(temporary, FileMode.Create, FileAccess.Write, FileShare.None))
                { await file.WriteAsync(Encoding.UTF8.GetBytes(state.ToJsonString()), cancellationToken); await file.FlushAsync(cancellationToken); file.Flush(true); }
                File.Move(temporary, path, true);
            }
            finally { File.Delete(temporary); }
        }
        finally { mutation.Release(); }
    }
    private async Task RunAsync()
    {
        try
        {
            while (true)
            {
                var context = await listener.GetContextAsync().WaitAsync(stop.Token);
                try
                {
                    if (context.Request.HttpMethod != "POST" || context.Request.Url != Endpoint) throw new InvalidDataException("Unexpected SAML SOAP receiver request.");
                    using var buffer = new MemoryStream(); var block = new byte[8192]; int read;
                    while ((read = await context.Request.InputStream.ReadAsync(block, stop.Token)) != 0)
                    { if (buffer.Length + read > 262144) throw new InvalidDataException("SOAP request exceeds bound."); buffer.Write(block, 0, read); }
                    string body = Encoding.UTF8.GetString(buffer.ToArray()); currentSoap = body;
                    string response = await provider.HandleLogoutSoapAsync(Endpoint, body, this, stop.Token);
                    context.Response.StatusCode = 200; context.Response.ContentType = "text/xml";
                    await context.Response.OutputStream.WriteAsync(Encoding.UTF8.GetBytes(response), stop.Token); Interlocked.Increment(ref Successes);
                }
                catch (Exception error) when (error is IOException or InvalidDataException)
                {
                    Interlocked.Increment(ref Failures); context.Response.StatusCode = 503;
                }
                finally { context.Response.Close(); }
            }
        }
        catch (Exception error) when (stop.IsCancellationRequested && error is OperationCanceledException or HttpListenerException or ObjectDisposedException) { }
    }
    public async ValueTask DisposeAsync()
    {
        await stop.CancelAsync(); listener.Close();
        try { await loop; }
        finally { mutation.Dispose(); stop.Dispose(); File.Delete(path); }
    }
}
#endif
