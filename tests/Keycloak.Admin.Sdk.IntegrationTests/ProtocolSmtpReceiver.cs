using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Channels;

// Owned loopback SMTP fixture. It never forwards a message and never logs bodies, action tokens or recipients.
internal sealed class ProtocolSmtpReceiver : IAsyncDisposable
{
    internal const int Port = 18088;
    private readonly TcpListener listener = new(IPAddress.Loopback, Port);
    private readonly CancellationTokenSource stop = new();
    private readonly Channel<Message> messages = Channel.CreateBounded<Message>(8);
    private readonly Task loop;
    internal sealed class Message(string recipient, string body)
    {
        internal string Recipient { get; } = recipient;
        internal Uri ActionLink(Uri issuer)
        {
            // Jakarta Mail uses quoted-printable for long action links. Decode only in memory in this fixture.
            string decoded = body.Replace("=\r\n", "", StringComparison.Ordinal).Replace("=\n", "", StringComparison.Ordinal);
            decoded = Regex.Replace(decoded, "=([0-9a-fA-F]{2})", m => ((char)Convert.ToByte(m.Groups[1].Value, 16)).ToString(), RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
            decoded = WebUtility.HtmlDecode(decoded);
            string prefix = issuer.AbsoluteUri + "/login-actions/action-token?key=";
            var matches = Regex.Matches(decoded, Regex.Escape(prefix) + "[A-Za-z0-9_.%-]+", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1)).Select(m => m.Value).Distinct(StringComparer.Ordinal).ToArray();
            if (matches.Length != 1) throw new InvalidDataException("Expected one action link in the owned SMTP message.");
            return new(matches[0]);
        }
    }
    internal ProtocolSmtpReceiver() { listener.Start(); loop = RunAsync(); }
    internal async Task<Message> ReceiveAsync(CancellationToken ct)
    { using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(20)); return await messages.Reader.ReadAsync(timeout.Token); }
    private async Task RunAsync()
    {
        try
        {
            while (true)
            {
                using var client = await listener.AcceptTcpClientAsync(stop.Token);
                await using var stream = client.GetStream(); using var reader = new StreamReader(stream, Encoding.ASCII, false, 4096, true);
                await using var writer = new StreamWriter(stream, Encoding.ASCII, 4096, true) { NewLine = "\r\n", AutoFlush = true };
                await writer.WriteLineAsync("220 sdk-owned-smtp ESMTP".AsMemory(), stop.Token);
                string recipient = "";
                while (true)
                {
                    string? line = await reader.ReadLineAsync(stop.Token); if (line is null) break;
                    if (line.Length > 65536) throw new InvalidDataException("SMTP fixture command exceeds its bound.");
                    string verb = line.Split(' ', 2)[0].ToUpperInvariant();
                    if (verb is "EHLO" or "HELO") await writer.WriteLineAsync("250 sdk-owned-smtp".AsMemory(), stop.Token);
                    else if (verb == "RCPT") { recipient = line; await writer.WriteLineAsync("250 accepted".AsMemory(), stop.Token); }
                    else if (verb == "DATA")
                    {
                        await writer.WriteLineAsync("354 end with dot".AsMemory(), stop.Token); var body = new StringBuilder();
                        while (true)
                        {
                            string data = await reader.ReadLineAsync(stop.Token) ?? throw new EndOfStreamException();
                            if (data == ".") break;
                            if (body.Length + data.Length > 1024 * 1024) throw new InvalidDataException("SMTP fixture message exceeds its bound.");
                            body.AppendLine(data.StartsWith("..", StringComparison.Ordinal) ? data[1..] : data);
                        }
                        await messages.Writer.WriteAsync(new(recipient, body.ToString()), stop.Token); await writer.WriteLineAsync("250 queued".AsMemory(), stop.Token);
                    }
                    else if (verb == "QUIT") { await writer.WriteLineAsync("221 bye".AsMemory(), stop.Token); break; }
                    else await writer.WriteLineAsync("250 ok".AsMemory(), stop.Token);
                }
            }
        }
        catch (Exception error) when (stop.IsCancellationRequested && error is OperationCanceledException or SocketException or IOException or ObjectDisposedException) { }
    }
    public async ValueTask DisposeAsync()
    { await stop.CancelAsync(); listener.Stop(); try { await loop; } finally { stop.Dispose(); } }
}
