using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;

// Controlled upstream wire counterpart. DNS overrides apply only to the owned Keycloak container;
// no request reaches a social service. Actual external accounts and API availability remain external.
internal sealed class ProtocolSocialCounterpart : IAsyncDisposable
{
    private readonly TcpListener listener = new(IPAddress.Loopback, 443);
    private readonly CancellationTokenSource stop = new();
    private readonly X509Certificate2 certificate;
    private readonly string secret, issuer;
    private readonly Task worker;
    private readonly SemaphoreSlim connections = new(8);
    private readonly List<Task> clients = [];
    private readonly object stateLock = new();
    private readonly Dictionary<string, (string Secret, Uri Callback)> requestTokens = new(StringComparer.Ordinal);
    private readonly HashSet<string> oauthNonces = new(StringComparer.Ordinal), accessTokens = new(StringComparer.Ordinal), codes = new(StringComparer.Ordinal);
    private readonly Dictionary<string, Uri> authorizations = new(StringComparer.Ordinal);
    internal bool CorruptState;
    internal int ValidatedOAuth1Requests, ValidatedOAuth2Requests;
    internal int CorruptedStateCallbacks;
    internal ProtocolSocialCounterpart(string directory, string secret, Uri issuer)
    {
        this.secret = secret; this.issuer = issuer.AbsoluteUri;
        certificate = X509Certificate2.CreateFromPemFile(Path.Combine(directory, "social.pem"), Path.Combine(directory, "social.key"));
        listener.Start(); worker = RunAsync();
    }
    private async Task RunAsync()
    {
        try
        {
            while (true)
            {
                await connections.WaitAsync(stop.Token);
                TcpClient client;
                try { client = await listener.AcceptTcpClientAsync(stop.Token); } catch { connections.Release(); throw; }
                clients.Add(HandleClientAsync(client));
            }
        }
        catch (Exception error) when (stop.IsCancellationRequested && error is OperationCanceledException or SocketException or ObjectDisposedException or IOException) { }
        finally { await Task.WhenAll(clients); }
    }
    private async Task HandleClientAsync(TcpClient connection)
    {
        using var client = connection;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(stop.Token); timeout.CancelAfter(TimeSpan.FromSeconds(10));
        using var stream = new SslStream(client.GetStream());
        try
        {
                try
                {
                    await stream.AuthenticateAsServerAsync(new SslServerAuthenticationOptions { ServerCertificate = certificate }, timeout.Token);
                    using var reader = new StreamReader(stream, new UTF8Encoding(false, true), false, 1024, true);
                    string request = await reader.ReadLineAsync(timeout.Token) ?? throw new InvalidDataException();
                    var parts = request.Split(' '); if (parts.Length != 3 || request.Length > 8192) throw new InvalidDataException();
                    var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase); int total = 0;
                    while (await reader.ReadLineAsync(timeout.Token) is { Length: > 0 } line)
                    { if ((total += line.Length) > 32768) throw new InvalidDataException(); int split = line.IndexOf(':'); headers.Add(line[..split], line[(split + 1)..].Trim()); }
                    int length = headers.TryGetValue("Content-Length", out string? size) ? int.Parse(size, System.Globalization.CultureInfo.InvariantCulture) : 0;
                    if (length is < 0 or > 65536) throw new InvalidDataException(); char[] data = new char[length];
                    if (length > 0 && await reader.ReadBlockAsync(data.AsMemory(), timeout.Token) != length) throw new InvalidDataException();
                    var target = new Uri("https://" + headers["Host"] + parts[1]); var body = Form(new string(data));
                    Console.WriteLine("Owned social counterpart: " + parts[0] + " " + target.Host + target.AbsolutePath);
                    Reply result; lock (stateLock) result = Handle(parts[0], target, headers.GetValueOrDefault("Authorization"), body);
                    string response = "HTTP/1.1 " + result.Status + " response\r\nConnection: close\r\nContent-Type: " + result.Media + "\r\nContent-Length: " + Encoding.UTF8.GetByteCount(result.Body) + "\r\n"
                        + (result.Redirect is null ? "" : "Location: " + result.Redirect.AbsoluteUri + "\r\n") + "\r\n" + result.Body;
                    await stream.WriteAsync(Encoding.UTF8.GetBytes(response), timeout.Token); await stream.FlushAsync(timeout.Token);
                }
                catch (Exception error) when (error is IOException or System.Security.Authentication.AuthenticationException or InvalidDataException or FormatException or ArgumentException or KeyNotFoundException or OperationCanceledException)
                { Console.WriteLine("Owned social counterpart refused: " + error.GetType().Name); }
        }
        finally { connections.Release(); }
    }
    private Reply Handle(string method, Uri target, string? authorization, Dictionary<string, string> body)
    {
        var query = Form(target.Query.TrimStart('?'));
        if (target.Host == "api.twitter.com")
        {
            if (target.AbsolutePath is "/oauth/authenticate" or "/oauth/authorize")
            {
                if (!requestTokens.TryGetValue(query.GetValueOrDefault("oauth_token") ?? "", out var authorizationState)) return Error();
                return Redirect(Callback(authorizationState.Callback, new() { ["oauth_token"] = query["oauth_token"], ["oauth_verifier"] = "owned-verifier" }));
            }
            var oauth = OAuth(authorization);
            string token = oauth.GetValueOrDefault("oauth_token") ?? "";
            string tokenSecret = target.AbsolutePath == "/oauth/request_token" ? "" : requestTokens.TryGetValue(token, out var state) ? state.Secret : "";
            if (target.AbsolutePath.StartsWith("/1.1/", StringComparison.Ordinal)) tokenSecret = "owned-access-secret";
            if (!Verify(method, target, oauth, body, tokenSecret)) return Error();
            ValidatedOAuth1Requests++;
            if (target.AbsolutePath == "/oauth/request_token")
            {
                var callback = new Uri(oauth.GetValueOrDefault("oauth_callback") ?? body.GetValueOrDefault("oauth_callback") ?? throw new InvalidDataException("Missing controlled callback.")); RequireCallback(callback, "twitter"); string handle = Guid.NewGuid().ToString("N");
                string requestSecret = Guid.NewGuid().ToString("N"); requestTokens[handle] = (requestSecret, callback);
                return new(200, "application/x-www-form-urlencoded", "oauth_token=" + handle + "&oauth_token_secret=" + requestSecret + "&oauth_callback_confirmed=true");
            }
            if (target.AbsolutePath == "/oauth/access_token")
            {
                if (!requestTokens.ContainsKey(token) || (oauth.GetValueOrDefault("oauth_verifier") ?? body.GetValueOrDefault("oauth_verifier")) != "owned-verifier") return Error();
                requestTokens.Remove(token); string access = Guid.NewGuid().ToString("N"); accessTokens.Add(access);
                return new(200, "application/x-www-form-urlencoded", "oauth_token=" + access + "&oauth_token_secret=owned-access-secret&user_id=42&screen_name=twitter-user");
            }
            if (target.AbsolutePath == "/1.1/account/verify_credentials.json" && accessTokens.Contains(token))
                return Json(new() { ["id"] = 42, ["id_str"] = "42", ["name"] = "Twitter Fixture", ["screen_name"] = "twitter-user", ["email"] = "twitter@example.invalid", ["created_at"] = "Wed Oct 10 20:19:24 +0000 2018" });
        }
        if (target.Host == "api.instagram.com" && target.AbsolutePath == "/oauth/authorize")
        {
            var callback = new Uri(query["redirect_uri"]); RequireCallback(callback, "instagram");
            if (query["client_id"] != "social-fixture" || query["response_type"] != "code") return Error();
            string code = Guid.NewGuid().ToString("N"); codes.Add(code); authorizations[code] = callback;
            return Redirect(Callback(callback, new() { ["code"] = code, ["state"] = query["state"] }));
        }
        if (target.Host == "api.instagram.com" && target.AbsolutePath == "/oauth/access_token")
        {
            if (method != "POST" || body.GetValueOrDefault("client_id") != "social-fixture" || body.GetValueOrDefault("client_secret") != secret
                || body.GetValueOrDefault("grant_type") != "authorization_code" || !codes.Remove(body.GetValueOrDefault("code") ?? "")
                || body.GetValueOrDefault("redirect_uri") != authorizations[body["code"]].AbsoluteUri) return Error();
            ValidatedOAuth2Requests++; string token = Guid.NewGuid().ToString("N"); accessTokens.Add(token); return Json(new() { ["access_token"] = token, ["user_id"] = "42", ["token_type"] = "bearer" });
        }
        if (target.Host == "graph.instagram.com" && target.AbsolutePath == "/me" && accessTokens.Contains(query.GetValueOrDefault("access_token") ?? ""))
            return Json(new() { ["id"] = "42", ["username"] = "instagram-user" });
        return Error();
    }
    private Uri Callback(Uri original, Dictionary<string, string> extra)
    {
        var query = Form(original.Query.TrimStart('?')); foreach (var pair in extra) query.Add(pair.Key, pair.Value);
        if (CorruptState) { query["state"] = "invalid-state"; CorruptedStateCallbacks++; }
        return new(original.GetLeftPart(UriPartial.Path) + "?" + string.Join('&', query.Select(p => Escape(p.Key) + "=" + Escape(p.Value))));
    }
    private void RequireCallback(Uri callback, string provider)
    { if (callback.GetLeftPart(UriPartial.Path) != issuer + "/broker/sdk-" + provider + "/endpoint") throw new InvalidDataException("Foreign controlled callback."); }
    private bool Verify(string method, Uri target, Dictionary<string, string> oauth, Dictionary<string, string> body, string tokenSecret)
    {
        if (oauth.GetValueOrDefault("oauth_consumer_key") != "social-fixture" || oauth.GetValueOrDefault("oauth_signature_method") != "HMAC-SHA1"
            || !long.TryParse(oauth.GetValueOrDefault("oauth_timestamp"), out long timestamp) || Math.Abs(DateTimeOffset.UtcNow.ToUnixTimeSeconds() - timestamp) > 60) return false;
        var parameters = oauth.Where(p => p.Key != "oauth_signature" && p.Key != "realm").Concat(Form(target.Query.TrimStart('?'))).Concat(body)
            .Select(p => new KeyValuePair<string, string>(Escape(p.Key), Escape(p.Value))).OrderBy(p => p.Key, StringComparer.Ordinal).ThenBy(p => p.Value, StringComparer.Ordinal);
        string normalized = string.Join('&', parameters.Select(p => p.Key + "=" + p.Value));
        string basis = method + "&" + Escape(target.GetLeftPart(UriPartial.Path)) + "&" + Escape(normalized);
        string signature = Convert.ToBase64String(HMACSHA1.HashData(Encoding.ASCII.GetBytes(Escape(secret) + "&" + Escape(tokenSecret)), Encoding.ASCII.GetBytes(basis)));
        return CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(signature), Encoding.ASCII.GetBytes(oauth.GetValueOrDefault("oauth_signature") ?? ""))
            && oauthNonces.Add(oauth["oauth_nonce"]);
    }
    private static Dictionary<string, string> OAuth(string? authorization)
    { if (authorization?.StartsWith("OAuth ", StringComparison.Ordinal) != true) return new(); return authorization[6..].Split(',').Select(p => p.Trim().Split('=', 2)).ToDictionary(p => p[0], p => Uri.UnescapeDataString(p[1].Trim('"')), StringComparer.Ordinal); }
    private static Dictionary<string, string> Form(string text) => text.Length == 0 ? new() : text.Split('&').Select(p => p.Split('=', 2)).ToDictionary(p => Uri.UnescapeDataString(p[0].Replace('+', ' ')), p => Uri.UnescapeDataString(p.Length == 1 ? "" : p[1].Replace('+', ' ')), StringComparer.Ordinal);
    private static string Escape(string value) => Uri.EscapeDataString(value);
    private static Reply Error() => new(400, "application/json", "{\"error\":\"invalid_request\"}");
    private static Reply Json(JsonObject value) => new(200, "application/json", value.ToJsonString());
    private static Reply Redirect(Uri value) => new(302, "text/plain", "", value);
    private sealed record Reply(int Status, string Media, string Body, Uri? Redirect = null);
    public async ValueTask DisposeAsync()
    { await stop.CancelAsync(); listener.Stop(); try { await worker; } finally { certificate.Dispose(); stop.Dispose(); connections.Dispose(); } }
}
