using System.Net;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

// Controlled external issuer fixture, not a Kubernetes API server or a SPIRE deployment.
// Exercises real Keycloak provider discovery/JWKS/bundle validation without claiming infrastructure acceptance.
internal sealed class ProtocolWorkloadIssuer : IAsyncDisposable
{
    internal const string KubernetesIssuer = "https://kubernetes.default.svc";
    internal const string Root = "http://127.0.0.1:18083";
    private readonly HttpListener listener = new();
    private readonly CancellationTokenSource stop = new();
    private readonly Task loop;
    private string jwks = "", bundle = "";
    private readonly ConcurrentDictionary<string, string> documents = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, string> requestObjects = new(StringComparer.Ordinal);
    internal void PublishDocument(string path, JsonElement document) => documents[path] = document.GetRawText();
    internal void PublishRequestObject(string path, string credential) => requestObjects[path] = credential;
    internal ProtocolWorkloadIssuer(RSA key, string id)
    { Publish(key, id); listener.Prefixes.Add(Root + "/"); listener.Start(); loop = RunAsync(); }
    internal void Publish(RSA key, string id)
    {
        var publicKey = key.ExportParameters(false);
        JsonObject Jwk(string use) => new() { ["kty"] = "RSA", ["kid"] = id, ["n"] = Base64UrlEncoder.Encode(publicKey.Modulus!), ["e"] = Base64UrlEncoder.Encode(publicKey.Exponent!), ["use"] = use };
        Volatile.Write(ref jwks, new JsonObject { ["keys"] = new JsonArray(Jwk("sig")) }.ToJsonString());
        Volatile.Write(ref bundle, new JsonObject { ["keys"] = new JsonArray(Jwk("jwt-svid")), ["spiffe_sequence"] = 1, ["spiffe_refresh_hint"] = 60 }.ToJsonString());
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
                    string path = context.Request.Url!.AbsolutePath;
                    string body = path switch { "/.well-known/openid-configuration" => new JsonObject { ["issuer"] = KubernetesIssuer, ["jwks_uri"] = Root + "/jwks" }.ToJsonString(),
                        "/jwks" => Volatile.Read(ref jwks), "/bundle" => Volatile.Read(ref bundle), _ => requestObjects.GetValueOrDefault(path) ?? documents.GetValueOrDefault(path) ?? "{}" };
                    context.Response.StatusCode = context.Request.HttpMethod == "GET" && (path is "/.well-known/openid-configuration" or "/jwks" or "/bundle" || documents.ContainsKey(path) || requestObjects.ContainsKey(path)) ? 200 : 404;
                    context.Response.Headers["Cache-Control"] = "no-store";
                    // Sequential fixtures reuse this owned port; never leave Keycloak pooled on a previous listener instance.
                    context.Response.KeepAlive = false;
                    byte[] bytes = Encoding.UTF8.GetBytes(body); context.Response.ContentType = requestObjects.ContainsKey(path) ? "application/oauth-authz-req+jwt" : "application/json"; context.Response.ContentLength64 = bytes.Length;
                    await context.Response.OutputStream.WriteAsync(bytes, stop.Token);
                }
                finally { context.Response.Close(); }
            }
        }
        catch (Exception error) when (stop.IsCancellationRequested && error is OperationCanceledException or HttpListenerException or ObjectDisposedException) { }
    }
    public async ValueTask DisposeAsync()
    { await stop.CancelAsync(); listener.Close(); try { await loop; } finally { stop.Dispose(); } }
}
