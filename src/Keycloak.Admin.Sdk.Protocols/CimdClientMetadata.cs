using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Keycloak.Admin.Sdk.Protocols;

/// <summary>A public OAuth Client ID Metadata Document. The host publishes it at ClientId over HTTPS.
/// Keycloak's CIMD client policy must separately permit the document/redirect/key domains. This object never fetches an arbitrary URL.</summary>
public sealed class CimdClientMetadata
{
    public string ClientId { get; }
    public string AuthenticationMethod { get; }
    private readonly JsonElement document;
    public JsonElement ToJson() => document.Clone();
    public CimdClientMetadata(JsonElement document, bool allowLoopbackHttp = false)
    {
        if (document.ValueKind != JsonValueKind.Object || Encoding.UTF8.GetByteCount(document.GetRawText()) > 65536
            || document.EnumerateObject().GroupBy(p => p.Name, StringComparer.Ordinal).Any(g => g.Count() != 1)
            || document.TryGetProperty("client_secret", out _) || document.TryGetProperty("client_secret_expires_at", out _) || document.TryGetProperty("registration_access_token", out _)) throw Invalid();
        ClientId = String(document, "client_id"); ValidateEndpoint(ClientId, allowLoopbackHttp);
        if (!document.TryGetProperty("redirect_uris", out var redirects) || redirects.ValueKind != JsonValueKind.Array || redirects.GetArrayLength() is 0 or > 32) throw Invalid();
        foreach (var value in redirects.EnumerateArray())
        {
            if (value.ValueKind != JsonValueKind.String || !Uri.TryCreate(value.GetString(), UriKind.Absolute, out var uri) || uri.Fragment.Length != 0 || uri.UserInfo.Length != 0 || uri.OriginalString.Contains('*', StringComparison.Ordinal)) throw Invalid();
            if (uri.Scheme is "http" or "https") ValidateEndpoint(uri.AbsoluteUri, allowLoopbackHttp);
        }
        AuthenticationMethod = document.TryGetProperty("token_endpoint_auth_method", out _) ? String(document, "token_endpoint_auth_method") : "none";
        if (AuthenticationMethod is not ("none" or "private_key_jwt" or "tls_client_auth" or "self_signed_tls_client_auth")) throw Invalid();
        bool uriKeys = document.TryGetProperty("jwks_uri", out _), inlineKeys = document.TryGetProperty("jwks", out var keys);
        if (uriKeys && inlineKeys || AuthenticationMethod == "private_key_jwt" && !uriKeys && !inlineKeys) throw Invalid();
        if (uriKeys) ValidateEndpoint(String(document, "jwks_uri"), allowLoopbackHttp);
        if (inlineKeys)
        {
            if (keys.ValueKind != JsonValueKind.Object || !keys.TryGetProperty("keys", out var array) || array.ValueKind != JsonValueKind.Array || array.GetArrayLength() is 0 or > 32) throw Invalid();
            foreach (var key in array.EnumerateArray())
            {
                if (key.ValueKind != JsonValueKind.Object || String(key, "kty") is not ("RSA" or "EC" or "OKP")
                    || key.EnumerateObject().Any(p => p.Name is "k" or "d" or "p" or "q" or "dp" or "dq" or "qi" or "oth")
                    || key.EnumerateObject().GroupBy(p => p.Name, StringComparer.Ordinal).Any(g => g.Count() != 1)) throw Invalid();
            }
        }
        this.document = document.Clone();
    }
    /// <summary>Creates common authorization-code/PKCE metadata. A JWKS URI selects private_key_jwt; otherwise the client is public.</summary>
    public static CimdClientMetadata Create(Uri clientId, string name, IEnumerable<Uri> redirectUris, Uri? jwksUri = null, bool allowLoopbackHttp = false)
    {
        ArgumentNullException.ThrowIfNull(clientId); ArgumentException.ThrowIfNullOrWhiteSpace(name); ArgumentNullException.ThrowIfNull(redirectUris);
        static string Absolute(Uri uri) { ArgumentNullException.ThrowIfNull(uri); if (!uri.IsAbsoluteUri) throw Invalid(); return uri.AbsoluteUri; }
        var body = new JsonObject { ["client_id"] = Absolute(clientId), ["client_name"] = name, ["redirect_uris"] = new JsonArray(redirectUris.Take(33).Select(uri => (JsonNode)JsonValue.Create(Absolute(uri))!).ToArray()),
            ["grant_types"] = new JsonArray("authorization_code", "refresh_token"), ["response_types"] = new JsonArray("code"), ["token_endpoint_auth_method"] = jwksUri is null ? "none" : "private_key_jwt" };
        if (jwksUri is not null) body["jwks_uri"] = Absolute(jwksUri);
        using var json = JsonDocument.Parse(body.ToJsonString()); return new(json.RootElement, allowLoopbackHttp);
    }
    public OAuthClientAuthentication CreateAuthentication(Func<CancellationToken, ValueTask<string>>? assertion = null)
        => OAuthClientAuthentication.ClientMetadata(this, assertion);
    private static string String(JsonElement value, string name)
    { if (!value.TryGetProperty(name, out var property) || property.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(property.GetString())) throw Invalid(); return property.GetString()!; }
    private static void ValidateEndpoint(string value, bool allowLoopbackHttp)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.UserInfo.Length != 0 || uri.Fragment.Length != 0 || uri.Query.Length != 0
            || !(uri.Scheme == "https" || allowLoopbackHttp && uri.Scheme == "http" && uri.IsLoopback)) throw Invalid();
    }
    private static ArgumentException Invalid() => new("Invalid or credential-bearing public client metadata document.");
}
