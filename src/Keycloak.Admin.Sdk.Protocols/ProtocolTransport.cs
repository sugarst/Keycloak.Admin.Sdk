using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Collections.Frozen;
using Keycloak.Admin.Sdk.Capabilities;

namespace Keycloak.Admin.Sdk.Protocols;

/// <summary>Transport contract only: a successful call is not proof of protocol or business validation.</summary>
public sealed class ProtocolResponse
{
    public HttpStatusCode StatusCode { get; }
    public JsonElement? Json { get; }
    /// <summary>Explicitly requested non-JSON protocol content. Treat signed or encrypted bytes as unverified credentials.</summary>
    public ReadOnlyMemory<byte> RawBody { get; }
    public string? BodyMediaType { get; }
    public IReadOnlyDictionary<string, IReadOnlyList<string>> Headers { get; }
    public ProtocolResponse(HttpStatusCode statusCode, JsonElement? json, IEnumerable<KeyValuePair<string, IEnumerable<string>>>? headers = null,
        ReadOnlyMemory<byte> rawBody = default, string? bodyMediaType = null)
    {
        StatusCode = statusCode; Json = json; RawBody = rawBody.ToArray(); BodyMediaType = bodyMediaType;
        Headers = (headers ?? []).GroupBy(p => p.Key, StringComparer.OrdinalIgnoreCase).ToFrozenDictionary(g => g.Key,
            g => (IReadOnlyList<string>)Array.AsReadOnly(g.SelectMany(p => p.Value).ToArray()), StringComparer.OrdinalIgnoreCase);
    }
    // Object.ToString deliberately does not render credential-bearing payloads or headers.
}

/// <summary>No response body, token, request URL or parameters are included in exception messages.</summary>
public sealed class KeycloakProtocolException(HttpStatusCode statusCode, string operation, OAuthError error = OAuthError.Unknown, ScimError scimError = ScimError.None, string? dpopNonce = null)
    : HttpRequestException($"Keycloak protocol request failed ({(int)statusCode}, {operation}).", null, statusCode)
{
    public string Operation { get; } = operation;
    public OAuthError Error { get; } = error;
    public ScimError ScimError { get; } = scimError;
    public string? DpopNonce { get; } = dpopNonce;
}

/// <summary>Only known protocol error identifiers are retained. Server descriptions are never exposed.</summary>
public enum OAuthError { Unknown, AuthorizationPending, SlowDown, AccessDenied, ExpiredToken, InvalidGrant, InvalidClient, InvalidRequest, InvalidScope, UseDpopNonce, InvalidDpopProof, InvalidToken, InvalidTarget }
public enum ScimError { None, Unknown, InvalidFilter, TooMany, Uniqueness, Mutability, InvalidSyntax, InvalidPath, NoTarget, InvalidValue, Sensitive }

/// <summary>Bound to one server and realm. Caller owns HttpClient, credentials and user/session isolation.
/// Configure its handler with AllowAutoRedirect=false. No request is automatically retried.</summary>
public sealed class ProtocolTransport
{
    private readonly HttpClient http;
    private readonly Uri root;
    private readonly Uri serverRoot;
    internal string RealmSegment { get; }
    private readonly IKeycloakFeatureGate? gate;
    private readonly ApplicationSupportPolicy? supportPolicy;
    private readonly DpopProofKey? proofKey;
    private readonly bool mutualTls;
    public Uri Issuer => new(root.AbsoluteUri.TrimEnd('/'));

    public ProtocolTransport(HttpClient http, Uri server, string realm, IKeycloakFeatureGate? gate = null, DpopProofKey? proofKey = null, bool mutualTls = false)
        : this(http, server, realm, gate, proofKey, null, mutualTls) { }
    internal ProtocolTransport(HttpClient http, Uri server, string realm, IKeycloakFeatureGate? gate, DpopProofKey? proofKey, ApplicationSupportPolicy? supportPolicy, bool mutualTls = false)
    {
        this.http = http ?? throw new ArgumentNullException(nameof(http));
        ArgumentNullException.ThrowIfNull(server);
        if (!server.IsAbsoluteUri || server.Scheme is not ("https" or "http") || server.Query.Length != 0
            || server.Fragment.Length != 0 || server.UserInfo.Length != 0)
            throw new ArgumentException("An HTTP(S) server without credentials, query or fragment is required.", nameof(server));
        serverRoot = new(server.AbsoluteUri.TrimEnd('/') + "/");
        RealmSegment = Segment(realm);
        root = new Uri(serverRoot.AbsoluteUri + "realms/" + RealmSegment + "/");
        this.gate = gate;
        this.proofKey = proofKey;
        this.supportPolicy = supportPolicy;
        this.mutualTls = mutualTls;
    }

    /// <summary>Only independently promoted capabilities for the actual runtime can pass this factory's policy.
    /// Preview/Experimental require individual opt-ins; the host gate can subsequently close an otherwise allowed capability.</summary>
    public static ProtocolTransport CreateSupported(HttpClient http, Uri server, string realm, KeycloakServerCapabilities serverCapabilities,
        ApplicationSupportConfiguration configuration, IKeycloakFeatureGate hostGate, DpopProofKey? proofKey = null, bool mutualTls = false)
    {
        ArgumentNullException.ThrowIfNull(hostGate);
        return new(http, server, realm, hostGate, proofKey, new(serverCapabilities, configuration), mutualTls);
    }

    internal static string Segment(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if (value is "." or "..") throw new ArgumentException("Dot segments are not permitted.", nameof(value));
        return Uri.EscapeDataString(value);
    }

    internal Uri Target(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || path.StartsWith('/') || path.Contains('\\') || path.Contains('?') || path.Contains('#')
            || path.Split('/').Any(p => Uri.UnescapeDataString(p) is "." or "..") || Uri.TryCreate(path, UriKind.Absolute, out _))
            throw new ArgumentException("A realm-relative protocol path is required.", nameof(path));
        return new Uri(root.AbsoluteUri + path);
    }

    internal static string Query(IEnumerable<KeyValuePair<string, string>> values)
        => string.Join('&', values.Select(v => Uri.EscapeDataString(v.Key) + "=" + Uri.EscapeDataString(v.Value)));

    internal Task<ProtocolResponse> SendAsync(HttpMethod method, string path, string operation, string feature,
        HttpContent? content, string? accessToken, IEnumerable<KeyValuePair<string, string>>? query,
        Func<HttpRequestMessage, CancellationToken, ValueTask>? authenticate, CancellationToken cancellationToken, IEnumerable<string>? additionalFeatures = null, string? responseMediaType = null)
        => SendCoreAsync(method, path, operation, feature, content, accessToken, query, authenticate, false, cancellationToken, additionalFeatures, responseMediaType);

    internal Task<ProtocolResponse> SendServerAsync(HttpMethod method, string path, string operation, string feature,
        HttpContent? content, string? accessToken, IEnumerable<KeyValuePair<string, string>>? query, CancellationToken cancellationToken, string? responseMediaType = null)
        => SendCoreAsync(method, path, operation, feature, content, accessToken, query, null, true, cancellationToken, null, responseMediaType);

    private async Task<ProtocolResponse> SendCoreAsync(HttpMethod method, string path, string operation, string feature,
        HttpContent? content, string? accessToken, IEnumerable<KeyValuePair<string, string>>? query,
        Func<HttpRequestMessage, CancellationToken, ValueTask>? authenticate, bool serverPath, CancellationToken cancellationToken, IEnumerable<string>? additionalFeatures, string? responseMediaType)
    {
        if (responseMediaType is not (null or "application/jwt" or "application/oauth-authz-req+jwt" or "image/png"))
            throw new ArgumentException("An explicit supported protocol media type is required.", nameof(responseMediaType));
        Uri target = Target(path); // Apply the same traversal/absolute-path validation to both scopes.
        if (serverPath) target = new(serverRoot.AbsoluteUri + path);
        using var request = new HttpRequestMessage(method, target) { Content = content };
        cancellationToken.ThrowIfCancellationRequested();
        bool dpop = proofKey is not null && (accessToken is not null || ((feature.StartsWith("KeycloakSdk.Protocols.Oidc", StringComparison.Ordinal) || feature.StartsWith("KeycloakSdk.Protocols.Wallet", StringComparison.Ordinal)) && method == HttpMethod.Post));
        var required = new List<string> { feature };
        if (feature.StartsWith("KeycloakSdk.Protocols.Oidc", StringComparison.Ordinal) && feature != "KeycloakSdk.Protocols.Oidc") required.Add("KeycloakSdk.Protocols.Oidc");
        required.AddRange(additionalFeatures ?? []);
        if (dpop) required.Add("KeycloakSdk.Protocols.Dpop");
        await EnsureEnabledAsync(required.Distinct(StringComparer.Ordinal).ToArray(), path, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (query is not null)
        {
            string suffix = Query(query);
            if (suffix.Length != 0) request.RequestUri = new Uri(request.RequestUri!.AbsoluteUri + "?" + suffix);
        }
        if (accessToken is not null) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(responseMediaType ?? (feature == "KeycloakSdk.Protocols.Scim" ? "application/scim+json" : "application/json")));
        if (authenticate is not null) await authenticate(request, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (dpop)
        {
            var authorization = request.Headers.Authorization;
            string? boundToken = authorization?.Scheme == "Bearer" ? authorization.Parameter : null;
            if (boundToken is not null) request.Headers.Authorization = new AuthenticationHeaderValue("DPoP", boundToken);
            request.Headers.Add("DPoP", proofKey!.CreateProof(method, request.RequestUri!, boundToken));
        }
        using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        string? nonce = null;
        if (dpop && response.Headers.TryGetValues("DPoP-Nonce", out var challenges))
        {
            string[] values = challenges.ToArray();
            if (values.Length != 1) throw new InvalidDataException("Expected one DPoP nonce.");
            nonce = values[0];
            try { proofKey!.SetNonce(request.RequestUri!, nonce); }
            catch (ArgumentException) { throw new InvalidDataException("Invalid DPoP nonce."); }
        }
        if (!response.IsSuccessStatusCode)
        {
            var errors = await ReadErrorAsync(response.Content, cancellationToken).ConfigureAwait(false);
            throw new KeycloakProtocolException(response.StatusCode, operation, errors.OAuth, errors.Scim, nonce);
        }
        var headers = response.Headers.Concat(response.Content.Headers).ToArray();
        if (response.StatusCode == HttpStatusCode.NoContent) return new(response.StatusCode, null, headers);
        if (responseMediaType is not null && response.Content.Headers.ContentType?.MediaType != responseMediaType)
            throw new InvalidDataException("Unexpected protocol response media type.");
        byte[] bytes = await ReadBoundedAsync(response.Content, responseMediaType is null ? 16 * 1024 * 1024 : responseMediaType == "image/png" ? 1024 * 1024 : 65536, cancellationToken).ConfigureAwait(false);
        if (responseMediaType is not null) return new(response.StatusCode, null, headers, bytes, responseMediaType);
        if (bytes.Length == 0) return new(response.StatusCode, null, headers);
        using var document = JsonDocument.Parse(bytes);
        return new(response.StatusCode, document.RootElement.Clone(), headers);
    }

    private static async Task<byte[]> ReadBoundedAsync(HttpContent content, int maximum, CancellationToken ct)
    {
        using var stream = await content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        using var buffer = new MemoryStream(); var chunk = new byte[8192];
        while (true)
        {
            int read = await stream.ReadAsync(chunk, ct).ConfigureAwait(false);
            if (read == 0) return buffer.ToArray();
            if (buffer.Length + read > maximum) throw new InvalidDataException("Protocol response exceeds its size limit.");
            buffer.Write(chunk, 0, read);
        }
    }

    private static async Task<(OAuthError OAuth, ScimError Scim)> ReadErrorAsync(HttpContent content, CancellationToken ct)
    {
        // Bound untrusted errors; do not buffer or expose a possibly huge HTML page, token or description.
        using var stream = await content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        var buffer = new byte[4097]; int length = 0;
        while (length < buffer.Length)
        {
            int read = await stream.ReadAsync(buffer.AsMemory(length), ct).ConfigureAwait(false);
            if (read == 0) break;
            length += read;
        }
        if (length > 4096) return default;
        try
        {
            using var json = JsonDocument.Parse(buffer.AsMemory(0, length));
            if (json.RootElement.ValueKind != JsonValueKind.Object) return default;
            ScimError scim = ScimError.None;
            if (json.RootElement.TryGetProperty("scimType", out var scimType) && scimType.ValueKind == JsonValueKind.String)
                scim = scimType.GetString() switch { "invalidFilter" => ScimError.InvalidFilter, "tooMany" => ScimError.TooMany,
                    "uniqueness" => ScimError.Uniqueness, "mutability" => ScimError.Mutability, "invalidSyntax" => ScimError.InvalidSyntax,
                    "invalidPath" => ScimError.InvalidPath, "noTarget" => ScimError.NoTarget, "invalidValue" => ScimError.InvalidValue,
                    "sensitive" => ScimError.Sensitive, _ => ScimError.Unknown };
            if (!json.RootElement.TryGetProperty("error", out var error) || error.ValueKind != JsonValueKind.String) return (OAuthError.Unknown, scim);
            var oauth = error.GetString() switch
            {
                "authorization_pending" => OAuthError.AuthorizationPending, "slow_down" => OAuthError.SlowDown,
                "access_denied" => OAuthError.AccessDenied, "expired_token" => OAuthError.ExpiredToken,
                "invalid_grant" => OAuthError.InvalidGrant, "invalid_client" => OAuthError.InvalidClient, "invalid_target" => OAuthError.InvalidTarget,
                "invalid_request" => OAuthError.InvalidRequest, "invalid_scope" => OAuthError.InvalidScope,
                "use_dpop_nonce" => OAuthError.UseDpopNonce, "invalid_dpop_proof" => OAuthError.InvalidDpopProof, "invalid_token" => OAuthError.InvalidToken, _ => OAuthError.Unknown
            };
            return (oauth, scim);
        }
        catch (JsonException) { return default; }
    }

    /// <summary>Checks support and the final host gates before initiating a browser or host workflow that sends its own HTTP requests.</summary>
    public ValueTask EnsureEnabledAsync(string feature, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(feature);
        return EnsureEnabledAsync(feature.StartsWith("KeycloakSdk.Protocols.Oidc", StringComparison.Ordinal) && feature != "KeycloakSdk.Protocols.Oidc"
            ? [feature, "KeycloakSdk.Protocols.Oidc"] : [feature], "", cancellationToken);
    }
    /// <summary>Checks a workflow's dependent capabilities against one host snapshot when the snapshot gate is used.</summary>
    public ValueTask EnsureEnabledAsync(IEnumerable<string> features, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(features); var required = features.ToArray();
        if (required.Length == 0 || required.Any(string.IsNullOrWhiteSpace)) throw new ArgumentException("Explicit nonempty capability keys are required.", nameof(features));
        if (required.Any(f => f.StartsWith("KeycloakSdk.Protocols.Oidc", StringComparison.Ordinal))) required = [.. required, "KeycloakSdk.Protocols.Oidc"];
        return EnsureEnabledAsync(required.Distinct(StringComparer.Ordinal).ToArray(), "", cancellationToken);
    }
    private async ValueTask EnsureEnabledAsync(string[] features, string path, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (mutualTls) features = [.. features, "KeycloakSdk.Protocols.MutualTls"];
        foreach (string feature in features) supportPolicy?.EnsureAllowed(feature, path);
        if (!await HostAllowsAsync(features, ct).ConfigureAwait(false)) throw new InvalidOperationException("Protocol disabled by host: " + features[0]);
        ct.ThrowIfCancellationRequested();
    }
    private async ValueTask<bool> HostAllowsAsync(string[] features, CancellationToken ct)
    {
        if (gate is null) return true;
        if (gate is KeycloakFeatureSnapshotGate snapshot)
        {
            var flags = snapshot.Capture();
            return flags.GetValueOrDefault("KeycloakSdk.Protocols") && features.All(f => flags.GetValueOrDefault(f));
        }
        if (!await gate.IsEnabledAsync("KeycloakSdk.Protocols", ct).ConfigureAwait(false)) return false;
        foreach (string feature in features) if (!await gate.IsEnabledAsync(feature, ct).ConfigureAwait(false)) return false;
        return true;
    }
}
