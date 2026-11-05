using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

namespace Keycloak.Admin.Sdk;

/// <summary>Thread-safe admin transport. The caller owns HttpClient and the token provider.</summary>
public sealed partial class KeycloakAdminClient(HttpClient httpClient, Uri server, IAccessTokenProvider? tokenProvider, KeycloakAdminClientOptions options)
{
    private readonly HttpClient httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
    private readonly Uri server = AdminUri.Base(server);
    private readonly IAccessTokenProvider? tokenProvider = tokenProvider;
    private readonly bool recoverUnauthorized = (options ?? throw new ArgumentNullException(nameof(options))).EnableUnauthorizedRecovery;
    private readonly IKeycloakAdminRequestPolicy? requestPolicy = options.RequestPolicy;

    public KeycloakAdminClient(HttpClient httpClient, Uri server, IAccessTokenProvider? tokenProvider = null)
        : this(httpClient, server, tokenProvider, new KeycloakAdminClientOptions()) { }

    /// <summary>Escape hatch for source-only or vendor endpoints. Consumes/disposes content; buffers the response. No retries.</summary>
    public Task<AdminResponse> SendAsync(HttpMethod method, string path, IEnumerable<KeyValuePair<string, string?>>? query = null, HttpContent? content = null, CancellationToken cancellationToken = default)
        => SendBufferedAsync(null, false, method, path, query, content, cancellationToken);

    /// <summary>Raw request with explicit replay permission. Only bodyless admin GET/HEAD can be replayed, and client recovery must also be enabled.</summary>
    public Task<AdminResponse> SendAsync(KeycloakRequestOptions options, HttpMethod method, string path, IEnumerable<KeyValuePair<string, string?>>? query = null, HttpContent? content = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        return SendBufferedAsync(null, options.AllowUnauthorizedReplay, method, path, query, content, cancellationToken);
    }

    internal Task<AdminResponse> SendOperationAsync(string operation, HttpMethod method, string path, IEnumerable<KeyValuePair<string, string?>>? query, HttpContent? content, CancellationToken cancellationToken)
        => SendBufferedAsync(operation, true, method, path, query, content, cancellationToken);

    private async Task<AdminResponse> SendBufferedAsync(string? operation, bool allowReplay, HttpMethod method, string path, IEnumerable<KeyValuePair<string, string?>>? query, HttpContent? content, CancellationToken cancellationToken)
    {
        using var response = await SendCoreAsync(operation, allowReplay, method, path, query, content, cancellationToken).ConfigureAwait(false);
        var bytes = await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
        var headers = response.Headers.Concat(response.Content.Headers).ToDictionary(h => h.Key, h => h.Value.ToArray(), StringComparer.OrdinalIgnoreCase);
        return new AdminResponse(response.StatusCode, response.Headers.Location, headers, bytes);
    }

    /// <summary>Uses explicit JSON metadata, including caller-supplied source-generated contracts, for Native AOT.</summary>
    public Task<AdminResponse<T>> SendJsonAsync<T>(HttpMethod method, string path, IEnumerable<KeyValuePair<string, string?>>? query, HttpContent? content, JsonTypeInfo<T> responseType, CancellationToken cancellationToken = default)
        => SendJsonCoreAsync<T>(null, false, method, path, query, content, responseType, cancellationToken);

    public Task<AdminResponse<T>> SendJsonAsync<T>(KeycloakRequestOptions options, HttpMethod method, string path, IEnumerable<KeyValuePair<string, string?>>? query, HttpContent? content, JsonTypeInfo<T> responseType, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        return SendJsonCoreAsync<T>(null, options.AllowUnauthorizedReplay, method, path, query, content, responseType, cancellationToken);
    }

    internal Task<AdminResponse<T>> SendJsonOperationAsync<T>(string operation, HttpMethod method, string path, IEnumerable<KeyValuePair<string, string?>>? query, HttpContent? content, JsonTypeInfo<T> responseType, CancellationToken cancellationToken)
        => SendJsonCoreAsync<T>(operation, true, method, path, query, content, responseType, cancellationToken);

    private async Task<AdminResponse<T>> SendJsonCoreAsync<T>(string? operation, bool allowReplay, HttpMethod method, string path, IEnumerable<KeyValuePair<string, string?>>? query, HttpContent? content, JsonTypeInfo<T> responseType, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(responseType);
        var response = await SendBufferedAsync(operation, allowReplay, method, path, query, content, cancellationToken).ConfigureAwait(false);
        try
        {
            var value = response.Content.IsEmpty ? default : JsonSerializer.Deserialize(response.Content.Span, responseType);
            return new AdminResponse<T>(response, value);
        }
        catch (JsonException error) { throw new KeycloakResponseFormatException(response.StatusCode, error); }
    }

    /// <summary>Streams a download without buffering. Caller must dispose the returned response. Consumes/disposes request content.</summary>
    public Task<AdminStreamResponse> OpenStreamAsync(HttpMethod method, string path, IEnumerable<KeyValuePair<string, string?>>? query = null, HttpContent? content = null, CancellationToken cancellationToken = default)
        => OpenStreamCoreAsync(false, method, path, query, content, cancellationToken);

    public Task<AdminStreamResponse> OpenStreamAsync(KeycloakRequestOptions options, HttpMethod method, string path, IEnumerable<KeyValuePair<string, string?>>? query = null, HttpContent? content = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        return OpenStreamCoreAsync(options.AllowUnauthorizedReplay, method, path, query, content, cancellationToken);
    }

    private async Task<AdminStreamResponse> OpenStreamCoreAsync(bool allowReplay, HttpMethod method, string path, IEnumerable<KeyValuePair<string, string?>>? query, HttpContent? content, CancellationToken cancellationToken)
    {
        var response = await SendCoreAsync(null, allowReplay, method, path, query, content, cancellationToken).ConfigureAwait(false);
        try
        {
            return new AdminStreamResponse(response, await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false));
        }
        catch { response.Dispose(); throw; }
    }

    private async Task<HttpResponseMessage> SendCoreAsync(string? operation, bool allowReplay, HttpMethod method, string path, IEnumerable<KeyValuePair<string, string?>>? query, HttpContent? content, CancellationToken cancellationToken)
    {
        Uri? target = null;
        for (int attempt = 0; ; attempt++)
        {
            using var request = new HttpRequestMessage { Method = method, Content = content };
            cancellationToken.ThrowIfCancellationRequested();
            // Materialize the URI only once: caller query enumerables need not be repeatable.
            target ??= AdminUri.Combine(server, path, query ?? []);
            request.RequestUri = target;
            if (attempt == 0 && requestPolicy is not null)
                await requestPolicy.EnsureAllowedAsync(method, target, operation, cancellationToken).ConfigureAwait(false);
            string? token = null;
            if (tokenProvider is not null)
            {
                token = await tokenProvider.GetAccessTokenAsync(cancellationToken).ConfigureAwait(false);
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            }
            var response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
            if (response.IsSuccessStatusCode) return response;
            var error = new KeycloakAdminException(response.StatusCode, method.Method, KeycloakFailureStage.AdminApi, operation);
            response.Dispose(); // Never read untrusted error bodies, including on the first 401.
            if (recoverUnauthorized && error.StatusCode == System.Net.HttpStatusCode.Unauthorized && token is not null
                && path.StartsWith("/admin/", StringComparison.Ordinal) && tokenProvider is IRefreshableAccessTokenProvider refreshable)
            {
                await refreshable.InvalidateAsync(token, cancellationToken).ConfigureAwait(false);
                if (attempt == 0 && allowReplay && content is null && (method == HttpMethod.Get || method == HttpMethod.Head)) continue;
            }
            throw error;
        }
    }
}
