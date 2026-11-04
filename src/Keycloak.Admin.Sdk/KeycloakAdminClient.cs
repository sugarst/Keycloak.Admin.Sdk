using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

namespace Keycloak.Admin.Sdk;

/// <summary>Thread-safe admin transport. The caller owns HttpClient and the token provider.</summary>
public sealed partial class KeycloakAdminClient
{
    private readonly HttpClient httpClient;
    private readonly Uri server;
    private readonly IAccessTokenProvider? tokenProvider;

    public KeycloakAdminClient(HttpClient httpClient, Uri server, IAccessTokenProvider? tokenProvider = null)
    {
        this.httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        this.server = AdminUri.Base(server);
        this.tokenProvider = tokenProvider;
    }

    /// <summary>Escape hatch for source-only or vendor endpoints. Consumes/disposes content; buffers the response. No retries.</summary>
    public async Task<AdminResponse> SendAsync(HttpMethod method, string path, IEnumerable<KeyValuePair<string, string?>>? query = null, HttpContent? content = null, CancellationToken cancellationToken = default)
    {
        using var request = new HttpRequestMessage(method, AdminUri.Combine(server, path, query ?? [])) { Content = content };
        cancellationToken.ThrowIfCancellationRequested();
        if (tokenProvider is not null)
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", await tokenProvider.GetAccessTokenAsync(cancellationToken).ConfigureAwait(false));
        using var response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode) throw new KeycloakAdminException(response.StatusCode, method.Method);
        var bytes = await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
        var headers = response.Headers.Concat(response.Content.Headers).ToDictionary(h => h.Key, h => h.Value.ToArray(), StringComparer.OrdinalIgnoreCase);
        return new AdminResponse(response.StatusCode, response.Headers.Location, headers, bytes);
    }

    /// <summary>Uses explicit JSON metadata, including caller-supplied source-generated contracts, for Native AOT.</summary>
    public async Task<AdminResponse<T>> SendJsonAsync<T>(HttpMethod method, string path, IEnumerable<KeyValuePair<string, string?>>? query, HttpContent? content, JsonTypeInfo<T> responseType, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(responseType);
        var response = await SendAsync(method, path, query, content, cancellationToken).ConfigureAwait(false);
        try
        {
            var value = response.Content.IsEmpty ? default : JsonSerializer.Deserialize(response.Content.Span, responseType);
            return new AdminResponse<T>(response, value);
        }
        catch (JsonException error) { throw new KeycloakResponseFormatException(response.StatusCode, error); }
    }

    /// <summary>Streams a download without buffering. Caller must dispose the returned response. Consumes/disposes request content.</summary>
    public async Task<AdminStreamResponse> OpenStreamAsync(HttpMethod method, string path, IEnumerable<KeyValuePair<string, string?>>? query = null, HttpContent? content = null, CancellationToken cancellationToken = default)
    {
        using var request = new HttpRequestMessage(method, AdminUri.Combine(server, path, query ?? [])) { Content = content };
        cancellationToken.ThrowIfCancellationRequested();
        if (tokenProvider is not null)
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", await tokenProvider.GetAccessTokenAsync(cancellationToken).ConfigureAwait(false));
        var response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        try
        {
            if (!response.IsSuccessStatusCode) throw new KeycloakAdminException(response.StatusCode, method.Method);
            return new AdminStreamResponse(response, await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false));
        }
        catch { response.Dispose(); throw; }
    }
}
