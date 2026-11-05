using System.Text.Json.Serialization.Metadata;

namespace Keycloak.Admin.Sdk;

/// <summary>
/// Admin API client contract. Resource interfaces are generated from the pinned contracts.
/// The caller or DI container owns HttpClient and the token provider.
/// Requests consume and dispose their content; callers dispose returned stream responses.
/// </summary>
public partial interface IKeycloakAdminClient
{
    /// <summary>Buffers a raw response. Unauthorized replay requires the explicit-options overload.</summary>
    Task<AdminResponse> SendAsync(HttpMethod method, string path,
        IEnumerable<KeyValuePair<string, string?>>? query = null, HttpContent? content = null,
        CancellationToken cancellationToken = default);

    /// <summary>Buffers a raw response with explicit unauthorized replay permission.</summary>
    Task<AdminResponse> SendAsync(KeycloakRequestOptions options, HttpMethod method, string path,
        IEnumerable<KeyValuePair<string, string?>>? query = null, HttpContent? content = null,
        CancellationToken cancellationToken = default);

    /// <summary>Deserializes a buffered response using explicit JSON metadata for Native AOT.</summary>
    Task<AdminResponse<T>> SendJsonAsync<T>(HttpMethod method, string path,
        IEnumerable<KeyValuePair<string, string?>>? query, HttpContent? content, JsonTypeInfo<T> responseType,
        CancellationToken cancellationToken = default);

    /// <summary>Deserializes a response using explicit JSON metadata and unauthorized replay permission.</summary>
    Task<AdminResponse<T>> SendJsonAsync<T>(KeycloakRequestOptions options, HttpMethod method, string path,
        IEnumerable<KeyValuePair<string, string?>>? query, HttpContent? content, JsonTypeInfo<T> responseType,
        CancellationToken cancellationToken = default);

    /// <summary>Returns an unbuffered response that the caller must dispose.</summary>
    Task<AdminStreamResponse> OpenStreamAsync(HttpMethod method, string path,
        IEnumerable<KeyValuePair<string, string?>>? query = null, HttpContent? content = null,
        CancellationToken cancellationToken = default);

    /// <summary>Returns an unbuffered response with explicit unauthorized replay permission.</summary>
    Task<AdminStreamResponse> OpenStreamAsync(KeycloakRequestOptions options, HttpMethod method, string path,
        IEnumerable<KeyValuePair<string, string?>>? query = null, HttpContent? content = null,
        CancellationToken cancellationToken = default);
}
