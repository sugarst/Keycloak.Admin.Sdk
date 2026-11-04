using System.Net;

namespace Keycloak.Admin.Sdk;

public record AdminEndpoint(string Method, string Path, string Operation, string SourceFile, int SourceLine);

/// <summary>Buffered successful response. Location is not followed automatically.</summary>
public class AdminResponse(HttpStatusCode statusCode, Uri? location, IReadOnlyDictionary<string, string[]> headers, byte[] content)
{
    protected AdminResponse(AdminResponse response) : this(response.StatusCode, response.Location, response.Headers, [])
    {
        Content = response.Content;
    }
    public HttpStatusCode StatusCode { get; } = statusCode;
    public Uri? Location { get; } = location;
    public IReadOnlyDictionary<string, string[]> Headers { get; } = headers;
    public ReadOnlyMemory<byte> Content { get; } = content;
}

public sealed class AdminResponse<T>(AdminResponse response, T? body) : AdminResponse(response)
{
    public T? Body { get; } = body;
    public bool HasBody => !Content.IsEmpty;
}

/// <summary>HTTP failure. Response bodies and query values are deliberately excluded.</summary>
public sealed class KeycloakAdminException(HttpStatusCode statusCode, string method) : HttpRequestException($"Keycloak Admin API returned {(int)statusCode} for {method}.", null, statusCode)
{
    public string Method { get; } = method;
}

public sealed class KeycloakResponseFormatException(HttpStatusCode statusCode, Exception inner) : Exception("Keycloak returned an unexpected JSON response.", inner)
{
    public HttpStatusCode StatusCode { get; } = statusCode;
}
