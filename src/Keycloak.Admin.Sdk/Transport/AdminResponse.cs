using System.Net;

namespace Keycloak.Admin.Sdk;

public record AdminEndpoint(string Method, string Path, string Operation, string SourceFile, int SourceLine);

/// <summary>Buffered HTTP response. Location is not followed automatically.</summary>
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

    internal static IReadOnlyDictionary<string, string[]> SnapshotHeaders(HttpResponseMessage response) =>
        response.Headers.NonValidated.Concat(response.Content.Headers.NonValidated)
            .GroupBy(header => header.Key, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.SelectMany(header => header.Value).ToArray(), StringComparer.OrdinalIgnoreCase);
}

public sealed class AdminResponse<T>(AdminResponse response, T? body) : AdminResponse(response)
{
    public T? Body { get; } = body;
    public bool HasBody => !Content.IsEmpty;
}

public enum KeycloakFailureStage { Unknown = 0, AdminApi, TokenEndpoint }

/// <summary>HTTP categories, not business reasons such as a duplicate username.</summary>
public enum KeycloakErrorKind { Unknown = 0, BadRequest, Unauthorized, Forbidden, NotFound, Conflict }

/// <summary>HTTP failure. Use Response to explicitly inspect diagnostics from the Admin API.</summary>
public sealed class KeycloakAdminException : HttpRequestException
{
    public KeycloakAdminException(HttpStatusCode statusCode, string method)
        : this(statusCode, method, KeycloakFailureStage.Unknown, null) { }

    internal KeycloakAdminException(HttpStatusCode statusCode, string method, KeycloakFailureStage stage, string? operation, AdminErrorResponse? response = null)
        : base(response?.GetDisplayMessage() ?? $"Keycloak Admin API returned {(int)statusCode} for {method}.", null, statusCode)
    {
        Method = method;
        Stage = stage;
        Operation = operation;
        Response = response;
        ErrorKind = statusCode switch
        {
            HttpStatusCode.BadRequest => KeycloakErrorKind.BadRequest,
            HttpStatusCode.Unauthorized => KeycloakErrorKind.Unauthorized,
            HttpStatusCode.Forbidden => KeycloakErrorKind.Forbidden,
            HttpStatusCode.NotFound => KeycloakErrorKind.NotFound,
            HttpStatusCode.Conflict => KeycloakErrorKind.Conflict,
            _ => KeycloakErrorKind.Unknown
        };
    }

    public string Method { get; }
    public KeycloakFailureStage Stage { get; }
    public KeycloakErrorKind ErrorKind { get; }
    public string? Operation { get; }
    /// <summary>The final Admin API response, when available. May contain sensitive data.</summary>
    public AdminErrorResponse? Response { get; }
    /// <summary>Reserved for verified safe codes. Currently always null.</summary>
    public string? ErrorCode => null;
}

public sealed class KeycloakResponseFormatException(HttpStatusCode statusCode, Exception inner) : Exception("Keycloak returned an unexpected JSON response.", inner)
{
    internal KeycloakResponseFormatException(AdminResponse response, Exception inner) : this(response.StatusCode, inner)
    {
        Response = response;
    }

    public HttpStatusCode StatusCode { get; } = statusCode;
    /// <summary>The buffered HTTP response that failed JSON deserialization. May contain sensitive data.</summary>
    public AdminResponse? Response { get; }
}
