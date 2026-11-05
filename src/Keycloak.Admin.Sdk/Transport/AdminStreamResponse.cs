using System.Net;

namespace Keycloak.Admin.Sdk;

/// <summary>Owns the HTTP response and content stream. Dispose when finished reading.</summary>
public sealed class AdminStreamResponse : IDisposable
{
    private readonly HttpResponseMessage response;
    internal AdminStreamResponse(HttpResponseMessage response, Stream content)
    {
        this.response = response;
        Content = content;
    }
    public HttpStatusCode StatusCode => response.StatusCode;
    public Uri? Location => response.Headers.Location;
    public Stream Content { get; }
    public void Dispose() => response.Dispose();
}
