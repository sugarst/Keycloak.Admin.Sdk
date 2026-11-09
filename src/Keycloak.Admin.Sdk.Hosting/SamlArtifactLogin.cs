using System.Collections.Specialized;
using System.Text;
using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Schemas;

namespace Keycloak.Admin.Sdk.Hosting;

public sealed partial class KeycloakSamlServiceProvider
{
    internal async Task<VerifiedSamlSession> CompleteArtifactLoginAsync(string? requestId, string state, DateTimeOffset expiry, string[] contexts, Action consume,
        Uri actualCallback, string artifact, string relayState, HttpClient http, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(http); ct.ThrowIfCancellationRequested();
        await EnsureSamlLoginAsync(contexts, ct).ConfigureAwait(false);
        if (actualCallback != callback || DateTimeOffset.UtcNow >= expiry || !Fixed(state, relayState)) throw new InvalidDataException("Unexpected or expired SAML artifact callback.");
        if (http.DefaultRequestHeaders.Contains("Authorization") || http.DefaultRequestHeaders.Contains("Cookie")) throw new ArgumentException("Use a dedicated credential-free artifact client.", nameof(http));
        if (signing is null) throw new InvalidOperationException("Artifact resolution requires a host-owned signing certificate.");
        try
        {
            if (artifact.Length > 128) throw new InvalidDataException("SAML artifact exceeds its bound.");
            byte[] bytes = Convert.FromBase64String(artifact);
            if (bytes.Length != 44 || bytes[0] != 0 || bytes[1] != 4) throw new InvalidDataException("Unexpected SAML artifact format.");
            var configuration = Configuration(); var endpoint = new Uri(transport.Issuer.AbsoluteUri + "/protocol/saml/resolve");
            configuration.ArtifactResolutionService = new Saml2IndexedEndpoint { Index = 0, Location = endpoint };
            var resolve = new Saml2ArtifactResolve(configuration);
            new Saml2ArtifactBinding().Unbind(new ITfoxtec.Identity.Saml2.Http.HttpRequest { Method = "GET", Query = new NameValueCollection { ["SAMLart"] = artifact, ["RelayState"] = relayState } }, resolve);
            consume();
            using var bounded = new HttpClient(new ArtifactHttpHandler(http, endpoint, token => EnsureSamlLoginAsync(contexts, token)));
            var response = await new Saml2SoapEnvelope().ResolveAsync(new FixedArtifactClient(bounded), resolve, new Saml2AuthnResponse(configuration), ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested();
            ValidateArtifactResponse(response, resolve.IdAsString);
            var document = ReadXml(response.XmlDocument.OuterXml);
            var inner = ArtifactAuthenticationResponse(document);
            return await CompleteAsync(requestId, state, expiry, contexts, () => { }, callback,
                Convert.ToBase64String(Encoding.UTF8.GetBytes(inner.ToString(System.Xml.Linq.SaveOptions.DisableFormatting))), relayState, ct).ConfigureAwait(false);
        }
        catch (Exception error) when (error is not (OperationCanceledException or InvalidDataException)) { throw new InvalidDataException("SAML artifact validation failed."); }
    }
    internal static System.Xml.Linq.XElement ArtifactAuthenticationResponse(System.Xml.Linq.XDocument document)
        => document.Root!.Elements(Protocol + "Response").SingleOrDefault() ?? throw new InvalidDataException("Expected one inner SAML response.");
    internal void ValidateArtifactResponse(Saml2ArtifactResponse response, string requestId)
    {
        if (response.Status != Saml2StatusCodes.Success || response.InResponseTo?.Value != requestId || response.Issuer != transport.Issuer.AbsoluteUri
            || response.IssueInstant < DateTimeOffset.UtcNow.AddMinutes(-5) || response.IssueInstant > DateTimeOffset.UtcNow.AddSeconds(30)) throw new InvalidDataException("Invalid artifact response correlation or lifetime.");
    }
    private sealed class FixedArtifactClient(HttpClient http) : IHttpClientFactory { public HttpClient CreateClient(string name) => http; }
    internal sealed class ArtifactHttpHandler(HttpClient http, Uri endpoint, Func<CancellationToken, ValueTask> gate) : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            if (request.Method != HttpMethod.Post || request.RequestUri != endpoint) throw new InvalidDataException("Artifact resolution must use the pinned realm endpoint.");
            await gate(ct).ConfigureAwait(false);
            using var forwarded = new HttpRequestMessage(request.Method, endpoint);
            foreach (var header in request.Headers) forwarded.Headers.TryAddWithoutValidation(header.Key, header.Value);
            if (request.Content is not null)
            {
                byte[] content = await request.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
                if (content.Length > 262144) throw new InvalidDataException("SAML SOAP request exceeds its bound.");
                forwarded.Content = new ByteArrayContent(content);
                foreach (var header in request.Content.Headers) forwarded.Content.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }
            using var response = await http.SendAsync(forwarded, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            using var stream = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false); using var buffer = new MemoryStream(); var block = new byte[8192];
            int read; while ((read = await stream.ReadAsync(block, ct).ConfigureAwait(false)) != 0)
            { if (buffer.Length + read > 262144) throw new InvalidDataException("SAML SOAP response exceeds its bound."); buffer.Write(block, 0, read); }
            string body = Encoding.UTF8.GetString(buffer.ToArray()); var document = ReadXml(body); System.Xml.Linq.XNamespace soap = "http://schemas.xmlsoap.org/soap/envelope/";
            if (document.Root!.Name != soap + "Envelope" || document.Root.Elements(soap + "Body").Count() != 1 || document.Descendants(soap + "Body").Count() != 1) throw new InvalidDataException("Invalid artifact SOAP envelope.");
            return new(response.StatusCode) { Content = new StringContent(body, Encoding.UTF8, "text/xml") };
        }
    }
}
