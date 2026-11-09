using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Xml.Linq;

namespace Keycloak.Admin.Sdk.Hosting;

public sealed partial class KeycloakSamlServiceProvider
{
    /// <summary>Explicit SAML ECP compatibility flow. Reads per-call credentials only after capability and host gates.
    /// Prefer the browser flow for interactive authentication. The host configures the dedicated HTTP handler with redirects disabled.</summary>
    public async Task<VerifiedSamlSession> AuthenticateEcpAsync(HttpClient http, Func<CancellationToken, ValueTask<NetworkCredential>> readCredentials,
        bool allowLoopbackHttp = false, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(http); ArgumentNullException.ThrowIfNull(readCredentials); cancellationToken.ThrowIfCancellationRequested();
        var issuer = transport.Issuer;
        if (issuer.Scheme != "https" && !(allowLoopbackHttp && issuer.IsLoopback)) throw new ArgumentException("ECP credentials require trusted HTTPS.");
        if (http.DefaultRequestHeaders.Contains("Authorization") || http.DefaultRequestHeaders.Contains("Cookie")) throw new ArgumentException("Use a dedicated credential-free ECP client.", nameof(http));
        var transaction = await StartLoginAsync(new SamlLoginOptions { RequestBinding = SamlBrowserBinding.Post }, cancellationToken).ConfigureAwait(false);
        var requestXml = ReadXml(Encoding.UTF8.GetString(Convert.FromBase64String(transaction.FormFields!["SAMLRequest"])));
        XNamespace soap = "http://schemas.xmlsoap.org/soap/envelope/", ecp = "urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp";
        var envelope = new XDocument(new XElement(soap + "Envelope", new XAttribute(XNamespace.Xmlns + "soap", soap), new XElement(soap + "Body", requestXml.Root)));
        var endpoint = new Uri(issuer.AbsoluteUri + "/protocol/saml");
        await EnsureSamlLoginAsync([], cancellationToken).ConfigureAwait(false);
        var credentials = await readCredentials(cancellationToken).ConfigureAwait(false);
        ArgumentNullException.ThrowIfNull(credentials); ArgumentException.ThrowIfNullOrWhiteSpace(credentials.UserName); ArgumentException.ThrowIfNullOrWhiteSpace(credentials.Password);
        if (credentials.UserName.Contains(':', StringComparison.Ordinal)) throw new ArgumentException("An ECP Basic username cannot contain a colon.", nameof(readCredentials));
        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint) { Content = new StringContent(envelope.ToString(SaveOptions.DisableFormatting), Encoding.UTF8, "text/xml") };
        request.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(credentials.UserName + ":" + credentials.Password)));
        using var bounded = new HttpClient(new ArtifactHttpHandler(http, endpoint, token => EnsureSamlLoginAsync([], token)));
        try
        {
            using var response = await bounded.SendAsync(request, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode) throw new InvalidDataException("SAML ECP authentication failed.");
            var document = ReadXml(await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false));
            var header = document.Root!.Element(soap + "Header")?.Elements(ecp + "Response").SingleOrDefault();
            if (header is null || (string?)header.Attribute("AssertionConsumerServiceURL") != callback.AbsoluteUri) throw new InvalidDataException("ECP assertion consumer endpoint mismatch.");
            // ArtifactHttpHandler has already required one direct SOAP Body, including for chunked responses.
            var inner = document.Root!.Element(soap + "Body")!.Elements(Protocol + "Response").SingleOrDefault() ?? throw new InvalidDataException("Expected one signed ECP authentication response.");
            return await transaction.CompleteAsync(callback, Convert.ToBase64String(Encoding.UTF8.GetBytes(inner.ToString(SaveOptions.DisableFormatting))), transaction.FormFields["RelayState"], cancellationToken).ConfigureAwait(false);
        }
        catch (Exception error) when (error is not (OperationCanceledException or InvalidDataException)) { throw new InvalidDataException("SAML ECP response validation failed."); }
    }
}
