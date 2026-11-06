using System.Security.Cryptography.X509Certificates;
using System.Xml;
using System.Xml.Linq;
using Keycloak.Admin.Sdk.Protocols;

namespace Keycloak.Admin.Sdk.Hosting;

/// <summary>Loads signing trust only from the pinned realm metadata over the host's trusted HTTPS connection.
/// The caller owns and disposes returned public certificates. Refresh metadata explicitly when realm keys rotate.</summary>
public static class KeycloakSamlMetadata
{
    public static async Task<IReadOnlyList<X509Certificate2>> LoadSigningCertificatesAsync(HttpClient http, ProtocolTransport transport, bool allowLoopbackHttp = false, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(http); ArgumentNullException.ThrowIfNull(transport);
        var issuer = transport.Issuer;
        if (issuer.Scheme != "https" && !(allowLoopbackHttp && issuer.IsLoopback)) throw new ArgumentException("Trusted HTTPS metadata is required.");
        if (http.DefaultRequestHeaders.Contains("Authorization") || http.DefaultRequestHeaders.Contains("Cookie")) throw new ArgumentException("Use a dedicated credential-free metadata client.", nameof(http));
        await transport.EnsureEnabledAsync("KeycloakSdk.Protocols.Saml", cancellationToken).ConfigureAwait(false);
        using var request = new HttpRequestMessage(HttpMethod.Get, issuer.AbsoluteUri + "/protocol/saml/descriptor");
        using var reply = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        if (!reply.IsSuccessStatusCode) throw new HttpRequestException("Pinned SAML metadata request failed.", null, reply.StatusCode);
        using var stream = await reply.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var buffer = new MemoryStream(); var block = new byte[8192];
        int read;
        while ((read = await stream.ReadAsync(block, cancellationToken).ConfigureAwait(false)) != 0)
        {
            if (buffer.Length + read > 262144) throw new InvalidDataException("SAML metadata exceeds its bound.");
            buffer.Write(block, 0, read);
        }
        buffer.Position = 0;
        using var reader = XmlReader.Create(buffer, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 262144 });
        var xml = XDocument.Load(reader); XNamespace metadata = "urn:oasis:names:tc:SAML:2.0:metadata", ds = "http://www.w3.org/2000/09/xmldsig#";
        var root = xml.Root;
        if (root?.Name != metadata + "EntityDescriptor" || (string?)root.Attribute("entityID") != issuer.AbsoluteUri) throw new InvalidDataException("SAML metadata issuer mismatch.");
        var descriptor = root.Element(metadata + "IDPSSODescriptor") ?? throw new InvalidDataException("Missing SAML IdP descriptor.");
        var endpoints = descriptor.Elements(metadata + "SingleSignOnService").ToArray();
        if (!endpoints.Any(e => (string?)e.Attribute("Binding") == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                && (string?)e.Attribute("Location") == issuer.AbsoluteUri + "/protocol/saml")) throw new InvalidDataException("SAML metadata does not advertise the pinned redirect endpoint.");
        var certificates = new List<X509Certificate2>();
        try
        {
            foreach (var key in descriptor.Elements(metadata + "KeyDescriptor").Where(k => k.Attribute("use") is null || (string?)k.Attribute("use") == "signing"))
                foreach (var value in key.Descendants(ds + "X509Certificate")) certificates.Add(X509CertificateLoader.LoadCertificate(Convert.FromBase64String(value.Value)));
            if (certificates.Count == 0) throw new InvalidDataException("No pinned IdP signing certificates.");
            cancellationToken.ThrowIfCancellationRequested(); return certificates.AsReadOnly();
        }
        catch { foreach (var certificate in certificates) certificate.Dispose(); throw; }
    }
}
