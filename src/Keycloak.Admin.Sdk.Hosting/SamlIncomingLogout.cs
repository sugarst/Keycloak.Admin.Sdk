using System.Collections.Specialized;
using System.Collections.Frozen;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Schemas;

namespace Keycloak.Admin.Sdk.Hosting;

/// <summary>The host atomically revokes matching issuer/SP/NameID/session-index sessions and records ReplayKey through ExpiresAt.
/// Duplicate deliveries complete successfully; storage failure must leave the notification retryable. Distributed hosts require a shared durable store.</summary>
public interface ISamlLogoutSessionStore
{
    ValueTask RevokeOnceAsync(SamlLogoutNotification notification, CancellationToken cancellationToken = default);
}

public sealed class SamlLogoutNotification
{
    public string Issuer { get; }
    public string ServiceProvider { get; }
    public string NameId { get; }
    public string? NameIdFormat { get; }
    public string SessionIndex { get; }
    public string ReplayKey { get; }
    public DateTimeOffset ExpiresAt { get; }
    internal SamlLogoutNotification(string issuer, string sp, string nameId, string? format, string sessionIndex, string requestId, DateTimeOffset expires)
    { Issuer = issuer; ServiceProvider = sp; NameId = nameId; NameIdFormat = format; SessionIndex = sessionIndex; ExpiresAt = expires;
        ReplayKey = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes("saml-logout-request\n" + issuer + "\n" + sp + "\n" + requestId))); }
}

public sealed class SamlLogoutReply
{
    public Uri Destination { get; }
    public IReadOnlyDictionary<string, string>? FormFields { get; }
    internal SamlLogoutReply(Uri destination, IReadOnlyDictionary<string, string>? fields) { Destination = destination; FormFields = fields; }
}

public sealed partial class KeycloakSamlServiceProvider
{
    public Task<SamlLogoutReply> HandleLogoutPostAsync(Uri actualCallback, string request, string? relayState, ISamlLogoutSessionStore sessions, CancellationToken cancellationToken = default)
        => HandleIncomingLogoutAsync(actualCallback, request, relayState, null, sessions, cancellationToken);

    public Task<SamlLogoutReply> HandleLogoutRedirectAsync(Uri actualCallback, ISamlLogoutSessionStore sessions, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(actualCallback); cancellationToken.ThrowIfCancellationRequested();
        if (!actualCallback.IsAbsoluteUri || actualCallback.Fragment.Length != 0 || actualCallback.GetLeftPart(UriPartial.Path) != logoutCallback.AbsoluteUri) throw new InvalidDataException("Unexpected SAML logout destination.");
        var query = ReadQuery(actualCallback.Query);
        return HandleIncomingLogoutAsync(logoutCallback, query["SAMLRequest"]!, query["RelayState"], actualCallback, sessions, cancellationToken);
    }

    public async Task<string> HandleLogoutSoapAsync(Uri actualCallback, string soapEnvelope, ISamlLogoutSessionStore sessions, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested(); XNamespace soap = "http://schemas.xmlsoap.org/soap/envelope/";
        var document = ReadXml(soapEnvelope);
        if (document.Root?.Name != soap + "Envelope" || document.Descendants(soap + "Body").Count() != 1) throw new InvalidDataException("Invalid SAML logout SOAP envelope.");
        var request = document.Root.Element(soap + "Body")?.Elements(Protocol + "LogoutRequest").SingleOrDefault() ?? throw new InvalidDataException("Expected one SOAP logout request.");
        var reply = await HandleLogoutPostAsync(actualCallback, Convert.ToBase64String(Encoding.UTF8.GetBytes(request.ToString(SaveOptions.DisableFormatting))), null, sessions, cancellationToken).ConfigureAwait(false);
        var response = ReadXml(Encoding.UTF8.GetString(Convert.FromBase64String(reply.FormFields!["SAMLResponse"])));
        return new XDocument(new XElement(soap + "Envelope", new XElement(soap + "Body", response.Root))).ToString(SaveOptions.DisableFormatting);
    }

    private async Task<SamlLogoutReply> HandleIncomingLogoutAsync(Uri actualCallback, string encoded, string? relayState, Uri? redirect, ISamlLogoutSessionStore sessions, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(sessions); ct.ThrowIfCancellationRequested();
        await EnsureSamlLoginAsync([], ct).ConfigureAwait(false);
        if (actualCallback != logoutCallback || relayState?.Length > 1024) throw new InvalidDataException("Unexpected SAML logout callback or state.");
        if (signing is null) throw new InvalidOperationException("A signed SAML logout response requires a host-owned signing certificate.");
        Saml2LogoutRequest request; SamlLogoutNotification notification;
        try
        {
            request = new Saml2LogoutRequest(Configuration());
            if (redirect is null)
            {
                ValidateXmlResponse(encoded);
                new Saml2PostBinding().Unbind(new ITfoxtec.Identity.Saml2.Http.HttpRequest { Method = "POST", Form = new NameValueCollection { ["SAMLRequest"] = encoded } }, request);
            }
            else
            {
                await ValidateDeflateAsync(encoded, ct).ConfigureAwait(false);
                new Saml2RedirectBinding().Unbind(new ITfoxtec.Identity.Saml2.Http.HttpRequest { Method = "GET", Query = ReadQuery(redirect.Query), QueryString = redirect.Query }, request);
            }
            var now = DateTimeOffset.UtcNow; var xml = ReadXml(request.XmlDocument.OuterXml);
            // ITfoxtec 4.21 does not populate NotOnOrAfter while reading. Keycloak may omit this optional attribute;
            // in that case bound the request by its verified IssueInstant, never by the library constructor's default.
            DateTimeOffset expires = xml.Root?.Attribute("NotOnOrAfter") is { } expiryAttribute ? System.Xml.XmlConvert.ToDateTimeOffset(expiryAttribute.Value) : request.IssueInstant.AddMinutes(5);
            if (request.Destination != logoutCallback || request.Issuer != transport.Issuer.AbsoluteUri || string.IsNullOrWhiteSpace(request.IdAsString)
                || string.IsNullOrWhiteSpace(request.NameId?.Value) || string.IsNullOrWhiteSpace(request.SessionIndex) || request.IssueInstant < now.AddMinutes(-5) || request.IssueInstant > now.AddSeconds(30)
                || expires <= now || expires > now.AddMinutes(10) || xml.Root?.Name != Protocol + "LogoutRequest" || xml.Root.Elements(Protocol + "SessionIndex").Count() != 1
                || xml.Root.Elements(Assertion + "NameID").Count() != 1 || xml.Root.Elements(Assertion + "Issuer").Count() != 1)
                throw new InvalidDataException("Invalid SAML logout identity session correlation or lifetime.");
            notification = new(transport.Issuer.AbsoluteUri, entityId, request.NameId.Value, request.NameId.Format?.OriginalString, request.SessionIndex, request.IdAsString, expires.AddSeconds(30));
        }
        catch (Exception error) when (error is not (OperationCanceledException or InvalidDataException)) { throw new InvalidDataException("SAML logout request validation failed."); }
        await sessions.RevokeOnceAsync(notification, ct).ConfigureAwait(false);
        await EnsureSamlLoginAsync([], ct).ConfigureAwait(false);
        var response = new Saml2LogoutResponse(Configuration()) { Destination = new(transport.Issuer.AbsoluteUri + "/protocol/saml"), InResponseTo = request.Id, Status = Saml2StatusCodes.Success };
        if (redirect is not null)
        {
            var binding = new Saml2RedirectBinding { RelayState = relayState }; binding.Bind(response);
            return new(binding.RedirectLocation, null);
        }
        var post = new Saml2PostBinding { RelayState = relayState }; post.Bind(response);
        var fields = new Dictionary<string, string> { ["SAMLResponse"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(post.XmlDocument.OuterXml)) };
        if (relayState is not null) fields.Add("RelayState", relayState);
        return new(response.Destination, fields.ToFrozenDictionary(StringComparer.Ordinal));
    }
}
