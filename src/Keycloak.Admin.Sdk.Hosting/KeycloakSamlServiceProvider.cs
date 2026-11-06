using System.Collections.Specialized;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Security;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Schemas;
using Keycloak.Admin.Sdk.Protocols;
using Microsoft.IdentityModel.Tokens.Saml2;

namespace Keycloak.Admin.Sdk.Hosting;

/// <summary>Managed SAML SP using explicit, trusted Keycloak signing certificates. The caller owns all certificate lifetimes.
/// Bind every transaction to its initiating browser session; never recreate a transaction from an incoming RelayState.</summary>
public sealed partial class KeycloakSamlServiceProvider
{
    private readonly ProtocolTransport transport;
    private readonly string entityId;
    private readonly Uri callback;
    private readonly Uri logoutCallback;
    private readonly X509Certificate2[] trustedSigning, decrypting;
    private readonly X509Certificate2? signing;
    private readonly ISecurityTokenReplayStore replay;
    internal static readonly XNamespace Assertion = "urn:oasis:names:tc:SAML:2.0:assertion";
    internal static readonly XNamespace Protocol = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static readonly XNamespace Metadata = "urn:oasis:names:tc:SAML:2.0:metadata";
    public KeycloakSamlServiceProvider(ProtocolTransport transport, string entityId, Uri assertionConsumerService, IEnumerable<X509Certificate2> trustedSigningCertificates,
        ISecurityTokenReplayStore replayStore, X509Certificate2? signingCertificate = null, IEnumerable<X509Certificate2>? decryptionCertificates = null, Uri? singleLogoutService = null)
    {
        if (!RuntimeFeature.IsDynamicCodeSupported) throw new PlatformNotSupportedException("SAML host integration is verified independently for Managed only.");
        this.transport = transport ?? throw new ArgumentNullException(nameof(transport));
        ArgumentException.ThrowIfNullOrWhiteSpace(entityId);
        if (!Uri.TryCreate(entityId, UriKind.Absolute, out _)) throw new ArgumentException("An absolute SAML entity URI is required.", nameof(entityId));
        this.entityId = entityId;
        ValidateCallback(assertionConsumerService); callback = assertionConsumerService;
        logoutCallback = singleLogoutService ?? callback; ValidateCallback(logoutCallback);
        ArgumentNullException.ThrowIfNull(trustedSigningCertificates); trustedSigning = trustedSigningCertificates.ToArray();
        if (trustedSigning.Length == 0 || trustedSigning.Any(c => c is null)) throw new ArgumentException("Explicit trusted IdP signing certificates are required.", nameof(trustedSigningCertificates));
        replay = replayStore ?? throw new ArgumentNullException(nameof(replayStore)); signing = signingCertificate;
        decrypting = (decryptionCertificates ?? []).ToArray();
        if (signing is not null && !signing.HasPrivateKey || decrypting.Any(c => c is null || !c.HasPrivateKey)) throw new ArgumentException("Signing and decryption certificates require host-owned private keys.");
    }
    private Saml2Configuration Configuration()
    {
        var certificates = trustedSigning.Where(c => c.NotBefore.ToUniversalTime() <= DateTime.UtcNow && c.NotAfter.ToUniversalTime() > DateTime.UtcNow).ToList();
        if (certificates.Count == 0) throw new InvalidDataException("No currently valid trusted SAML signing certificate.");
        return new()
        {
        Issuer = entityId, AllowedIssuer = transport.Issuer.AbsoluteUri, SingleSignOnDestination = new(transport.Issuer.AbsoluteUri + "/protocol/saml"),
        SingleLogoutDestination = new(transport.Issuer.AbsoluteUri + "/protocol/saml"),
        AllowedAudienceUris = [entityId], AudienceRestricted = true,
        SignatureValidationCertificates = certificates,
        // Keys are explicitly trusted, including Keycloak's realm-generated self-signed signing certificates.
        CertificateValidationMode = X509CertificateValidationMode.None, RevocationMode = X509RevocationMode.NoCheck,
        SigningCertificate = signing, SignAuthnRequest = signing is not null, DecryptionCertificates = [.. decrypting],
        SignatureValidationAlgorithms = ["http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
            "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1", "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384", "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"],
        SaveBootstrapContext = false
        };
    }
    public async Task<SamlLoginTransaction> StartLoginAsync(bool forceAuthentication = false, IEnumerable<Uri>? authenticationContexts = null, CancellationToken cancellationToken = default)
    {
        return await StartLoginAsync(new SamlLoginOptions { ForceAuthentication = forceAuthentication, AuthenticationContexts = (authenticationContexts ?? []).ToArray() }, cancellationToken).ConfigureAwait(false);
    }
    internal async Task<VerifiedSamlSession> CompleteAsync(string? requestId, string state, DateTimeOffset expiry, string[] expectedContexts, Action consume, Uri actualCallback, string responseValue, string relayState, CancellationToken ct, Uri? redirectResponse = null)
    {
        await EnsureSamlLoginAsync(expectedContexts, ct).ConfigureAwait(false);
        if (actualCallback != callback || DateTimeOffset.UtcNow >= expiry || !Fixed(state, relayState)) throw new InvalidDataException("Unexpected or expired SAML callback.");
        consume();
        try
        {
            var response = new Saml2AuthnResponse(Configuration());
            if (redirectResponse is null)
            {
                ValidateXmlResponse(responseValue);
                new Saml2PostBinding().Unbind(new ITfoxtec.Identity.Saml2.Http.HttpRequest { Method = "POST", Form = new NameValueCollection { ["SAMLResponse"] = responseValue, ["RelayState"] = relayState } }, response);
            }
            else
            {
                await ValidateDeflateAsync(responseValue, ct).ConfigureAwait(false);
                new Saml2RedirectBinding().Unbind(new ITfoxtec.Identity.Saml2.Http.HttpRequest { Method = "GET", Query = ReadQuery(redirectResponse.Query), QueryString = redirectResponse.Query }, response);
            }
            ct.ThrowIfCancellationRequested();
            if (response.Status != Saml2StatusCodes.Success || response.Destination != callback || response.InResponseTo?.Value != requestId)
                throw new InvalidDataException("Invalid SAML response correlation.");
            var assertion = response.Saml2SecurityToken.Assertion;
            if (assertion.Issuer.Value != transport.Issuer.AbsoluteUri || assertion.Subject.NameId is null || string.IsNullOrWhiteSpace(assertion.Subject.NameId.Value)
                || assertion.Conditions?.NotOnOrAfter is not { } notAfter || notAfter <= DateTime.UtcNow || notAfter > DateTime.UtcNow.AddDays(1))
                throw new InvalidDataException("Invalid SAML assertion identity or lifetime.");
            bool confirmed = assertion.Subject.SubjectConfirmations.Any(c => c.Method.OriginalString == "urn:oasis:names:tc:SAML:2.0:cm:bearer" && c.SubjectConfirmationData is { } data
                && data.Recipient == callback && data.InResponseTo?.Value == requestId && data.NotOnOrAfter > DateTime.UtcNow);
            if (!confirmed) throw new InvalidDataException("Invalid SAML bearer subject confirmation.");
            if (assertion.Conditions.AudienceRestrictions.Count == 0 || assertion.Conditions.AudienceRestrictions.Any(r => !r.Audiences.Any(a => a == entityId)))
                throw new InvalidDataException("SAML audience must exactly match this service provider.");
            var authentication = assertion.Statements.OfType<Saml2AuthenticationStatement>().Single();
            string? authenticationContext = authentication.AuthenticationContext.ClassReference?.OriginalString;
            if (expectedContexts.Length != 0 && !expectedContexts.Contains(authenticationContext, StringComparer.Ordinal)) throw new InvalidDataException("SAML authentication assurance requirement was not met.");
            var responseXml = ReadXml(response.XmlDocument.OuterXml);
            var assertionElements = responseXml.Descendants(Assertion + "Assertion").ToArray();
            bool directAssertion = assertionElements.Length == 1 && (assertionElements[0].Parent == responseXml.Root
                || (assertionElements[0].Parent?.Name == Assertion + "EncryptedAssertion" && assertionElements[0].Parent!.Parent == responseXml.Root));
            if (responseXml.Root?.Name != Protocol + "Response" || responseXml.Root.Element(Assertion + "Issuer")?.Value != transport.Issuer.AbsoluteUri
                || !directAssertion) throw new InvalidDataException("Unexpected SAML signed envelope.");
            string key = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes("saml\n" + transport.Issuer.AbsoluteUri + "\n" + assertion.Id.Value)));
            if (!await replay.TryUseAsync(key, new DateTimeOffset(DateTime.SpecifyKind(notAfter, DateTimeKind.Utc)), ct).ConfigureAwait(false)) throw new InvalidDataException("Replayed SAML assertion.");
            return new(response.ClaimsIdentity, assertion.Subject.NameId, response.SessionIndex, transport.Issuer.AbsoluteUri, entityId, authenticationContext);
        }
        catch (Exception error) when (error is not (OperationCanceledException or InvalidDataException))
        { throw new InvalidDataException("SAML authentication response validation failed."); }
    }
    public string CreateMetadata()
    {
        var descriptor = new XElement(Metadata + "SPSSODescriptor", new XAttribute("protocolSupportEnumeration", Protocol.NamespaceName),
            new XAttribute("AuthnRequestsSigned", signing is not null), new XAttribute("WantAssertionsSigned", true),
            new XElement(Metadata + "SingleLogoutService", new XAttribute("Binding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"), new XAttribute("Location", logoutCallback.AbsoluteUri)),
            new XElement(Metadata + "SingleLogoutService", new XAttribute("Binding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"), new XAttribute("Location", logoutCallback.AbsoluteUri)),
            new XElement(Metadata + "AssertionConsumerService", new XAttribute("Binding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"), new XAttribute("Location", callback.AbsoluteUri), new XAttribute("index", 0), new XAttribute("isDefault", true)));
        descriptor.Add(new XElement(Metadata + "AssertionConsumerService", new XAttribute("Binding", BindingUri(SamlBrowserBinding.Redirect)), new XAttribute("Location", callback.AbsoluteUri), new XAttribute("index", 1)),
            new XElement(Metadata + "AssertionConsumerService", new XAttribute("Binding", BindingUri(SamlBrowserBinding.Artifact)), new XAttribute("Location", callback.AbsoluteUri), new XAttribute("index", 2)));
        XNamespace ds = "http://www.w3.org/2000/09/xmldsig#";
        foreach (var (certificate, use) in (signing is null ? Enumerable.Empty<(X509Certificate2, string)>() : new[] { (signing, "signing") }).Concat(decrypting.Select(c => (c, "encryption"))))
            descriptor.AddFirst(new XElement(Metadata + "KeyDescriptor", new XAttribute("use", use), new XElement(ds + "KeyInfo", new XElement(ds + "X509Data", new XElement(ds + "X509Certificate", Convert.ToBase64String(certificate.RawData))))));
        return new XDocument(new XElement(Metadata + "EntityDescriptor", new XAttribute("entityID", entityId), descriptor)).ToString(SaveOptions.DisableFormatting);
    }
    internal static string NewState() => Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(24));
    private static bool Fixed(string expected, string actual) => actual is not null && CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(expected), Encoding.UTF8.GetBytes(actual));
    private static void ValidateCallback(Uri value)
    { ArgumentNullException.ThrowIfNull(value); if (!value.IsAbsoluteUri || value.Scheme is not ("https" or "http") || value.UserInfo.Length != 0 || value.Query.Length != 0 || value.Fragment.Length != 0) throw new ArgumentException("An HTTP(S) callback without credentials, query or fragment is required.", nameof(value)); }
    private static void ValidateXmlResponse(string value)
    { ArgumentException.ThrowIfNullOrWhiteSpace(value); if (value.Length > 350000) throw new InvalidDataException("SAML response exceeds its bound."); ReadXml(Encoding.UTF8.GetString(Convert.FromBase64String(value))); }
    private static XDocument ReadXml(string value)
    {
        using var reader = XmlReader.Create(new StringReader(value), new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 262144 });
        return XDocument.Load(reader, LoadOptions.PreserveWhitespace);
    }
}

public sealed class SamlLoginTransaction
{
    private readonly KeycloakSamlServiceProvider provider; private readonly string? id; private readonly string state; private readonly DateTimeOffset expires = DateTimeOffset.UtcNow.AddMinutes(5); private int consumed;
    private readonly string[] expectedContexts;
    private readonly SamlBrowserBinding responseBinding;
    public Uri AuthorizationUri { get; }
    public IReadOnlyDictionary<string, string>? FormFields { get; }
    internal SamlLoginTransaction(KeycloakSamlServiceProvider provider, string? id, string state, Uri uri, string[]? expectedContexts = null,
        SamlBrowserBinding responseBinding = SamlBrowserBinding.Post, IReadOnlyDictionary<string, string>? formFields = null)
    { this.provider = provider; this.id = id; this.state = state; AuthorizationUri = uri; this.expectedContexts = expectedContexts ?? []; this.responseBinding = responseBinding; FormFields = formFields; }
    public Task<VerifiedSamlSession> CompleteAsync(Uri actualCallback, string encodedResponse, string relayState, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (responseBinding != SamlBrowserBinding.Post) throw new InvalidDataException("SAML response binding does not match its initiating transaction.");
        return provider.CompleteAsync(id, state, expires, expectedContexts, Consume, actualCallback, encodedResponse, relayState, cancellationToken);
    }
    public Task<VerifiedSamlSession> CompleteRedirectAsync(Uri actualCallback, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (responseBinding != SamlBrowserBinding.Redirect) throw new InvalidDataException("SAML response binding does not match its initiating transaction.");
        return provider.CompleteRedirectLoginAsync(id, state, expires, expectedContexts, Consume, actualCallback, cancellationToken);
    }
    public Task<VerifiedSamlSession> CompleteArtifactAsync(Uri actualCallback, string artifact, string relayState, HttpClient http, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (responseBinding != SamlBrowserBinding.Artifact) throw new InvalidDataException("SAML response binding does not match its initiating transaction.");
        return provider.CompleteArtifactLoginAsync(id, state, expires, expectedContexts, Consume, actualCallback, artifact, relayState, http, cancellationToken);
    }
    private void Consume() { if (Interlocked.Exchange(ref consumed, 1) != 0) throw new InvalidDataException("SAML transaction already consumed."); }
}

public sealed class VerifiedSamlSession
{
    public ClaimsPrincipal Principal { get; }
    public string NameId { get; }
    public string? NameIdFormat { get; }
    public string? NameQualifier { get; }
    public string? ServiceProviderNameQualifier { get; }
    public string? SessionIndex { get; }
    public string Issuer { get; }
    public string ServiceProvider { get; }
    public string? AuthenticationContext { get; }
    internal VerifiedSamlSession(ClaimsIdentity identity, Saml2NameIdentifier nameId, string? sessionIndex, string issuer, string serviceProvider, string? authenticationContext = null)
    { Principal = new(identity); NameId = nameId.Value; NameIdFormat = nameId.Format?.OriginalString; NameQualifier = nameId.NameQualifier; ServiceProviderNameQualifier = nameId.SPNameQualifier; SessionIndex = sessionIndex; Issuer = issuer; ServiceProvider = serviceProvider; AuthenticationContext = authenticationContext; }
}
