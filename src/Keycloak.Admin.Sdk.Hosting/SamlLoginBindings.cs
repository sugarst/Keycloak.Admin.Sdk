using System.Collections.Frozen;
using System.Text;
using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Schemas;

namespace Keycloak.Admin.Sdk.Hosting;

public enum SamlBrowserBinding { Redirect, Post, Artifact }

public sealed class SamlLoginOptions
{
    public SamlBrowserBinding RequestBinding { get; init; } = SamlBrowserBinding.Redirect;
    public SamlBrowserBinding ResponseBinding { get; init; } = SamlBrowserBinding.Post;
    public bool ForceAuthentication { get; init; }
    public bool Passive { get; init; }
    public IReadOnlyList<Uri> AuthenticationContexts { get; init; } = [];
}

public sealed partial class KeycloakSamlServiceProvider
{
    public async Task<SamlLoginTransaction> StartLoginAsync(SamlLoginOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options); cancellationToken.ThrowIfCancellationRequested();
        if (options.RequestBinding is not (SamlBrowserBinding.Redirect or SamlBrowserBinding.Post) || !Enum.IsDefined(options.ResponseBinding)) throw new ArgumentOutOfRangeException(nameof(options));
        if (options.Passive && options.ForceAuthentication) throw new ArgumentException("A SAML authentication request cannot be both passive and forced.", nameof(options));
        string[] contexts = (options.AuthenticationContexts ?? throw new ArgumentNullException(nameof(options))).Select(c => c is not null && c.IsAbsoluteUri ? c.AbsoluteUri : throw new ArgumentException("Authentication contexts must be absolute URIs.", nameof(options))).ToArray();
        await EnsureSamlLoginAsync(contexts, cancellationToken).ConfigureAwait(false);
        var request = new Saml2AuthnRequest(Configuration()) { AssertionConsumerServiceUrl = callback, ProtocolBinding = new(BindingUri(options.ResponseBinding)), ForceAuthn = options.ForceAuthentication, IsPassive = options.Passive };
        if (contexts.Length != 0) request.RequestedAuthnContext = new RequestedAuthnContext { Comparison = AuthnContextComparisonTypes.Exact, AuthnContextClassRef = contexts };
        string state = NewState(); Uri destination; IReadOnlyDictionary<string, string>? fields = null;
        if (options.RequestBinding == SamlBrowserBinding.Post)
        {
            var binding = new Saml2PostBinding { RelayState = state }; binding.Bind(request); destination = request.Destination;
            fields = new Dictionary<string, string> { ["SAMLRequest"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(binding.XmlDocument.OuterXml)), ["RelayState"] = state }.ToFrozenDictionary(StringComparer.Ordinal);
        }
        else { var binding = new Saml2RedirectBinding { RelayState = state }; binding.Bind(request); destination = binding.RedirectLocation; }
        cancellationToken.ThrowIfCancellationRequested();
        return new(this, request.IdAsString, state, destination, contexts, options.ResponseBinding, fields);
    }

    /// <summary>Initiates an IdP-initiated URL while retaining a protected, browser-bound one-use transaction.
    /// The host must never construct this transaction from an incoming SAMLResponse or RelayState.</summary>
    public async Task<SamlLoginTransaction> StartIdpInitiatedLoginAsync(string clientUrlAlias, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientUrlAlias);
        if (clientUrlAlias.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('-' or '_'))) throw new ArgumentException("An explicit SAML client URL alias is required.", nameof(clientUrlAlias));
        await EnsureSamlLoginAsync([], cancellationToken).ConfigureAwait(false);
        string state = NewState();
        return new(this, null, state, new(transport.Issuer.AbsoluteUri + "/protocol/saml/clients/" + Uri.EscapeDataString(clientUrlAlias) + "?RelayState=" + state));
    }
    private ValueTask EnsureSamlLoginAsync(string[] contexts, CancellationToken ct)
        => transport.EnsureEnabledAsync(contexts.Length == 0 ? ["KeycloakSdk.Protocols.Saml"] : new[] { "KeycloakSdk.Protocols.Saml", "KeycloakSdk.Protocols.SamlStepUp" }, ct);
    internal static string BindingUri(SamlBrowserBinding binding) => binding switch
    {
        SamlBrowserBinding.Redirect => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
        SamlBrowserBinding.Post => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
        SamlBrowserBinding.Artifact => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact",
        _ => throw new ArgumentOutOfRangeException(nameof(binding))
    };

    internal Task<VerifiedSamlSession> CompleteRedirectLoginAsync(string? requestId, string state, DateTimeOffset expiry, string[] expectedContexts,
        Action consume, Uri actualCallback, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(actualCallback); ct.ThrowIfCancellationRequested();
        if (!actualCallback.IsAbsoluteUri || actualCallback.GetLeftPart(UriPartial.Path) != callback.AbsoluteUri || actualCallback.Fragment.Length != 0) throw new InvalidDataException("Unexpected SAML redirect destination.");
        var fields = ReadQuery(actualCallback.Query);
        return CompleteAsync(requestId, state, expiry, expectedContexts, consume, callback, fields["SAMLResponse"]!, fields["RelayState"]!, ct, actualCallback);
    }
}
