using System.Collections.Specialized;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Schemas;
using Microsoft.IdentityModel.Tokens.Saml2;

namespace Keycloak.Admin.Sdk.Hosting;

public sealed partial class KeycloakSamlServiceProvider
{
    /// <summary>Signed SP-initiated logout for an independently verified SAML session. Clear the host's local session as part of its own logout flow.</summary>
    public async Task<SamlLogoutTransaction> StartLogoutAsync(VerifiedSamlSession session, CancellationToken cancellationToken = default)
        => await StartLogoutAsync(session, SamlBrowserBinding.Redirect, cancellationToken).ConfigureAwait(false);
    public async Task<SamlLogoutTransaction> StartLogoutAsync(VerifiedSamlSession session, SamlBrowserBinding requestBinding, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);
        if (requestBinding is not (SamlBrowserBinding.Redirect or SamlBrowserBinding.Post)) throw new ArgumentOutOfRangeException(nameof(requestBinding));
        if (session.Issuer != transport.Issuer.AbsoluteUri || session.ServiceProvider != entityId) throw new ArgumentException("SAML logout session belongs to another issuer or service provider.", nameof(session));
        await transport.EnsureEnabledAsync("KeycloakSdk.Protocols.Saml", cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(session.SessionIndex)) throw new ArgumentException("The verified session must identify its Keycloak session index.", nameof(session));
        if (signing is null) throw new InvalidOperationException("SAML logout initiation requires a host-owned signing certificate.");
        var name = new Saml2NameIdentifier(session.NameId) { NameQualifier = session.NameQualifier, SPNameQualifier = session.ServiceProviderNameQualifier };
        if (session.NameIdFormat is not null) name.Format = new(session.NameIdFormat);
        var request = new Saml2LogoutRequest(Configuration()) { NameId = name, SessionIndex = session.SessionIndex, NotOnOrAfter = DateTimeOffset.UtcNow.AddMinutes(5) };
        string state = NewState();
        if (requestBinding == SamlBrowserBinding.Post)
        {
            var post = new Saml2PostBinding { RelayState = state }; post.Bind(request); cancellationToken.ThrowIfCancellationRequested();
            return new(this, request.IdAsString, state, request.Destination, new Dictionary<string, string> { ["SAMLRequest"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(post.XmlDocument.OuterXml)), ["RelayState"] = state }.AsReadOnly());
        }
        var binding = new Saml2RedirectBinding { RelayState = state }; binding.Bind(request);
        cancellationToken.ThrowIfCancellationRequested(); return new(this, request.IdAsString, state, binding.RedirectLocation);
    }
    internal async Task CompleteLogoutAsync(string requestId, string state, DateTimeOffset expiry, Action consume, Uri actualCallback, string? postResponse, string? postState, CancellationToken ct)
    {
        await transport.EnsureEnabledAsync("KeycloakSdk.Protocols.Saml", ct).ConfigureAwait(false);
        if (!actualCallback.IsAbsoluteUri || actualCallback.Fragment.Length != 0 || actualCallback.GetLeftPart(UriPartial.Path) != logoutCallback.AbsoluteUri || DateTimeOffset.UtcNow >= expiry)
            throw new InvalidDataException("Unexpected or expired SAML logout callback.");
        try
        {
            var response = new Saml2LogoutResponse(Configuration());
            if (postResponse is not null)
            {
                if (actualCallback != logoutCallback || !Fixed(state, postState!)) throw new InvalidDataException("SAML logout state mismatch.");
                consume(); ValidateXmlResponse(postResponse);
                new Saml2PostBinding().Unbind(new ITfoxtec.Identity.Saml2.Http.HttpRequest { Method = "POST", Form = new NameValueCollection { ["SAMLResponse"] = postResponse, ["RelayState"] = postState } }, response);
            }
            else
            {
                var query = ReadQuery(actualCallback.Query);
                if (!Fixed(state, query["RelayState"]!)) throw new InvalidDataException("SAML logout state mismatch.");
                consume(); await ValidateDeflateAsync(query["SAMLResponse"]!, ct).ConfigureAwait(false);
                new Saml2RedirectBinding().Unbind(new ITfoxtec.Identity.Saml2.Http.HttpRequest { Method = "GET", Query = query, QueryString = actualCallback.Query }, response);
            }
            ct.ThrowIfCancellationRequested();
            ValidateLogoutResponse(response, requestId);
            string key = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes("saml-logout\n" + transport.Issuer.AbsoluteUri + "\n" + response.IdAsString)));
            if (!await replay.TryUseAsync(key, DateTimeOffset.UtcNow.AddMinutes(6), ct).ConfigureAwait(false)) throw new InvalidDataException("Replayed SAML logout response.");
        }
        catch (Exception error) when (error is not (OperationCanceledException or InvalidDataException)) { throw new InvalidDataException("SAML logout response validation failed."); }
    }
    internal void ValidateLogoutResponse(Saml2LogoutResponse response, string requestId)
    {
        ValidateMessageId(response.IdAsString);
        if (response.Status != Saml2StatusCodes.Success || response.Destination != logoutCallback || response.InResponseTo?.Value != requestId || response.Issuer != transport.Issuer.AbsoluteUri
            || response.IssueInstant < DateTimeOffset.UtcNow.AddMinutes(-5) || response.IssueInstant > DateTimeOffset.UtcNow.AddSeconds(30))
            throw new InvalidDataException("Invalid SAML logout response correlation or lifetime.");
    }
    internal static NameValueCollection ReadQuery(string query)
    {
        if (query.Length > 350000) throw new InvalidDataException("SAML redirect exceeds its bound.");
        var result = new NameValueCollection(StringComparer.Ordinal);
        foreach (string pair in query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            string[] parts = pair.Split('=', 2); string key = Uri.UnescapeDataString(parts[0].Replace('+', ' '));
            if (parts.Length != 2 || result.AllKeys.Contains(key, StringComparer.Ordinal)) throw new InvalidDataException("Duplicate or malformed SAML redirect field.");
            result.Add(key, Uri.UnescapeDataString(parts[1].Replace('+', ' ')));
        }
        return result;
    }
    private static async Task ValidateDeflateAsync(string value, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        using var input = new MemoryStream(Convert.FromBase64String(value)); using var deflate = new DeflateStream(input, CompressionMode.Decompress); using var buffer = new MemoryStream();
        var block = new byte[8192]; int read;
        while ((read = await deflate.ReadAsync(block, ct).ConfigureAwait(false)) != 0)
        { if (buffer.Length + read > 262144) throw new InvalidDataException("SAML redirect expands beyond its bound."); buffer.Write(block, 0, read); }
        ReadXml(Encoding.UTF8.GetString(buffer.ToArray()));
    }
}

/// <summary>A browser-bound, one-time logout transaction. Never recreate it from an incoming message or RelayState.</summary>
public sealed class SamlLogoutTransaction
{
    private readonly KeycloakSamlServiceProvider provider; private readonly string id, state; private readonly DateTimeOffset expiry = DateTimeOffset.UtcNow.AddMinutes(5); private int consumed;
    public Uri AuthorizationUri { get; }
    public IReadOnlyDictionary<string, string>? FormFields { get; }
    internal SamlLogoutTransaction(KeycloakSamlServiceProvider provider, string id, string state, Uri uri, IReadOnlyDictionary<string, string>? formFields = null) { this.provider = provider; this.id = id; this.state = state; AuthorizationUri = uri; FormFields = formFields; }
    public Task CompleteRedirectAsync(Uri callback, CancellationToken cancellationToken = default) => provider.CompleteLogoutAsync(id, state, expiry, Consume, callback, null, null, cancellationToken);
    public Task CompletePostAsync(Uri callback, string encodedResponse, string relayState, CancellationToken cancellationToken = default)
        => provider.CompleteLogoutAsync(id, state, expiry, Consume, callback, encodedResponse, relayState, cancellationToken);
    private void Consume() { if (Interlocked.Exchange(ref consumed, 1) != 0) throw new InvalidDataException("SAML logout transaction already consumed."); }
}
