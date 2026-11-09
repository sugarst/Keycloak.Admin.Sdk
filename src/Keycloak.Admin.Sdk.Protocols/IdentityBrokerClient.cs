using System.Security.Cryptography;
using System.Text;

namespace Keycloak.Admin.Sdk.Protocols;

/// <summary>Retrieves upstream provider credentials. The response is not a locally verified identity.
/// Provider consent, storage and allowed-client configuration are enforced by Keycloak.</summary>
public sealed class IdentityBrokerClient(ProtocolTransport transport)
{
    private readonly ProtocolTransport transport = transport ?? throw new ArgumentNullException(nameof(transport));
    private const string Feature = "KeycloakSdk.Protocols.IdentityBrokering";
    /// <summary>Deprecated v1 API requiring the user's broker read-token role.</summary>
    public Task<ProtocolResponse> GetTokenLegacyAsync(string provider, string userAccessToken, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userAccessToken);
        return transport.SendAsync(HttpMethod.Get, Path(provider), "Broker.TokenV1", "KeycloakSdk.Protocols.IdentityBrokeringLegacy", null, userAccessToken, null, null, cancellationToken);
    }
    /// <summary>v2 authenticates the confidential requesting client separately from the user's token.</summary>
    public Task<ProtocolResponse> GetTokenAsync(string provider, OAuthClientAuthentication client, string userAccessToken, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(client); ArgumentException.ThrowIfNullOrWhiteSpace(userAccessToken);
        return transport.SendAsync(HttpMethod.Post, Path(provider), "Broker.TokenV2", Feature, null, null, null, async (request, ct) =>
        {
            var form = new Dictionary<string, string> { ["token"] = userAccessToken };
            await client.ApplyAsync(request, form, ct).ConfigureAwait(false);
            request.Content = new FormUrlEncodedContent(form);
        }, cancellationToken, client.RequiredFeatures);
    }
    /// <summary>Deprecated, server-disabled-by-default link initiation. Bind the random nonce and callback to the current authenticated browser session.
    /// Prefer an OIDC transaction with Action="idp_link:provider".</summary>
    public Uri CreateLegacyLinkUri(string provider, string clientId, string authenticatedSessionId, Uri redirect, string nonce)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId); ArgumentException.ThrowIfNullOrWhiteSpace(authenticatedSessionId);
        ArgumentException.ThrowIfNullOrWhiteSpace(nonce); DpopProofKey.ValidateTarget(redirect);
        string hash = Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(nonce + authenticatedSessionId + clientId + provider))).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        return new(transport.Target("broker/" + ProtocolTransport.Segment(provider) + "/link").AbsoluteUri + "?" + ProtocolTransport.Query(new Dictionary<string, string>
        { ["client_id"] = clientId, ["redirect_uri"] = redirect.AbsoluteUri, ["nonce"] = nonce, ["hash"] = hash }));
    }
    private static string Path(string provider) => "broker/" + ProtocolTransport.Segment(provider) + "/token";
}
