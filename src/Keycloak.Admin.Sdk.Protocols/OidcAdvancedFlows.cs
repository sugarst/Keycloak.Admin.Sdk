using System.Text.Json;

namespace Keycloak.Admin.Sdk.Protocols;

public sealed partial class OidcClient
{
    /// <summary>Delegation requires both subject and actor tokens. Authentication is still performed as the requesting client.
    /// Subject consent, may_act matching and FGAP v2 authorization are enforced by Keycloak, never inferred by the SDK.</summary>
    public Task<ProtocolResponse> ExchangeDelegatedAsync(OAuthClientAuthentication client, string subjectToken, string actorToken,
        string? audience = null, string? scope = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(subjectToken); ArgumentException.ThrowIfNullOrWhiteSpace(actorToken);
        var form = new Dictionary<string, string> { ["grant_type"] = "urn:ietf:params:oauth:grant-type:token-exchange",
            ["subject_token"] = subjectToken, ["subject_token_type"] = "urn:ietf:params:oauth:token-type:access_token",
            ["actor_token"] = actorToken, ["actor_token_type"] = "urn:ietf:params:oauth:token-type:access_token",
            ["requested_token_type"] = "urn:ietf:params:oauth:token-type:access_token" };
        if (audience is not null) form.Add("audience", audience);
        return GrantAsync(client, form, scope, "Oidc.DelegatedExchange", cancellationToken);
    }

    /// <summary>Deprecated legacy exchange, deliberately separate from standard and delegated exchange.</summary>
    public Task<ProtocolResponse> ExchangeLegacyAsync(OAuthClientAuthentication client, string subjectToken, string? subjectIssuer = null,
        string? requestedIssuer = null, string? requestedSubject = null, string? audience = null, CancellationToken cancellationToken = default,
        TokenExchangeRequestedTokenType? requestedTokenType = null, TokenExchangeSubjectTokenType subjectTokenType = TokenExchangeSubjectTokenType.AccessToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(subjectToken);
        var form = new Dictionary<string, string> { ["grant_type"] = "urn:ietf:params:oauth:grant-type:token-exchange",
            ["subject_token"] = subjectToken,
            ["subject_token_type"] = subjectTokenType switch
            {
                TokenExchangeSubjectTokenType.AccessToken => "urn:ietf:params:oauth:token-type:access_token",
                TokenExchangeSubjectTokenType.IdToken => "urn:ietf:params:oauth:token-type:id_token",
                TokenExchangeSubjectTokenType.Jwt => "urn:ietf:params:oauth:token-type:jwt",
                _ => throw new ArgumentOutOfRangeException(nameof(subjectTokenType))
            } };
        if (subjectIssuer is not null) { ArgumentException.ThrowIfNullOrWhiteSpace(subjectIssuer); form.Add("subject_issuer", subjectIssuer); }
        if (requestedIssuer is not null) form.Add("requested_issuer", requestedIssuer);
        if (requestedSubject is not null) form.Add("requested_subject", requestedSubject);
        if (audience is not null) form.Add("audience", audience);
        if (requestedTokenType is not null) form.Add("requested_token_type", RequestedTokenType(requestedTokenType.Value, legacy: true));
        return FormAsync(client, TokenPath, form, null, "Oidc.LegacyExchange", cancellationToken,
            additionalFeatures: requestedTokenType == TokenExchangeRequestedTokenType.Saml2 ? ["KeycloakSdk.Protocols.Saml"] : []);
    }

    /// <summary>Deprecated direct impersonation. Requires a confidential client explicitly granted FGAP v1 impersonation permission by the server.</summary>
    public Task<ProtocolResponse> ImpersonateLegacyAsync(OAuthClientAuthentication client, string requestedSubject, string? audience = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(requestedSubject);
        var form = new Dictionary<string, string> { ["grant_type"] = "urn:ietf:params:oauth:grant-type:token-exchange", ["requested_subject"] = requestedSubject };
        if (audience is not null) form.Add("audience", audience);
        return GrantAsync(client, form, null, "Oidc.LegacyExchange", cancellationToken);
    }

    private static string RequestedTokenType(TokenExchangeRequestedTokenType type, bool legacy = false) => type switch
    {
        TokenExchangeRequestedTokenType.AccessToken => "urn:ietf:params:oauth:token-type:access_token",
        TokenExchangeRequestedTokenType.IdToken when !legacy => "urn:ietf:params:oauth:token-type:id_token",
        TokenExchangeRequestedTokenType.RefreshToken => "urn:ietf:params:oauth:token-type:refresh_token",
        TokenExchangeRequestedTokenType.Saml2 when legacy => "urn:ietf:params:oauth:token-type:saml2",
        _ => throw new ArgumentOutOfRangeException(nameof(type))
    };

    /// <summary>Pushes an authorization request to the pinned realm. Use the returned request_uri only at this realm's authorization endpoint.</summary>
    public Task<ProtocolResponse> PushAuthorizationAsync(OAuthClientAuthentication client, Uri authorizationUri, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(client); ArgumentNullException.ThrowIfNull(authorizationUri);
        if (authorizationUri.GetLeftPart(UriPartial.Path) != transport.Target("protocol/openid-connect/auth").AbsoluteUri || authorizationUri.Fragment.Length != 0)
            throw new ArgumentException("Authorization request must target the pinned realm.", nameof(authorizationUri));
        var form = new Dictionary<string, string>(StringComparer.Ordinal);
        var resources = new List<KeyValuePair<string, string>>();
        foreach (string pair in authorizationUri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            string[] parts = pair.Split('=', 2);
            if (parts.Length != 2) throw new ArgumentException("Invalid authorization request parameter.", nameof(authorizationUri));
            string name = Uri.UnescapeDataString(parts[0].Replace('+', ' ')), value = Uri.UnescapeDataString(parts[1].Replace('+', ' '));
            if (name == "resource") { resources.Add(new(name, value)); continue; }
            if (!form.TryAdd(name, value))
                throw new ArgumentException("Duplicate or invalid authorization request parameter.", nameof(authorizationUri));
        }
        if (!form.Remove("client_id", out string? id) || id != client.ClientId) throw new ArgumentException("Authorization client mismatch.", nameof(authorizationUri));
        return FormAsync(client, "protocol/openid-connect/ext/par/request", form, null, "Oidc.PushedAuthorization", cancellationToken,
            OidcAuthorizationOptions.ResourceParameters(resources.Select(p => new Uri(p.Value))).ToArray());
    }

    public Uri CreatePushedAuthorizationUri(string clientId, ProtocolResponse pushed)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);
        JsonElement json = pushed.Json ?? throw new InvalidDataException("Empty PAR response.");
        string? requestUri = json.GetProperty("request_uri").GetString();
        if (string.IsNullOrWhiteSpace(requestUri) || json.GetProperty("expires_in").GetInt32() <= 0) throw new InvalidDataException("Invalid PAR response.");
        return new(transport.Target("protocol/openid-connect/auth").AbsoluteUri + "?" + ProtocolTransport.Query(new Dictionary<string, string>
        { ["client_id"] = clientId, ["request_uri"] = requestUri }));
    }

    /// <summary>Refresh-token logout. The host must also clear its own session and handle back-channel logout independently.</summary>
    public Task<ProtocolResponse> LogoutAsync(OAuthClientAuthentication client, string refreshToken, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(refreshToken);
        return FormAsync(client, "protocol/openid-connect/logout", new() { ["refresh_token"] = refreshToken }, null, "Oidc.Logout", cancellationToken);
    }

    public Uri CreateLogoutUri(string clientId, string idTokenHint, Uri postLogoutRedirectUri, string state)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId); ArgumentException.ThrowIfNullOrWhiteSpace(idTokenHint);
        ArgumentException.ThrowIfNullOrWhiteSpace(state); ValidateRedirect(postLogoutRedirectUri);
        return new(transport.Target("protocol/openid-connect/logout").AbsoluteUri + "?" + ProtocolTransport.Query(new Dictionary<string, string>
        { ["client_id"] = clientId, ["id_token_hint"] = idTokenHint, ["post_logout_redirect_uri"] = postLogoutRedirectUri.AbsoluteUri, ["state"] = state }));
    }
}
