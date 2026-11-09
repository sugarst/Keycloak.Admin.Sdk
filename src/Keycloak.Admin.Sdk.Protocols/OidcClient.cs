using System.Security.Cryptography;
using System.Text;

namespace Keycloak.Admin.Sdk.Protocols;

/// <summary>OIDC/OAuth requests. Raw grant responses are credentials, not verified identities.
/// Use OidcLoginTransaction with OidcTokenValidator for verified code callbacks, or host OIDC middleware for browser sessions.</summary>
public sealed partial class OidcClient(ProtocolTransport transport)
{
    private readonly ProtocolTransport transport = transport ?? throw new ArgumentNullException(nameof(transport));
    private const string Feature = "KeycloakSdk.Protocols.Oidc";
    private const string TokenPath = "protocol/openid-connect/token";
    public Uri Issuer => transport.Issuer;

    public Task<ProtocolResponse> DiscoverAsync(CancellationToken cancellationToken = default)
        => GetAsync(".well-known/openid-configuration", "Oidc.Discover", null, cancellationToken);
    public Task<ProtocolResponse> GetSigningKeysAsync(CancellationToken cancellationToken = default)
        => GetAsync("protocol/openid-connect/certs", "Oidc.SigningKeys", null, cancellationToken);
    public Task<ProtocolResponse> GetUserInfoAsync(string accessToken, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);
        return GetAsync("protocol/openid-connect/userinfo", "Oidc.UserInfo", accessToken, cancellationToken);
    }

    public Task<ProtocolResponse> ClientCredentialsAsync(OAuthClientAuthentication client, string? scope = null, CancellationToken cancellationToken = default, IEnumerable<Uri>? resources = null)
        => GrantAsync(client, new() { ["grant_type"] = "client_credentials" }, scope, "Oidc.ClientCredentials", cancellationToken, resources);
    /// <summary>Direct-grant compatibility API. Prefer authorization code + PKCE for interactive login; passwords/OTP are used only for this request.</summary>
    public Task<ProtocolResponse> PasswordGrantAsync(OAuthClientAuthentication client, string username, string password, string? otp = null, string? scope = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(username); ArgumentException.ThrowIfNullOrWhiteSpace(password);
        var form = new Dictionary<string, string> { ["grant_type"] = "password", ["username"] = username, ["password"] = password };
        if (otp is not null) { ArgumentException.ThrowIfNullOrWhiteSpace(otp); form.Add("totp", otp); }
        return GrantAsync(client, form, scope, "Oidc.PasswordGrant", cancellationToken);
    }
    public Task<ProtocolResponse> RedeemCodeAsync(OAuthClientAuthentication client, string code, Uri redirectUri, string verifier, CancellationToken cancellationToken = default, IEnumerable<Uri>? resources = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(code); ValidateRedirect(redirectUri); ValidateVerifier(verifier);
        return GrantAsync(client, new() { ["grant_type"] = "authorization_code", ["code"] = code,
            ["redirect_uri"] = redirectUri.AbsoluteUri, ["code_verifier"] = verifier }, null, "Oidc.RedeemCode", cancellationToken, resources);
    }
    public Task<ProtocolResponse> RefreshAsync(OAuthClientAuthentication client, string refreshToken, string? scope = null, CancellationToken cancellationToken = default, IEnumerable<Uri>? resources = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(refreshToken);
        return GrantAsync(client, new() { ["grant_type"] = "refresh_token", ["refresh_token"] = refreshToken }, scope, "Oidc.Refresh", cancellationToken, resources);
    }

    /// <summary>Each call performs one exchange. Server-side delegation consent, may_act and FGAP v2 must be configured separately.</summary>
    public Task<ProtocolResponse> ExchangeAsync(OAuthClientAuthentication client, string subjectToken, string? audience = null,
        string? scope = null, CancellationToken cancellationToken = default, TokenExchangeRequestedTokenType requestedTokenType = TokenExchangeRequestedTokenType.AccessToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(subjectToken);
        var form = new Dictionary<string, string> { ["grant_type"] = "urn:ietf:params:oauth:grant-type:token-exchange",
            ["subject_token"] = subjectToken, ["subject_token_type"] = "urn:ietf:params:oauth:token-type:access_token",
            ["requested_token_type"] = RequestedTokenType(requestedTokenType) };
        if (audience is not null) form.Add("audience", audience);
        return GrantAsync(client, form, scope, "Oidc.Exchange", cancellationToken);
    }
    public Task<ProtocolResponse> JwtGrantAsync(OAuthClientAuthentication client, string assertion, string? scope = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(assertion);
        return GrantAsync(client, new() { ["grant_type"] = "urn:ietf:params:oauth:grant-type:jwt-bearer", ["assertion"] = assertion }, scope,
            IsIdentityAssertion(assertion) ? "Oidc.IdentityAssertionGrant" : "Oidc.JwtGrant", cancellationToken);
    }
    public Task<ProtocolResponse> RequestDeviceCodeAsync(OAuthClientAuthentication client, string? scope = null, CancellationToken cancellationToken = default)
        => FormAsync(client, "protocol/openid-connect/auth/device", new(), scope, "Oidc.DeviceCode", cancellationToken);
    public Task<ProtocolResponse> RedeemDeviceCodeAsync(OAuthClientAuthentication client, string deviceCode, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(deviceCode);
        return GrantAsync(client, new() { ["grant_type"] = "urn:ietf:params:oauth:grant-type:device_code", ["device_code"] = deviceCode }, null, "Oidc.RedeemDeviceCode", cancellationToken);
    }
    public Task<ProtocolResponse> RequestBackchannelAuthenticationAsync(OAuthClientAuthentication client, string loginHint, string? scope = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(loginHint);
        return FormAsync(client, "protocol/openid-connect/ext/ciba/auth", new() { ["login_hint"] = loginHint }, scope, "Oidc.Ciba", cancellationToken);
    }
    public Task<ProtocolResponse> RedeemBackchannelAuthenticationAsync(OAuthClientAuthentication client, string authRequestId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(authRequestId);
        return GrantAsync(client, new() { ["grant_type"] = "urn:openid:params:grant-type:ciba", ["auth_req_id"] = authRequestId }, null, "Oidc.RedeemCiba", cancellationToken);
    }
    public Task<ProtocolResponse> IntrospectAsync(OAuthClientAuthentication client, string token, CancellationToken cancellationToken = default)
        => TokenActionAsync(client, "token/introspect", token, "Oidc.Introspect", cancellationToken);
    public Task<ProtocolResponse> RevokeAsync(OAuthClientAuthentication client, string token, CancellationToken cancellationToken = default)
        => TokenActionAsync(client, "revoke", token, "Oidc.Revoke", cancellationToken);

    public Uri CreateAuthorizationUri(string clientId, Uri redirectUri, string state, string nonce, string verifier, string scope = "openid", OidcAuthorizationOptions? options = null,
        OidcAuthorizationResponseType responseType = OidcAuthorizationResponseType.Code)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId); ArgumentException.ThrowIfNullOrWhiteSpace(state);
        ArgumentException.ThrowIfNullOrWhiteSpace(nonce); ValidateVerifier(verifier); ValidateRedirect(redirectUri);
        scope = string.Join(' ', new[] { scope }.Concat((options?.ParameterizedScopes ?? []).Select(s => { ArgumentNullException.ThrowIfNull(s); return s.Value; })));
        var query = new Dictionary<string, string> { ["response_type"] = responseType.Wire(), ["client_id"] = clientId,
            ["redirect_uri"] = redirectUri.AbsoluteUri, ["state"] = state, ["nonce"] = nonce, ["scope"] = scope,
            ["code_challenge_method"] = "S256", ["code_challenge"] = Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))) };
        return new Uri(transport.Target("protocol/openid-connect/auth").AbsoluteUri + "?" + ProtocolTransport.Query(query.Concat(options?.Parameters() ?? [])));
    }
    public static string CreateVerifier() => Base64Url(RandomNumberGenerator.GetBytes(32));
    private static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    private static void ValidateVerifier(string value)
    {
        if (value is null || value.Length is < 43 or > 128 || value.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('-' or '.' or '_' or '~')))
            throw new ArgumentException("A valid RFC 7636 verifier is required.", nameof(value));
    }
    private static void ValidateRedirect(Uri value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (!value.IsAbsoluteUri || value.Fragment.Length != 0 || value.UserInfo.Length != 0) throw new ArgumentException("An absolute callback URI without fragment or credentials is required.", nameof(value));
    }
    private Task<ProtocolResponse> GetAsync(string path, string operation, string? token, CancellationToken ct)
        => transport.SendAsync(HttpMethod.Get, path, operation, Feature, null, token, null, null, ct);
    private Task<ProtocolResponse> TokenActionAsync(OAuthClientAuthentication client, string path, string token, string operation, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);
        return FormAsync(client, "protocol/openid-connect/" + path, new() { ["token"] = token }, null, operation, ct);
    }
    private Task<ProtocolResponse> GrantAsync(OAuthClientAuthentication client, Dictionary<string, string> form, string? scope, string operation, CancellationToken ct, IEnumerable<Uri>? resources = null)
        => FormAsync(client, TokenPath, form, scope, operation, ct, OidcAuthorizationOptions.ResourceParameters(resources ?? []).ToArray());
    private Task<ProtocolResponse> FormAsync(OAuthClientAuthentication client, string path, Dictionary<string, string> form, string? scope, string operation, CancellationToken ct, IEnumerable<KeyValuePair<string, string>>? additional = null, IEnumerable<string>? additionalFeatures = null)
    {
        ArgumentNullException.ThrowIfNull(client);
        if (scope is not null) form.Add("scope", scope);
        var extra = (additional ?? []).ToArray();
        var features = (extra.Any(p => p.Key == "resource") ? new[] { "KeycloakSdk.Protocols.OidcResources" } : []).Concat(additionalFeatures ?? []).Concat(client.RequiredFeatures).ToArray();
        if (operation == "Oidc.IdentityAssertionGrant") features = [.. features, "KeycloakSdk.Protocols.OidcJwtGrant"];
        return transport.SendAsync(HttpMethod.Post, path, operation, OperationFeature(operation), null, null, null, async (request, token) =>
        {
            await client.ApplyAsync(request, form, token).ConfigureAwait(false);
            request.Content = new FormUrlEncodedContent(form.Concat(extra));
        }, ct, features);
    }
    private static string OperationFeature(string operation) => operation switch
    {
        "Oidc.Exchange" => "KeycloakSdk.Protocols.OidcStandardExchange", "Oidc.DelegatedExchange" => "KeycloakSdk.Protocols.OidcDelegation",
        "Oidc.LegacyExchange" => "KeycloakSdk.Protocols.OidcLegacyExchange", "Oidc.JwtGrant" => "KeycloakSdk.Protocols.OidcJwtGrant",
        "Oidc.IdentityAssertionGrant" => "KeycloakSdk.Protocols.OidcIdentityAssertion",
        "Oidc.DeviceCode" or "Oidc.RedeemDeviceCode" => "KeycloakSdk.Protocols.OidcDevice",
        "Oidc.Ciba" or "Oidc.RedeemCiba" => "KeycloakSdk.Protocols.OidcCiba", "Oidc.PushedAuthorization" => "KeycloakSdk.Protocols.OidcPar", _ => Feature
    };
}
