namespace Keycloak.Admin.Sdk.Protocols;

public enum OidcAuthorizationResponseType { Code, IdToken, Token, IdTokenToken, CodeIdToken, CodeToken, CodeIdTokenToken, None }

internal static class OidcResponseTypes
{
    internal static string Wire(this OidcAuthorizationResponseType type) => type switch
    {
        OidcAuthorizationResponseType.Code => "code", OidcAuthorizationResponseType.IdToken => "id_token", OidcAuthorizationResponseType.Token => "token",
        OidcAuthorizationResponseType.IdTokenToken => "id_token token", OidcAuthorizationResponseType.CodeIdToken => "code id_token",
        OidcAuthorizationResponseType.CodeToken => "code token", OidcAuthorizationResponseType.CodeIdTokenToken => "code id_token token",
        OidcAuthorizationResponseType.None => "none", _ => throw new ArgumentOutOfRangeException(nameof(type))
    };
}

/// <summary>Explicit compatibility flows for implicit, hybrid and none responses. Prefer OidcLoginTransaction for code + PKCE.
/// The host must bind this object to the initiating browser session in protected server storage. An OAuth-only or none response never yields a login identity.</summary>
public sealed class OidcBrowserTransaction
{
    private readonly OidcClient oidc;
    private readonly Uri callback;
    private readonly string clientId, nonce = OidcClient.CreateVerifier(), verifier = OidcClient.CreateVerifier();
    private readonly string[] requiredFeatures;
    private readonly OidcAuthorizationResponseMode mode;
    private readonly bool expectsCode, expectsIdentity, expectsAccess;
    private readonly Uri[] resources;
    private readonly DateTimeOffset expires;
    private readonly TimeProvider clock;
    private readonly OidcAssuranceRequirement? assurance;
    private int consumed;
    public string State { get; } = OidcClient.CreateVerifier();
    public Uri AuthorizationUri { get; }

    private OidcBrowserTransaction(OidcClient oidc, OAuthClientAuthentication client, Uri callback, OidcAuthorizationResponseType type, OidcAuthorizationOptions options, string scope, TimeProvider? clock)
    {
        this.oidc = oidc ?? throw new ArgumentNullException(nameof(oidc)); this.callback = callback; clientId = client.ClientId;
        this.clock = clock ?? TimeProvider.System; expires = this.clock.GetUtcNow().AddMinutes(5);
        assurance = options.RequiredAssurance;
        string wire = type.Wire();
        if (type == OidcAuthorizationResponseType.Code) throw new ArgumentException("Use OidcLoginTransaction for authorization code login.", nameof(type));
        expectsCode = wire.Split(' ').Contains("code", StringComparer.Ordinal); expectsIdentity = wire.Split(' ').Contains("id_token", StringComparer.Ordinal);
        expectsAccess = wire.Split(' ').Contains("token", StringComparer.Ordinal);
        if (!expectsIdentity && !expectsCode && assurance is not null) throw new ArgumentException("An ID-token response is required for authentication assurance.", nameof(options));
        mode = options.ResponseMode == OidcAuthorizationResponseMode.Jwt ? (expectsIdentity || expectsAccess ? OidcAuthorizationResponseMode.FragmentJwt : OidcAuthorizationResponseMode.QueryJwt) : options.ResponseMode;
        if (expectsIdentity && !scope.Split(' ').Contains("openid", StringComparer.Ordinal)) throw new ArgumentException("ID tokens require the openid scope.", nameof(scope));
        if ((expectsIdentity || expectsAccess) && mode == OidcAuthorizationResponseMode.Query) throw new ArgumentException("Front-channel credentials cannot use query response mode.", nameof(options));
        AuthorizationUri = oidc.CreateAuthorizationUri(clientId, callback, State, nonce, verifier, scope, options, type);
        if (callback.Query.Length != 0) throw new ArgumentException("Use a callback without fixed query parameters.", nameof(callback));
        resources = options.Resources.ToArray();
        requiredFeatures = OidcClient.AuthorizationFeatures(scope, options).Concat(["KeycloakSdk.Protocols.OidcBrowserCompatibility"]).ToArray();
    }

    public static async Task<OidcBrowserTransaction> StartAsync(OidcClient oidc, OAuthClientAuthentication client, Uri callback,
        OidcAuthorizationResponseType responseType, OidcAuthorizationOptions? options = null, string scope = "openid", TimeProvider? clock = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(client); cancellationToken.ThrowIfCancellationRequested();
        options ??= new() { ResponseMode = responseType == OidcAuthorizationResponseType.None ? OidcAuthorizationResponseMode.Query : OidcAuthorizationResponseMode.Fragment };
        var transaction = new OidcBrowserTransaction(oidc, client, callback, responseType, options, scope, clock);
        await oidc.EnsureFeaturesAsync(transaction.requiredFeatures.Concat(client.RequiredFeatures), cancellationToken).ConfigureAwait(false);
        return transaction;
    }

    public Task<OidcBrowserResult> CompleteAsync(Uri actualCallback, OAuthClientAuthentication client, OidcTokenValidator identityValidator,
        KeycloakAccessTokenValidator? accessValidator = null, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return CompleteCoreAsync(OidcCallbackParameters.Read(actualCallback, callback, mode), client, identityValidator, accessValidator, cancellationToken);
    }

    public Task<OidcBrowserResult> CompleteFormPostAsync(Uri actualCallback, IEnumerable<KeyValuePair<string, string>> fields, OAuthClientAuthentication client,
        OidcTokenValidator identityValidator, KeycloakAccessTokenValidator? accessValidator = null, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return CompleteCoreAsync(OidcCallbackParameters.ReadForm(actualCallback, callback, mode, fields), client, identityValidator, accessValidator, cancellationToken);
    }

    private async Task<OidcBrowserResult> CompleteCoreAsync(Dictionary<string, string> values, OAuthClientAuthentication client, OidcTokenValidator identityValidator,
        KeycloakAccessTokenValidator? accessValidator, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(client); ArgumentNullException.ThrowIfNull(identityValidator); ct.ThrowIfCancellationRequested();
        await oidc.EnsureFeaturesAsync(requiredFeatures.Concat(client.RequiredFeatures), ct).ConfigureAwait(false);
        if (client.ClientId != clientId || !identityValidator.Matches(oidc.Issuer, clientId)) throw new ArgumentException("Validators and authentication must match the initiating browser client.");
        if (clock.GetUtcNow() >= expires) throw new InvalidDataException("Browser transaction expired.");
        values = await OidcCallbackParameters.UnwrapAsync(values, mode, identityValidator, ct).ConfigureAwait(false);
        if (!values.TryGetValue("state", out var state) || !OidcLoginTransaction.FixedEquals(State, state)) throw new InvalidDataException("Browser response state mismatch.");
        if (clock.GetUtcNow() >= expires || Interlocked.Exchange(ref consumed, 1) != 0) throw new InvalidDataException("Browser transaction expired or already consumed.");
        if (values.ContainsKey("error") || values.TryGetValue("iss", out var issuer) && issuer != oidc.Issuer.AbsoluteUri) throw new InvalidDataException("Browser authorization failed or issuer mismatch.");
        string? Require(string key, bool expected)
        {
            bool present = values.TryGetValue(key, out string? value);
            if (present != expected || present && string.IsNullOrWhiteSpace(value)) throw new InvalidDataException("Browser response does not match its requested response type.");
            return value;
        }
        string? code = Require("code", expectsCode), idToken = Require("id_token", expectsIdentity), access = Require("access_token", expectsAccess);
        OidcIdentity? identity = idToken is null ? null : await identityValidator.ValidateBrowserIdTokenAsync(idToken, nonce, access, code, ct).ConfigureAwait(false);
        VerifiedAccessToken? verifiedAccess = null;
        if (access is not null)
        {
            if (!values.TryGetValue("token_type", out var tokenType) || tokenType != "Bearer" || accessValidator is null || !accessValidator.MatchesIssuer(oidc.Issuer)) throw new InvalidDataException("A bearer response and an explicit resource audience validator for the pinned issuer are required.");
            verifiedAccess = await accessValidator.ValidateAsync(access, ct).ConfigureAwait(false);
            if (identity is not null && identity.Subject != verifiedAccess.Subject) throw new InvalidDataException("Front-channel token subjects do not agree.");
        }
        ProtocolResponse? tokens = null;
        if (code is not null)
        {
            tokens = await oidc.RedeemCodeAsync(client, code, callback, verifier, ct, resources).ConfigureAwait(false);
            var tokenJson = tokens.Json ?? throw new InvalidDataException("Empty hybrid token response.");
            var redeemed = await identityValidator.ValidateIdTokenAsync(tokenJson.GetProperty("id_token").GetString()!, nonce, tokenJson.GetProperty("access_token").GetString()!, ct).ConfigureAwait(false);
            if (identity is not null && identity.Subject != redeemed.Subject || verifiedAccess is not null && verifiedAccess.Subject != redeemed.Subject) throw new InvalidDataException("Hybrid response subjects do not agree.");
            identity = redeemed;
        }
        if (assurance is not null) assurance.Validate(identity!); // Initiation rejects response types that cannot produce a verified ID token.
        return new(identity, verifiedAccess, tokens);
    }
}

/// <summary>A verified identity exists only when an ID token was verified. None and OAuth-only responses cannot authenticate a host login.</summary>
public sealed class OidcBrowserResult
{
    public OidcIdentity? Identity { get; }
    public VerifiedAccessToken? AccessToken { get; }
    public ProtocolResponse? Tokens { get; }
    internal OidcBrowserResult(OidcIdentity? identity, VerifiedAccessToken? accessToken, ProtocolResponse? tokens)
    { Identity = identity; AccessToken = accessToken; Tokens = tokens; }
}
