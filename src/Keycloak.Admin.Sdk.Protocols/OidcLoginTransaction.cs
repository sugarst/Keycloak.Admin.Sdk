using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Keycloak.Admin.Sdk.Protocols;

/// <summary>One server-side, user-session-bound login transaction. Never serialize it into a URL or an unprotected cookie.
/// The host must bind this object to its initiating browser session and protect its storage; distributed hosts need an atomic shared store.</summary>
public sealed class OidcLoginTransaction
{
    private readonly OidcClient oidc;
    private readonly Uri redirect;
    private readonly string clientId;
    private readonly string verifier = OidcClient.CreateVerifier();
    private readonly string nonce = OidcClient.CreateVerifier();
    private readonly TimeProvider clock;
    private readonly Uri[] resources;
    private readonly string[] requiredFeatures;
    private readonly OidcAuthorizationResponseMode responseMode;
    private readonly DateTimeOffset expires;
    private readonly OidcAssuranceRequirement? assurance;
    private int consumed;
    public string State { get; } = OidcClient.CreateVerifier();
    public Uri AuthorizationUri { get; private set; }

    public OidcLoginTransaction(OidcClient oidc, string clientId, Uri redirectUri, string scope = "openid",
        TimeSpan? lifetime = null, TimeProvider? clock = null, OidcAuthorizationOptions? options = null)
        : this(oidc, clientId, redirectUri, scope, lifetime, clock, options, []) { }

    private OidcLoginTransaction(OidcClient oidc, string clientId, Uri redirectUri, string scope, TimeSpan? lifetime, TimeProvider? clock,
        OidcAuthorizationOptions? options, IEnumerable<string> additionalFeatures)
    {
        this.oidc = oidc ?? throw new ArgumentNullException(nameof(oidc));
        this.clientId = clientId;
        if (!scope.Split(' ', StringSplitOptions.RemoveEmptyEntries).Contains("openid", StringComparer.Ordinal))
            throw new ArgumentException("An OpenID Connect login requires the openid scope.", nameof(scope));
        this.clock = clock ?? TimeProvider.System;
        TimeSpan duration = lifetime ?? TimeSpan.FromMinutes(5);
        if (duration <= TimeSpan.Zero || duration > TimeSpan.FromMinutes(15)) throw new ArgumentOutOfRangeException(nameof(lifetime));
        expires = this.clock.GetUtcNow() + duration;
        redirect = redirectUri;
        AuthorizationUri = oidc.CreateAuthorizationUri(clientId, redirectUri, State, nonce, verifier, scope, options);
        resources = options?.Resources.ToArray() ?? [];
        requiredFeatures = OidcClient.AuthorizationFeatures(scope, options).Concat(additionalFeatures).Distinct(StringComparer.Ordinal).ToArray();
        responseMode = options?.ResponseMode ?? OidcAuthorizationResponseMode.Query;
        assurance = options?.RequiredAssurance;
        // Fixed query parameters introduce ambiguity between application and protocol parameters.
        if (redirectUri.Query.Length != 0) throw new ArgumentException("Use a callback URI without query parameters.", nameof(redirectUri));
    }

    /// <summary>Checks independent support and all host gates before handing an authorization URL to a browser.</summary>
    public static async Task<OidcLoginTransaction> StartAsync(OidcClient oidc, string clientId, Uri redirectUri, string scope = "openid",
        TimeSpan? lifetime = null, TimeProvider? clock = null, OidcAuthorizationOptions? options = null, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var transaction = new OidcLoginTransaction(oidc, clientId, redirectUri, scope, lifetime, clock, options);
        await oidc.EnsureFeaturesAsync(transaction.requiredFeatures, cancellationToken).ConfigureAwait(false);
        return transaction;
    }

    /// <summary>Also checks the selected client authentication's dependent capability gates before returning a browser URL. No credential is read at initiation.</summary>
    public static async Task<OidcLoginTransaction> StartAsync(OidcClient oidc, OAuthClientAuthentication client, Uri redirectUri, string scope = "openid",
        TimeSpan? lifetime = null, TimeProvider? clock = null, OidcAuthorizationOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(client); cancellationToken.ThrowIfCancellationRequested();
        var transaction = new OidcLoginTransaction(oidc, client.ClientId, redirectUri, scope, lifetime, clock, options);
        await oidc.EnsureFeaturesAsync(transaction.requiredFeatures.Concat(client.RequiredFeatures), cancellationToken).ConfigureAwait(false);
        return transaction;
    }

    /// <summary>Creates a JAR whose signed request contains this exact transaction's state, nonce and PKCE challenge.
    /// Register the signing key at Keycloak; never create a replacement transaction from an incoming request object.</summary>
    public static async Task<OidcLoginTransaction> StartSignedAsync(OidcClient oidc, OAuthClientAuthentication client, Uri redirectUri, OidcRequestObjectSigner signer,
        string scope = "openid", TimeSpan? lifetime = null, TimeProvider? clock = null, OidcAuthorizationOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(client); ArgumentNullException.ThrowIfNull(signer); cancellationToken.ThrowIfCancellationRequested();
        var transaction = new OidcLoginTransaction(oidc, client.ClientId, redirectUri, scope, lifetime, clock, options, ["KeycloakSdk.Protocols.OidcRequestObjects"]);
        await oidc.EnsureFeaturesAsync(transaction.requiredFeatures.Concat(client.RequiredFeatures), cancellationToken).ConfigureAwait(false);
        transaction.AuthorizationUri = await signer.CreateAuthorizationUriAsync(oidc.Issuer, transaction.AuthorizationUri, cancellationToken).ConfigureAwait(false);
        return transaction;
    }

    /// <summary>Publishes this transaction's signed request at a host-owned HTTPS URI registered in the client's request_uri allowlist.
    /// The host serves the exact JWT briefly with application/oauth-authz-req+jwt and prevents unrelated content from replacing it.</summary>
    public static async Task<OidcLoginTransaction> StartReferencedAsync(OidcClient oidc, OAuthClientAuthentication client, Uri redirectUri, OidcRequestObjectSigner signer,
        Uri requestUri, Func<string, CancellationToken, ValueTask> publish, string scope = "openid", OidcAuthorizationOptions? options = null,
        bool allowLoopbackHttp = false, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(requestUri); ArgumentNullException.ThrowIfNull(publish); cancellationToken.ThrowIfCancellationRequested();
        if (!requestUri.IsAbsoluteUri || (requestUri.Scheme != "https" && !(allowLoopbackHttp && requestUri.Scheme == "http" && requestUri.IsLoopback))
            || requestUri.UserInfo.Length != 0 || requestUri.Fragment.Length != 0 || requestUri.AbsoluteUri.Length > 2048)
            throw new ArgumentException("A bounded HTTPS request-object URI without credentials or fragments is required.", nameof(requestUri));
        var transaction = await StartSignedAsync(oidc, client, redirectUri, signer, scope, options: options, cancellationToken: cancellationToken).ConfigureAwait(false);
        var parameters = OidcCallbackParameters.Read(transaction.AuthorizationUri, new(transaction.AuthorizationUri.GetLeftPart(UriPartial.Path)), OidcAuthorizationResponseMode.Query);
        await publish(parameters["request"], cancellationToken).ConfigureAwait(false);
        await oidc.EnsureFeaturesAsync(transaction.requiredFeatures.Concat(client.RequiredFeatures), cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        transaction.AuthorizationUri = new(transaction.AuthorizationUri.GetLeftPart(UriPartial.Path) + "?" + ProtocolTransport.Query([new("client_id", client.ClientId), new("request_uri", requestUri.AbsoluteUri)]));
        return transaction;
    }

    /// <summary>Validates the callback before sending the code once. A failed exchange consumes the transaction; restart login rather than replay a code.</summary>
    public async Task<OidcLoginResult> CompleteAsync(Uri callback, OAuthClientAuthentication client, OidcTokenValidator validator,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(callback); cancellationToken.ThrowIfCancellationRequested();
        var values = OidcCallbackParameters.Read(callback, redirect, responseMode);
        return await CompleteParametersAsync(values, client, validator, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>The host must supply the exact form fields from the initiating browser's bound callback request, after enforcing its request size limit.</summary>
    public async Task<OidcLoginResult> CompleteFormPostAsync(Uri callback, IEnumerable<KeyValuePair<string, string>> fields, OAuthClientAuthentication client,
        OidcTokenValidator validator, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(callback); ArgumentNullException.ThrowIfNull(fields); cancellationToken.ThrowIfCancellationRequested();
        return await CompleteParametersAsync(OidcCallbackParameters.ReadForm(callback, redirect, responseMode, fields), client, validator, cancellationToken).ConfigureAwait(false);
    }

    private async Task<OidcLoginResult> CompleteParametersAsync(Dictionary<string, string> values, OAuthClientAuthentication client, OidcTokenValidator validator, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(client); ArgumentNullException.ThrowIfNull(validator);
        cancellationToken.ThrowIfCancellationRequested();
        await oidc.EnsureFeaturesAsync(requiredFeatures.Concat(client.RequiredFeatures), cancellationToken).ConfigureAwait(false);
        if (client.ClientId != clientId || !validator.Matches(oidc.Issuer, clientId)) throw new ArgumentException("OIDC client/validator must match the initiating transaction.");
        if (clock.GetUtcNow() >= expires) throw new InvalidDataException("OIDC transaction expired.");
        values = await OidcCallbackParameters.UnwrapAsync(values, responseMode, validator, cancellationToken).ConfigureAwait(false);
        if (values.ContainsKey("id_token") || values.ContainsKey("access_token")) throw new InvalidDataException("An authorization-code callback cannot include unsolicited credentials.");
        if (!values.TryGetValue("state", out string? state) || !FixedEquals(State, state)) throw new InvalidDataException("OIDC state mismatch.");
        if (clock.GetUtcNow() >= expires || Interlocked.Exchange(ref consumed, 1) != 0) throw new InvalidDataException("OIDC transaction expired or already consumed.");
        if (values.ContainsKey("error") || !values.TryGetValue("code", out string? code) || string.IsNullOrWhiteSpace(code))
            throw new InvalidDataException("OIDC authorization was denied or returned no code.");
        if (values.TryGetValue("iss", out string? issuer) && issuer != oidc.Issuer.AbsoluteUri) throw new InvalidDataException("OIDC callback issuer mismatch.");
        var response = await oidc.RedeemCodeAsync(client, code, redirect, verifier, cancellationToken, resources).ConfigureAwait(false);
        var json = response.Json ?? throw new InvalidDataException("Empty OIDC token response.");
        string idToken = json.GetProperty("id_token").GetString() ?? throw new InvalidDataException("Missing ID token.");
        string accessToken = json.GetProperty("access_token").GetString() ?? throw new InvalidDataException("Missing access token.");
        var identity = await validator.ValidateIdTokenAsync(idToken, nonce, accessToken, cancellationToken).ConfigureAwait(false);
        assurance?.Validate(identity);
        return new(identity, response);
    }

    internal static bool FixedEquals(string left, string right)
        => CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(left), Encoding.UTF8.GetBytes(right));
}

/// <summary>Raw tokens remain credentials, even after the ID token has been verified. Avoid logging or placing this object in a client-side cookie.</summary>
public sealed class OidcLoginResult(OidcIdentity identity, ProtocolResponse tokens)
{
    public OidcIdentity Identity { get; } = identity;
    public ProtocolResponse Tokens { get; } = tokens;
}
