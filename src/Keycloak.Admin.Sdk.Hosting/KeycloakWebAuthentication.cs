using System.Globalization;
using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Nodes;
using Keycloak.Admin.Sdk.Protocols;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Keycloak.Admin.Sdk.Hosting;

/// <summary>Managed ASP.NET Core integration using its maintained OIDC and cookie handlers.
/// The host owns a shared, protected ITicketStore, Data Protection keys and trusted HTTPS/proxy configuration.</summary>
public static class KeycloakWebAuthentication
{
    internal static readonly TimeSpan MaximumSessionLifetime = TimeSpan.FromHours(8);
    private const string Feature = "KeycloakSdk.Protocols.BrowserOidc";
    private const string AssuranceSnapshot = ".keycloak.verified-assurance";
    private static readonly string[] Algorithms = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"];

    public static AuthenticationBuilder AddKeycloakWebApp(this AuthenticationBuilder builder, string scheme, ProtocolTransport transport,
        OAuthClientAuthentication client, ITicketStore ticketStore, IKeycloakLogoutStore logoutStore,
        PathString callbackPath = default, PathString signedOutCallbackPath = default, bool allowLoopbackHttp = false, OidcAssuranceRequirement? requiredAssurance = null)
    {
        ArgumentNullException.ThrowIfNull(builder); ArgumentException.ThrowIfNullOrWhiteSpace(scheme); ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(client); ArgumentNullException.ThrowIfNull(ticketStore); ArgumentNullException.ThrowIfNull(logoutStore);
        ValidateIssuer(transport.Issuer, allowLoopbackHttp);
        ValueTask EnsureWebAsync(CancellationToken ct) => transport.EnsureEnabledAsync(requiredAssurance is null
            ? [Feature, "KeycloakSdk.Protocols.Oidc"] : new[] { Feature, "KeycloakSdk.Protocols.Oidc", "KeycloakSdk.Protocols.OidcAssurance", "KeycloakSdk.Protocols.BrowserOidcAssurance" }, ct);
        string cookieScheme = scheme + ".cookie"; var oidc = new OidcClient(transport);
        builder.AddCookie(cookieScheme, options =>
        {
            options.SessionStore = ticketStore;
            options.Cookie.Name = "__Host-" + scheme; options.Cookie.HttpOnly = true; options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            options.Cookie.SameSite = SameSiteMode.Lax; options.Cookie.Path = "/";
            options.ExpireTimeSpan = MaximumSessionLifetime; options.SlidingExpiration = false;
            if (allowLoopbackHttp) { options.Cookie.Name = scheme; options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest; }
            options.Events.OnValidatePrincipal = async context =>
            {
                await EnsureWebAsync(context.HttpContext.RequestAborted).ConfigureAwait(false);
                bool reject = !TrySession(context.Principal, out string sid, out string sub, out var issued)
                    || await logoutStore.IsRevokedAsync(transport.Issuer.AbsoluteUri, sid, sub, issued, context.HttpContext.RequestAborted).ConfigureAwait(false);
                if (!reject && requiredAssurance is not null)
                    try
                    {
                        if (!context.Properties.Items.TryGetValue(AssuranceSnapshot, out string? snapshot) || snapshot is null) throw new InvalidDataException("Missing protected assurance snapshot.");
                        using var document = JsonDocument.Parse(snapshot); requiredAssurance.ValidateVerifiedClaims(document.RootElement);
                    }
                    catch (Exception error) when (error is InvalidDataException or JsonException) { reject = true; }
                if (reject)
                { context.RejectPrincipal(); await context.HttpContext.SignOutAsync(cookieScheme).ConfigureAwait(false); }
            };
            options.Events.OnRedirectToLogin = context => { context.Response.StatusCode = StatusCodes.Status401Unauthorized; return Task.CompletedTask; };
            options.Events.OnRedirectToAccessDenied = context => { context.Response.StatusCode = StatusCodes.Status403Forbidden; return Task.CompletedTask; };
        });
        return builder.AddOpenIdConnect(scheme, options =>
        {
            options.Authority = transport.Issuer.AbsoluteUri; options.ClientId = client.ClientId; options.SignInScheme = cookieScheme; options.SignOutScheme = cookieScheme;
            options.CallbackPath = callbackPath.HasValue ? callbackPath : "/signin-" + scheme;
            options.SignedOutCallbackPath = signedOutCallbackPath.HasValue ? signedOutCallbackPath : "/signout-callback-" + scheme;
            options.RemoteSignOutPath = "/frontchannel-" + scheme;
            options.RequireHttpsMetadata = !allowLoopbackHttp; options.MapInboundClaims = false;
            options.ResponseType = OpenIdConnectResponseType.Code; options.ResponseMode = OpenIdConnectResponseMode.Query;
            options.UsePkce = true; options.SaveTokens = true; // Tokens stay in the required server ticket store, never in the browser cookie.
            options.GetClaimsFromUserInfoEndpoint = false; options.RemoteAuthenticationTimeout = TimeSpan.FromMinutes(5);
            // The framework removes iat/acr by default after OnTokenValidated; local revocation and assurance checks need these signed claims.
            options.ClaimActions.Remove("iat"); options.ClaimActions.Remove("acr");
            options.ClaimActions.Remove("auth_time"); options.ClaimActions.Remove("amr");
            options.PushedAuthorizationBehavior = PushedAuthorizationBehavior.Disable; // PAR has its own independently promoted capability.
            options.ConfigurationManager = new PinnedConfiguration(transport, requiredAssurance);
            options.TokenValidationParameters = Parameters(transport, client.ClientId);
            options.ProtocolValidator.RequireNonce = true; options.ProtocolValidator.RequireState = true;
            if (allowLoopbackHttp)
            { options.CorrelationCookie.SecurePolicy = CookieSecurePolicy.SameAsRequest; options.CorrelationCookie.SameSite = SameSiteMode.Lax;
                options.NonceCookie.SecurePolicy = CookieSecurePolicy.SameAsRequest; options.NonceCookie.SameSite = SameSiteMode.Lax; }
            options.Events.OnRedirectToIdentityProvider = async context =>
            {
                await EnsureWebAsync(context.HttpContext.RequestAborted).ConfigureAwait(false);
                var choices = KeycloakAuthenticationProperties.Read(context.Properties);
                await oidc.EnsureAuthorizationEnabledAsync(choices, cancellationToken: context.HttpContext.RequestAborted).ConfigureAwait(false);
                if (choices.Action is not null) context.ProtocolMessage.SetParameter("kc_action", choices.Action);
                if (choices.IdentityProvider is not null) context.ProtocolMessage.SetParameter("kc_idp_hint", choices.IdentityProvider);
                if (requiredAssurance is not null)
                { context.ProtocolMessage.AcrValues = requiredAssurance.RequestedAcrValues; context.ProtocolMessage.MaxAge = requiredAssurance.MaximumAgeSeconds?.ToString(CultureInfo.InvariantCulture); }
            };
            options.Events.OnMessageReceived = async context =>
            { await EnsureWebAsync(context.HttpContext.RequestAborted).ConfigureAwait(false); };
            options.Events.OnAuthorizationCodeReceived = async context =>
            {
                await EnsureWebAsync(context.HttpContext.RequestAborted).ConfigureAwait(false);
                await oidc.EnsureAuthorizationEnabledAsync(KeycloakAuthenticationProperties.Read(context.Properties), cancellationToken: context.HttpContext.RequestAborted).ConfigureAwait(false);
                var request = context.TokenEndpointRequest ?? throw new InvalidDataException("Missing protected OIDC token request.");
                var response = await oidc.RedeemCodeAsync(client, request.Code, new Uri(request.RedirectUri), request.GetParameter("code_verifier"), context.HttpContext.RequestAborted).ConfigureAwait(false);
                context.HandleCodeRedemption(new OpenIdConnectMessage(response.Json!.Value.GetRawText()));
            };
            options.Events.OnTokenValidated = async context =>
            {
                await EnsureWebAsync(context.HttpContext.RequestAborted).ConfigureAwait(false);
                await oidc.EnsureAuthorizationEnabledAsync(KeycloakAuthenticationProperties.Read(context.Properties), cancellationToken: context.HttpContext.RequestAborted).ConfigureAwait(false);
                // The framework skips ValidateTokenResponse after HandleCodeRedemption; our gated transport owns redemption.
                // Explicitly preserve its nonce and token-response binding checks instead of merely reading the nonce cookie.
                JsonElement verifiedClaims;
                try
                {
                    var signed = context.SecurityToken?.InnerToken ?? context.SecurityToken;
                    if (signed is null || string.IsNullOrEmpty(signed.RawSignature)) throw new InvalidDataException("A signed ID token is required.");
                    using var payload = JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(signed.RawPayload));
                    if (payload.RootElement.TryGetProperty("typ", out var tokenKind) && (tokenKind.ValueKind != JsonValueKind.String || tokenKind.GetString() != "ID"))
                        throw new InvalidDataException("A Keycloak ID token is required.");
                    options.ProtocolValidator.ValidateTokenResponse(new OpenIdConnectProtocolValidationContext { ClientId = client.ClientId,
                        ProtocolMessage = context.TokenEndpointResponse ?? throw new InvalidDataException("Missing redeemed OIDC response."),
                        ValidatedIdToken = context.SecurityToken, Nonce = context.Nonce });
                    // Keep assurance bound to this exact validated token across the asynchronous session-store call.
                    verifiedClaims = payload.RootElement.Clone();
                }
                catch (Exception error) when (error is OpenIdConnectProtocolException or InvalidDataException or JsonException)
                { context.Fail("Invalid Keycloak OIDC token binding."); return; }
                if (!TrySession(context.Principal, out string sid, out string sub, out var issued)
                    || await logoutStore.IsRevokedAsync(transport.Issuer.AbsoluteUri, sid, sub, issued, context.HttpContext.RequestAborted).ConfigureAwait(false))
                    context.Fail("Invalid or revoked Keycloak session.");
                if (requiredAssurance is not null)
                    try
                    {
                        requiredAssurance.ValidateVerifiedClaims(verifiedClaims);
                        var snapshot = new JsonObject();
                        foreach (string name in new[] { "acr", "auth_time", "amr" })
                            if (verifiedClaims.TryGetProperty(name, out var value)) snapshot[name] = JsonNode.Parse(value.GetRawText());
                        // AuthenticationProperties stay in the required protected server ticket, independently of framework claim conversions.
                        var properties = context.Properties ?? throw new InvalidDataException("Protected OIDC transaction properties are required.");
                        properties.Items[AssuranceSnapshot] = snapshot.ToJsonString();
                    }
                    catch (Exception error) when (error is InvalidDataException or JsonException) { context.Fail("Required Keycloak authentication assurance was not attained."); }
            };
            options.Events.OnRedirectToIdentityProviderForSignOut = async context =>
            { await EnsureWebAsync(context.HttpContext.RequestAborted).ConfigureAwait(false); context.ProtocolMessage.ClientId = client.ClientId; };
            // Unauthenticated front-channel sid/iss queries must never revoke a victim's server session.
            // Use the signed back-channel endpoint; the front-channel handler only clears this browser's matching cookie.
            options.Events.OnRemoteSignOut = async context =>
            {
                await EnsureWebAsync(context.HttpContext.RequestAborted).ConfigureAwait(false);
                var current = await context.HttpContext.AuthenticateAsync(cookieScheme).ConfigureAwait(false);
                if (string.IsNullOrEmpty(context.ProtocolMessage?.Sid) || current.Principal?.FindFirst("sid")?.Value != context.ProtocolMessage.Sid || context.ProtocolMessage.Iss != transport.Issuer.AbsoluteUri)
                    context.HandleResponse();
            };
            options.Events.OnRemoteFailure = context =>
            { context.HandleResponse(); context.Response.StatusCode = StatusCodes.Status400BadRequest; return Task.CompletedTask; };
        });
    }

    /// <summary>Validates resource tokens against the fixed realm and explicit audience. DPoP tokens need DpopRequestValidator instead.</summary>
    public static AuthenticationBuilder AddKeycloakBearer(this AuthenticationBuilder builder, string scheme, ProtocolTransport transport, string audience, bool allowLoopbackHttp = false)
    {
        ArgumentNullException.ThrowIfNull(builder); ArgumentNullException.ThrowIfNull(transport); ArgumentException.ThrowIfNullOrWhiteSpace(audience);
        ValidateIssuer(transport.Issuer, allowLoopbackHttp);
        return builder.AddJwtBearer(scheme, options =>
        {
            options.Authority = transport.Issuer.AbsoluteUri; options.RequireHttpsMetadata = !allowLoopbackHttp;
            options.MapInboundClaims = false; options.SaveToken = false; options.IncludeErrorDetails = false;
            options.ConfigurationManager = new PinnedConfiguration(transport); options.TokenValidationParameters = Parameters(transport, audience);
            options.Events.OnMessageReceived = async context => { await EnsureEnabledAsync(transport, context.HttpContext.RequestAborted).ConfigureAwait(false); };
            options.Events.OnTokenValidated = context =>
            { if (context.Principal?.FindFirst("typ")?.Value != "Bearer") context.Fail("A bearer access token is required."); return Task.CompletedTask; };
        });
    }

    internal static async Task EnsureEnabledAsync(ProtocolTransport transport, CancellationToken ct)
    { await transport.EnsureEnabledAsync([Feature, "KeycloakSdk.Protocols.Oidc"], ct).ConfigureAwait(false); }
    internal static void ValidateIssuer(Uri issuer, bool allowLoopbackHttp)
    { if (issuer.Scheme != "https" && !(allowLoopbackHttp && issuer.Scheme == "http" && issuer.IsLoopback)) throw new ArgumentException("HTTPS is required; the explicit development exception permits loopback HTTP only."); }
    private static TokenValidationParameters Parameters(ProtocolTransport transport, string audience) => new()
    {
        ValidateIssuer = true, ValidIssuer = transport.Issuer.AbsoluteUri, ValidateAudience = true, ValidAudience = audience, IgnoreTrailingSlashWhenValidatingAudience = false,
        ValidateLifetime = true, RequireExpirationTime = true, RequireSignedTokens = true, ValidateIssuerSigningKey = true, ValidAlgorithms = Algorithms,
        ClockSkew = TimeSpan.FromSeconds(30), NameClaimType = "preferred_username", RoleClaimType = "roles",
        IncludeTokenOnFailedValidation = false, LogTokenId = false, LogValidationExceptions = false
    };
    private static bool TrySession(ClaimsPrincipal? principal, out string sid, out string sub, out DateTimeOffset issued)
    {
        sid = principal?.FindFirst("sid")?.Value ?? ""; sub = principal?.FindFirst("sub")?.Value ?? ""; issued = default;
        // Nonempty sid/sub prove principal exists; NumberStyles.None also rejects negative and signed integers.
        if (sid.Length == 0 || sub.Length == 0 || !long.TryParse(principal!.FindFirst("iat")?.Value, NumberStyles.None, CultureInfo.InvariantCulture, out long seconds) || seconds > 253402300799) return false;
        issued = DateTimeOffset.FromUnixTimeSeconds(seconds); return true;
    }

    private sealed class PinnedConfiguration(ProtocolTransport transport, OidcAssuranceRequirement? requiredAssurance = null) : IConfigurationManager<OpenIdConnectConfiguration>
    {
        public async Task<OpenIdConnectConfiguration> GetConfigurationAsync(CancellationToken cancellationToken)
        {
            await EnsureEnabledAsync(transport, cancellationToken).ConfigureAwait(false);
            if (requiredAssurance is not null) await transport.EnsureEnabledAsync(["KeycloakSdk.Protocols.OidcAssurance", "KeycloakSdk.Protocols.BrowserOidcAssurance"], cancellationToken).ConfigureAwait(false);
            var keys = await new OidcClient(transport).GetSigningKeysAsync(cancellationToken).ConfigureAwait(false);
            string path = transport.Issuer.AbsoluteUri + "/protocol/openid-connect/";
            var configuration = new OpenIdConnectConfiguration { Issuer = transport.Issuer.AbsoluteUri, AuthorizationEndpoint = path + "auth", TokenEndpoint = path + "token",
                UserInfoEndpoint = path + "userinfo", EndSessionEndpoint = path + "logout", JwksUri = path + "certs" };
            foreach (var key in new JsonWebKeySet(keys.Json!.Value.GetRawText()).GetSigningKeys()) configuration.SigningKeys.Add(key);
            return configuration;
        }
        public void RequestRefresh() { } // Keys are fetched through the fixed, gated transport on every configuration request.
    }
}
