using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Keycloak.Admin.Sdk.Protocols;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace Keycloak.Admin.Sdk.Hosting;

public static class KeycloakHostEndpoints
{
    /// <summary>Signed OIDC back-channel logout. Persist revocation before returning 200; retries are idempotent.
    /// The route must be registered as the client's backchannel.logout.url and accept anonymous POSTs, without browser antiforgery.</summary>
    public static IEndpointConventionBuilder MapKeycloakBackchannelLogout(this IEndpointRouteBuilder endpoints, string pattern,
        ProtocolTransport transport, string clientId, IKeycloakLogoutStore store, TimeProvider? clock = null)
    {
        ArgumentNullException.ThrowIfNull(endpoints); ArgumentNullException.ThrowIfNull(transport); ArgumentNullException.ThrowIfNull(store);
        var time = clock ?? TimeProvider.System;
        // Verification does not reserve a replay ID: a failed durable write must remain retryable.
        // RevokeAsync atomically applies an idempotent issuer/sid or issuer/sub marker, including concurrent deliveries.
        var validator = new OidcLogoutTokenValidator(new(transport), clientId, new IdempotentLogoutDelivery());
        return endpoints.MapPost(pattern, async (HttpContext context) =>
        {
            context.Response.Headers.CacheControl = "no-store";
            await KeycloakWebAuthentication.EnsureEnabledAsync(transport, context.RequestAborted).ConfigureAwait(false);
            if (!context.Request.HasFormContentType || context.Request.ContentLength > 65536)
            { context.Response.StatusCode = StatusCodes.Status400BadRequest; return; }
            try
            {
                // A bounded reader also covers chunked bodies whose Content-Length is absent.
                using var memory = new MemoryStream(); byte[] buffer = new byte[4096]; int count;
                while ((count = await context.Request.Body.ReadAsync(buffer, context.RequestAborted).ConfigureAwait(false)) != 0)
                { if (memory.Length + count > 65536) throw new InvalidDataException("Logout request is too large."); await memory.WriteAsync(buffer.AsMemory(0, count), context.RequestAborted).ConfigureAwait(false); }
                var fields = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(Encoding.UTF8.GetString(memory.ToArray()));
                if (fields.Count != 1 || !fields.TryGetValue("logout_token", out var value) || value.Count != 1 || string.IsNullOrWhiteSpace(value[0])) throw new InvalidDataException("Invalid logout request.");
                var verified = await validator.ValidateAsync(value[0]!, context.RequestAborted).ConfigureAwait(false); var claims = verified.Claims;
                string? Claim(string name) => claims.TryGetProperty(name, out var claim) && claim.ValueKind == JsonValueKind.String ? claim.GetString() : null;
                await store.RevokeAsync(transport.Issuer.AbsoluteUri, verified.Id, Claim("sid"), Claim("sub"), DateTimeOffset.FromUnixTimeSeconds(claims.GetProperty("iat").GetInt64()),
                    time.GetUtcNow().Add(KeycloakWebAuthentication.MaximumSessionLifetime).AddMinutes(11), context.RequestAborted).ConfigureAwait(false);
                context.Response.StatusCode = StatusCodes.Status200OK;
            }
            catch (Exception error) when (error is InvalidDataException or FormatException or JsonException or ArgumentOutOfRangeException)
            { context.Response.StatusCode = StatusCodes.Status400BadRequest; }
        }).AllowAnonymous();
    }
    private sealed class IdempotentLogoutDelivery : ISecurityTokenReplayStore
    {
        public ValueTask<bool> TryUseAsync(string proofId, DateTimeOffset expiresAt, CancellationToken cancellationToken = default)
        { cancellationToken.ThrowIfCancellationRequested(); return ValueTask.FromResult(true); }
    }
}

/// <summary>RFC 9728 metadata for an MCP/OAuth resource. The resource URI is the exact JWT audience, never the client ID of a caller.
/// This provides OAuth discovery and challenges; the host still authorizes individual MCP tools and operations.</summary>
public sealed class KeycloakProtectedResource
{
    private readonly ProtocolTransport transport;
    private readonly string[] scopes;
    public Uri Resource { get; }
    public Uri MetadataUri { get; }
    public string Challenge => "Bearer resource_metadata=\"" + MetadataUri.AbsoluteUri + "\"";
    public KeycloakProtectedResource(ProtocolTransport transport, Uri resource, IEnumerable<string> scopes, bool allowLoopbackHttp = false)
    {
        this.transport = transport ?? throw new ArgumentNullException(nameof(transport)); ArgumentNullException.ThrowIfNull(resource); ArgumentNullException.ThrowIfNull(scopes);
        if (!resource.IsAbsoluteUri || resource.UserInfo.Length != 0 || resource.Query.Length != 0 || resource.Fragment.Length != 0) throw new ArgumentException("An absolute resource URI without credentials, query or fragment is required.", nameof(resource));
        KeycloakWebAuthentication.ValidateIssuer(resource, allowLoopbackHttp); KeycloakWebAuthentication.ValidateIssuer(transport.Issuer, allowLoopbackHttp);
        this.scopes = scopes.Distinct(StringComparer.Ordinal).ToArray();
        if (this.scopes.Any(s => s.Length == 0 || s.Any(c => c < 0x21 || c > 0x7e || c is '"' or '\\'))) throw new ArgumentException("Invalid OAuth scopes.", nameof(scopes));
        Resource = resource;
        MetadataUri = new Uri(resource.GetLeftPart(UriPartial.Authority) + "/.well-known/oauth-protected-resource" + resource.AbsolutePath.TrimEnd('/'));
    }
    public IEndpointConventionBuilder MapMetadata(IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        return endpoints.MapGet(MetadataUri.AbsolutePath, async (HttpContext context) =>
        {
            await KeycloakWebAuthentication.EnsureEnabledAsync(transport, context.RequestAborted).ConfigureAwait(false);
            context.Response.ContentType = "application/json"; context.Response.Headers.CacheControl = "no-store";
            using var memory = new MemoryStream();
            using (var json = new Utf8JsonWriter(memory))
            {
                json.WriteStartObject(); json.WriteString("resource", Resource.AbsoluteUri);
                json.WriteStartArray("authorization_servers"); json.WriteStringValue(transport.Issuer.AbsoluteUri); json.WriteEndArray();
                json.WriteStartArray("bearer_methods_supported"); json.WriteStringValue("header"); json.WriteEndArray();
                json.WriteStartArray("scopes_supported"); foreach (string scope in scopes) json.WriteStringValue(scope); json.WriteEndArray(); json.WriteEndObject();
            }
            await context.Response.Body.WriteAsync(memory.ToArray(), context.RequestAborted).ConfigureAwait(false);
        }).AllowAnonymous();
    }
    public static bool HasScope(ClaimsPrincipal principal, string scope)
    {
        ArgumentNullException.ThrowIfNull(principal); ArgumentException.ThrowIfNullOrWhiteSpace(scope);
        return principal.Identity?.IsAuthenticated == true && principal.FindAll("scope").SelectMany(c => c.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries)).Contains(scope, StringComparer.Ordinal);
    }
}
