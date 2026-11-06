using System.Net;
using System.Text;
using System.Text.Json;

namespace Keycloak.Admin.Sdk.Protocols;

public enum UmaResponseMode { Token, Decision, Permissions }

/// <summary>UMA protection, persistent permission tickets and runtime authorization. PATs and end-user tokens are explicit and separate.</summary>
public sealed class UmaClient(ProtocolTransport transport)
{
    private readonly ProtocolTransport transport = transport ?? throw new ArgumentNullException(nameof(transport));
    private const string Feature = "KeycloakSdk.Protocols.Uma";
    private const string Tickets = "authz/protection/permission/ticket";
    private const string Policies = "authz/protection/uma-policy";
    public Task<ProtocolResponse> DiscoverAsync(CancellationToken cancellationToken = default)
        => transport.SendAsync(HttpMethod.Get, ".well-known/uma2-configuration", "Uma.Discover", Feature, null, null, null, null, cancellationToken);
    public Task<ProtocolResponse> CreatePermissionAsync(JsonElement permissions, string token, CancellationToken cancellationToken = default)
        => JsonAsync(HttpMethod.Post, "authz/protection/permission", permissions, token, cancellationToken);
    public Task<ProtocolResponse> CreateTicketAsync(JsonElement ticket, string protectionToken, CancellationToken cancellationToken = default)
        => JsonAsync(HttpMethod.Post, Tickets, ticket, protectionToken, cancellationToken);
    public Task<ProtocolResponse> UpdateTicketAsync(JsonElement ticket, string protectionToken, CancellationToken cancellationToken = default)
        => JsonAsync(HttpMethod.Put, Tickets, ticket, protectionToken, cancellationToken);
    public Task<ProtocolResponse> DeleteTicketAsync(string id, string protectionToken, CancellationToken cancellationToken = default)
        => JsonAsync(HttpMethod.Delete, Tickets + "/" + ProtocolTransport.Segment(id), null, protectionToken, cancellationToken);
    public Task<ProtocolResponse> GetTicketsAsync(string protectionToken, IEnumerable<KeyValuePair<string, string>>? query = null, CancellationToken cancellationToken = default)
        => GetAsync(Tickets, protectionToken, query, cancellationToken);
    public Task<ProtocolResponse> CountTicketsAsync(string protectionToken, IEnumerable<KeyValuePair<string, string>>? query = null, CancellationToken cancellationToken = default)
        => GetAsync(Tickets + "/count", protectionToken, query, cancellationToken);
    public Task<ProtocolResponse> CreatePolicyAsync(string resourceId, JsonElement policy, string ownerToken, CancellationToken cancellationToken = default)
        => JsonAsync(HttpMethod.Post, Policies + "/" + ProtocolTransport.Segment(resourceId), policy, ownerToken, cancellationToken);
    public Task<ProtocolResponse> GetPolicyAsync(string policyId, string ownerToken, CancellationToken cancellationToken = default)
        => GetAsync(Policies + "/" + ProtocolTransport.Segment(policyId), ownerToken, null, cancellationToken);
    public Task<ProtocolResponse> UpdatePolicyAsync(string policyId, JsonElement policy, string ownerToken, CancellationToken cancellationToken = default)
        => JsonAsync(HttpMethod.Put, Policies + "/" + ProtocolTransport.Segment(policyId), policy, ownerToken, cancellationToken);
    public Task<ProtocolResponse> DeletePolicyAsync(string policyId, string ownerToken, CancellationToken cancellationToken = default)
        => JsonAsync(HttpMethod.Delete, Policies + "/" + ProtocolTransport.Segment(policyId), null, ownerToken, cancellationToken);
    public Task<ProtocolResponse> GetPoliciesAsync(string ownerToken, IEnumerable<KeyValuePair<string, string>>? query = null, CancellationToken cancellationToken = default)
        => GetAsync(Policies, ownerToken, query, cancellationToken);

    /// <summary>Requests an RPT, explicit permission list or decision. Omitted permissions and tickets are left to server policy.
    /// No decision is cached. Existing RPTs are credentials and must stay in the current user's session.</summary>
    public Task<ProtocolResponse> AuthorizeAsync(string userToken, string audience, IEnumerable<string>? permissions = null, string? ticket = null,
        UmaResponseMode responseMode = UmaResponseMode.Token, string? existingRpt = null, bool submitRequest = false, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userToken); ArgumentException.ThrowIfNullOrWhiteSpace(audience);
        if (!Enum.IsDefined(responseMode)) throw new ArgumentOutOfRangeException(nameof(responseMode));
        var form = new List<KeyValuePair<string, string>> { new("grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket"), new("audience", audience),
            new("submit_request", submitRequest ? "true" : "false") };
        foreach (string permission in permissions ?? []) { ArgumentException.ThrowIfNullOrWhiteSpace(permission); form.Add(new("permission", permission)); }
        if (ticket is not null) { ArgumentException.ThrowIfNullOrWhiteSpace(ticket); form.Add(new("ticket", ticket)); }
        if (existingRpt is not null) { ArgumentException.ThrowIfNullOrWhiteSpace(existingRpt); form.Add(new("rpt", existingRpt)); }
        if (responseMode != UmaResponseMode.Token) form.Add(new("response_mode", responseMode == UmaResponseMode.Decision ? "decision" : "permissions"));
        return transport.SendAsync(HttpMethod.Post, "protocol/openid-connect/token", "Uma.Authorize", Feature,
            new FormUrlEncodedContent(form), userToken, null, null, cancellationToken);
    }
    public async Task<bool> EvaluateAsync(string userToken, string audience, IEnumerable<string> permissions, CancellationToken cancellationToken = default)
    {
        try
        {
            var response = await AuthorizeAsync(userToken, audience, permissions, responseMode: UmaResponseMode.Decision, cancellationToken: cancellationToken).ConfigureAwait(false);
            return (response.Json ?? throw new InvalidDataException("Empty UMA decision.")).GetProperty("result").GetBoolean();
        }
        catch (KeycloakProtocolException e) when (e.StatusCode == HttpStatusCode.Forbidden && e.Error == OAuthError.AccessDenied) { return false; }
    }
    private Task<ProtocolResponse> JsonAsync(HttpMethod method, string path, JsonElement? body, string token, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);
        return transport.SendAsync(method, path, "Uma.Protection", Feature, body is null ? null : new StringContent(body.Value.GetRawText(), Encoding.UTF8, "application/json"), token, null, null, ct);
    }
    private Task<ProtocolResponse> GetAsync(string path, string token, IEnumerable<KeyValuePair<string, string>>? query, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);
        return transport.SendAsync(HttpMethod.Get, path, "Uma.Tickets", Feature, null, token, query, null, ct);
    }
}
