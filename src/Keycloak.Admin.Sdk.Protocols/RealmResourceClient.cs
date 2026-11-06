using System.Text;
using System.Text.Json;

namespace Keycloak.Admin.Sdk.Protocols;

/// <summary>Realm-local application resource contracts. JSON payloads preserve protocol-specific extension attributes.
/// Permission, consent, schema and business-effect verification are separate from this transport.</summary>
public sealed class RealmResourceClient
{
    private readonly ProtocolTransport transport;
    private readonly string prefix;
    private readonly string feature;
    private RealmResourceClient(ProtocolTransport transport, string prefix, string feature)
    { this.transport = transport ?? throw new ArgumentNullException(nameof(transport)); this.prefix = prefix; this.feature = feature; }

    public static RealmResourceClient ScimUsers(ProtocolTransport transport) => new(transport, "scim/v2/Users", "KeycloakSdk.Protocols.Scim");
    public static RealmResourceClient ScimGroups(ProtocolTransport transport) => new(transport, "scim/v2/Groups", "KeycloakSdk.Protocols.Scim");
    public static RealmResourceClient ClientRegistration(ProtocolTransport transport) => new(transport, "clients-registrations/openid-connect", "KeycloakSdk.Protocols.ClientRegistration");
    /// <summary>Deprecated upstream provider, retained for explicit compatibility workflows.</summary>
    public static RealmResourceClient DefaultClientRegistration(ProtocolTransport transport) => new(transport, "clients-registrations/default", "KeycloakSdk.Protocols.ClientRegistration");
    public static RealmResourceClient UmaResources(ProtocolTransport transport) => new(transport, "authz/protection/resource_set", "KeycloakSdk.Protocols.Uma");

    public Task<ProtocolResponse> ListAsync(string accessToken, IEnumerable<KeyValuePair<string, string>>? query = null, CancellationToken cancellationToken = default)
    {
        if (prefix.StartsWith("clients-registrations/", StringComparison.Ordinal)) throw new NotSupportedException("The dynamic registration service has no collection listing operation.");
        return SendAsync(HttpMethod.Get, prefix, "Resource.List", accessToken, null, query, cancellationToken);
    }
    public Task<ProtocolResponse> GetAsync(string id, string accessToken, CancellationToken cancellationToken = default)
        => SendAsync(HttpMethod.Get, Item(id), "Resource.Get", accessToken, null, null, cancellationToken);
    public Task<ProtocolResponse> GetAsync(string id, string accessToken, IEnumerable<KeyValuePair<string, string>> query, CancellationToken cancellationToken = default)
        => SendAsync(HttpMethod.Get, Item(id), "Resource.Get", accessToken, null, query, cancellationToken);
    public Task<ProtocolResponse> SearchAsync(JsonElement searchRequest, string accessToken, CancellationToken cancellationToken = default)
    {
        if (!prefix.StartsWith("scim/", StringComparison.Ordinal)) throw new NotSupportedException("POST .search is only declared for SCIM resources.");
        return SendAsync(HttpMethod.Post, prefix + "/.search", "Resource.Search", accessToken, searchRequest, null, cancellationToken);
    }
    public Task<ProtocolResponse> CreateAsync(JsonElement body, string? accessToken = null, CancellationToken cancellationToken = default)
        => SendAsync(HttpMethod.Post, prefix, "Resource.Create", accessToken, body, null, cancellationToken);
    public Task<ProtocolResponse> ReplaceAsync(string id, JsonElement body, string accessToken, CancellationToken cancellationToken = default)
        => SendAsync(HttpMethod.Put, Item(id), "Resource.Replace", accessToken, body, null, cancellationToken);
    public Task<ProtocolResponse> PatchAsync(string id, JsonElement body, string accessToken, CancellationToken cancellationToken = default)
    {
        if (!prefix.StartsWith("scim/", StringComparison.Ordinal)) throw new NotSupportedException("PATCH is only declared for SCIM resources.");
        return SendAsync(HttpMethod.Patch, Item(id), "Resource.Patch", accessToken, body, null, cancellationToken);
    }
    public Task<ProtocolResponse> DeleteAsync(string id, string accessToken, CancellationToken cancellationToken = default)
        => SendAsync(HttpMethod.Delete, Item(id), "Resource.Delete", accessToken, null, null, cancellationToken);
    private string Item(string id) => prefix + "/" + ProtocolTransport.Segment(id);
    private Task<ProtocolResponse> SendAsync(HttpMethod method, string path, string operation, string? token, JsonElement? body,
        IEnumerable<KeyValuePair<string, string>>? query, CancellationToken ct)
    {
        var content = body is null ? null : new StringContent(body.Value.GetRawText(), Encoding.UTF8,
            prefix.StartsWith("scim/", StringComparison.Ordinal) ? "application/scim+json" : "application/json");
        return transport.SendAsync(method, path, operation, feature, content, token, query, null, ct);
    }
}
