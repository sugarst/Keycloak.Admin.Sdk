using System.Text;
using System.Text.Json;

namespace Keycloak.Admin.Sdk.Protocols;

/// <summary>Runtime OpenAPI and declarative Client Admin API v2, independently tracked from the static Admin API operation catalog.
/// Client paths identify clientId, not the internal UUID used by the older Admin API.</summary>
public sealed class ClientAdminV2Client
{
    private readonly ProtocolTransport transport;
    private readonly string path;
    private const string Feature = "KeycloakSdk.Protocols.ClientAdminV2";
    public ClientAdminV2Client(ProtocolTransport transport)
    {
        this.transport = transport ?? throw new ArgumentNullException(nameof(transport));
        path = "admin/api/" + transport.RealmSegment + "/clients/v2";
    }
    public Task<ProtocolResponse> ListAsync(string token, IEnumerable<KeyValuePair<string, string>>? query = null, CancellationToken cancellationToken = default)
        => SendAsync(HttpMethod.Get, path, null, token, query, false, cancellationToken);
    public Task<ProtocolResponse> CreateAsync(JsonElement client, string token, CancellationToken cancellationToken = default)
        => SendAsync(HttpMethod.Post, path, client, token, null, false, cancellationToken);
    public Task<ProtocolResponse> GetAsync(string clientId, string token, CancellationToken cancellationToken = default)
        => SendAsync(HttpMethod.Get, Item(clientId), null, token, null, false, cancellationToken);
    public Task<ProtocolResponse> UpsertAsync(string clientId, JsonElement client, string token, CancellationToken cancellationToken = default)
        => SendAsync(HttpMethod.Put, Item(clientId), client, token, null, false, cancellationToken);
    public Task<ProtocolResponse> PatchAsync(string clientId, JsonElement mergePatch, string token, CancellationToken cancellationToken = default)
        => SendAsync(HttpMethod.Patch, Item(clientId), mergePatch, token, null, true, cancellationToken);
    public Task<ProtocolResponse> DeleteAsync(string clientId, string token, CancellationToken cancellationToken = default)
        => SendAsync(HttpMethod.Delete, Item(clientId), null, token, null, false, cancellationToken);
    private string Item(string id) => path + "/" + ProtocolTransport.Segment(id);
    private Task<ProtocolResponse> SendAsync(HttpMethod method, string target, JsonElement? body, string token, IEnumerable<KeyValuePair<string, string>>? query, bool patch, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);
        return transport.SendServerAsync(method, target, "ClientAdminV2." + method.Method, Feature,
            body is null ? null : new StringContent(body.Value.GetRawText(), Encoding.UTF8, patch ? "application/merge-patch+json" : "application/json"), token, query, ct);
    }
}
