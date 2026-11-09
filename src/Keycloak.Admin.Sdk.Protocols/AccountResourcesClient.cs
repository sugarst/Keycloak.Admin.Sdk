using System.Text;
using System.Text.Json;

namespace Keycloak.Admin.Sdk.Protocols;

/// <summary>UMA account-console resource ownership and sharing APIs. These calls require the current user's token, not a resource-server PAT.</summary>
public sealed class AccountResourcesClient(ProtocolTransport transport)
{
    private readonly ProtocolTransport transport = transport ?? throw new ArgumentNullException(nameof(transport));
    public Task<ProtocolResponse> GetOwnedAsync(string token, IEnumerable<KeyValuePair<string, string>>? query = null, CancellationToken cancellationToken = default)
        => GetAsync("account/resources", token, query, cancellationToken);
    public Task<ProtocolResponse> GetSharedWithMeAsync(string token, IEnumerable<KeyValuePair<string, string>>? query = null, CancellationToken cancellationToken = default)
        => GetAsync("account/resources/shared-with-me", token, query, cancellationToken);
    public Task<ProtocolResponse> GetSharedWithOthersAsync(string token, IEnumerable<KeyValuePair<string, string>>? query = null, CancellationToken cancellationToken = default)
        => GetAsync("account/resources/shared-with-others", token, query, cancellationToken);
    public Task<ProtocolResponse> GetPendingAsync(string token, CancellationToken cancellationToken = default)
        => GetAsync("account/resources/pending-requests", token, null, cancellationToken);
    public Task<ProtocolResponse> GetAsync(string resourceId, string token, CancellationToken cancellationToken = default)
        => GetAsync(Item(resourceId), token, null, cancellationToken);
    public Task<ProtocolResponse> GetPermissionsAsync(string resourceId, string token, CancellationToken cancellationToken = default)
        => GetAsync(Item(resourceId) + "/permissions", token, null, cancellationToken);
    public Task<ProtocolResponse> GetPermissionRequestsAsync(string resourceId, string token, CancellationToken cancellationToken = default)
        => GetAsync(Item(resourceId) + "/permissions/requests", token, null, cancellationToken);
    public Task<ProtocolResponse> FindPermissionUserAsync(string resourceId, string value, string token, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        return GetAsync(Item(resourceId) + "/user", token, [new("value", value)], cancellationToken);
    }
    public Task<ProtocolResponse> UpdatePermissionsAsync(string resourceId, JsonElement permissions, string token, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);
        return transport.SendAsync(HttpMethod.Put, Item(resourceId) + "/permissions", "Uma.AccountPermissions", "KeycloakSdk.Protocols.Uma",
            new StringContent(permissions.GetRawText(), Encoding.UTF8, "application/json"), token, null, null, cancellationToken);
    }
    private static string Item(string id) => "account/resources/" + ProtocolTransport.Segment(id);
    private Task<ProtocolResponse> GetAsync(string path, string token, IEnumerable<KeyValuePair<string, string>>? query, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);
        return transport.SendAsync(HttpMethod.Get, path, "Uma.AccountResources", "KeycloakSdk.Protocols.Uma", null, token, query, null, ct);
    }
}
