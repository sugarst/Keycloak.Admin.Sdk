namespace Keycloak.Admin.Sdk.Protocols;

/// <summary>SCIM v2 discovery complements the Users/Groups resource clients. Extensions remain intact in JSON.</summary>
public sealed class ScimClient(ProtocolTransport transport)
{
    private readonly ProtocolTransport transport = transport ?? throw new ArgumentNullException(nameof(transport));
    public Task<ProtocolResponse> GetServiceProviderConfigurationAsync(string token, CancellationToken cancellationToken = default)
        => GetAsync("ServiceProviderConfig", token, cancellationToken);
    public Task<ProtocolResponse> GetSchemasAsync(string token, CancellationToken cancellationToken = default)
        => GetAsync("Schemas", token, cancellationToken);
    public Task<ProtocolResponse> GetSchemaAsync(string id, string token, CancellationToken cancellationToken = default)
        => GetAsync("Schemas/" + ProtocolTransport.Segment(id), token, cancellationToken);
    public Task<ProtocolResponse> GetResourceTypesAsync(string token, CancellationToken cancellationToken = default)
        => GetAsync("ResourceTypes", token, cancellationToken);
    /// <summary>26.8.1's individual ResourceTypes provider throws UnsupportedOperationException.
    /// Resolve the exact id from its authorized collection instead of calling the broken server route.</summary>
    public async Task<ProtocolResponse> GetResourceTypeAsync(string id, string token, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);
        var response = await GetResourceTypesAsync(token, cancellationToken).ConfigureAwait(false);
        var json = response.Json ?? throw new InvalidDataException("Empty SCIM resource types.");
        var item = json.GetProperty("Resources").EnumerateArray().SingleOrDefault(r => r.GetProperty("id").GetString() == id);
        if (item.ValueKind == System.Text.Json.JsonValueKind.Undefined)
            throw new KeycloakProtocolException(System.Net.HttpStatusCode.NotFound, "Scim.ResourceType");
        return new(response.StatusCode, item.Clone());
    }
    private Task<ProtocolResponse> GetAsync(string suffix, string token, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);
        return transport.SendAsync(HttpMethod.Get, "scim/v2/" + suffix, "Scim.Discovery", "KeycloakSdk.Protocols.Scim", null, token, null, null, ct);
    }
}
