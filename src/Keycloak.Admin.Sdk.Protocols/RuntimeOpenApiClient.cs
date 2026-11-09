namespace Keycloak.Admin.Sdk.Protocols;

/// <summary>Runtime OpenAPI is exposed on Keycloak's separately configured management endpoint.
/// Supply a transport bound to that explicit management URL. No realm administrator credential is forwarded.</summary>
public sealed class RuntimeOpenApiClient(ProtocolTransport managementTransport)
{
    private readonly ProtocolTransport transport = managementTransport ?? throw new ArgumentNullException(nameof(managementTransport));
    public Task<ProtocolResponse> GetAsync(CancellationToken cancellationToken = default)
        => transport.SendServerAsync(HttpMethod.Get, "openapi", "OpenApi.Read", "KeycloakSdk.Protocols.OpenApi", null, null, null, cancellationToken);
}
