namespace Keycloak.Admin.Sdk.Protocols;

/// <summary>Credential entitlement and issued-credential lifecycle for the current account, without admin credentials.</summary>
public sealed class Oid4vcAccountClient(ProtocolTransport transport)
{
    private readonly ProtocolTransport transport = transport ?? throw new ArgumentNullException(nameof(transport));
    public Task<ProtocolResponse> GetEntitlementsAsync(string accessToken, CancellationToken cancellationToken = default)
        => SendAsync(HttpMethod.Get, "verifiable-credentials", accessToken, cancellationToken);
    public Task<ProtocolResponse> RevokeEntitlementAsync(string credentialScopeName, string accessToken, CancellationToken cancellationToken = default)
        => SendAsync(HttpMethod.Delete, "verifiable-credentials/" + ProtocolTransport.Segment(credentialScopeName), accessToken, cancellationToken);
    public Task<ProtocolResponse> GetIssuedCredentialsAsync(string accessToken, CancellationToken cancellationToken = default)
        => SendAsync(HttpMethod.Get, "issued-verifiable-credentials", accessToken, cancellationToken);
    public Task<ProtocolResponse> RevokeIssuedCredentialAsync(string credentialId, string accessToken, CancellationToken cancellationToken = default)
        => SendAsync(HttpMethod.Delete, "issued-verifiable-credentials/" + ProtocolTransport.Segment(credentialId), accessToken, cancellationToken);
    private Task<ProtocolResponse> SendAsync(HttpMethod method, string path, string accessToken, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);
        return transport.SendAsync(method, "account/" + path, "Wallet.Account", Oid4vcIssuerClient.Feature, null, accessToken, null, null, ct, ["KeycloakSdk.Protocols.Account"]);
    }
}
