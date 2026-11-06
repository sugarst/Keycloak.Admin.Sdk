using System.Text.Json;

namespace Keycloak.Admin.Sdk.Protocols;

/// <summary>Credential-specific grants, separate from ordinary OIDC tokens and independently gated by their server feature.</summary>
public sealed class Oid4vcTokenClient(ProtocolTransport transport)
{
    private readonly ProtocolTransport transport = transport ?? throw new ArgumentNullException(nameof(transport));
    public Task<ProtocolResponse> RedeemPreAuthorizedCodeAsync(OAuthClientAuthentication client, string code, string? transactionCode = null,
        JsonElement? authorizationDetails = null, CancellationToken cancellationToken = default)
    {
        WalletJson.Credential(code);
        var form = new Dictionary<string, string> { ["grant_type"] = "urn:ietf:params:oauth:grant-type:pre-authorized_code", ["pre-authorized_code"] = code };
        if (transactionCode is not null) { WalletJson.Text(transactionCode); form["tx_code"] = transactionCode; }
        if (authorizationDetails is not null) form["authorization_details"] = new OidcAuthorizationOptions { AuthorizationDetails = authorizationDetails }.Parameters().Single().Value;
        return GrantAsync(client, form, "Wallet.PreAuthorizedCode", ["KeycloakSdk.Protocols.WalletPreAuthorized"], cancellationToken);
    }
    /// <summary>Refreshes an OID4VCI token with the normal OAuth refresh_token grant. The issuer preserves credential authorization and enforces revocation.</summary>
    public Task<ProtocolResponse> RefreshCredentialTokenAsync(OAuthClientAuthentication client, string refreshToken, CancellationToken cancellationToken = default)
    {
        WalletJson.Credential(refreshToken);
        return GrantAsync(client, new() { ["grant_type"] = "refresh_token", ["refresh_token"] = refreshToken }, "Wallet.RefreshCredentialToken", [], cancellationToken);
    }
    private Task<ProtocolResponse> GrantAsync(OAuthClientAuthentication client, Dictionary<string, string> form, string operation, string[] features, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(client);
        return transport.SendAsync(HttpMethod.Post, "protocol/openid-connect/token", operation, Oid4vcIssuerClient.Feature, null, null, null, async (request, token) =>
        {
            await client.ApplyAsync(request, form, token).ConfigureAwait(false); request.Content = new FormUrlEncodedContent(form);
        }, ct, ["KeycloakSdk.Protocols.Oidc", .. features, .. client.RequiredFeatures]);
    }
}
