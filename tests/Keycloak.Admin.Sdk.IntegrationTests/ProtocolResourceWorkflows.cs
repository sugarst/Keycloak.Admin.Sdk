using System.Text.Json;
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Protocols;

internal static class ProtocolResourceWorkflows
{
    internal static async Task RunAsync(KeycloakAdminClient admin, ProtocolTransport transport, string realm, string secret, Action<bool, string> check, CancellationToken ct)
    {
        var oidc = new OidcClient(transport); var first = new Uri("https://resources.invalid/first"); var second = new Uri("https://resources.invalid/second");
        var callback = new Uri("https://resources.invalid/callback");
        await admin.Clients.CreateClientAsync(realm, new ClientRepresentation { ClientId = "resource-client", Enabled = true, Protocol = "openid-connect", PublicClient = false,
            Secret = secret, ServiceAccountsEnabled = true, StandardFlowEnabled = true, RedirectUris = [callback.AbsoluteUri],
            ProtocolMappers = new[] { first, second }.Select((uri, i) => new ProtocolMapperRepresentation { Name = "resource-" + i, Protocol = "openid-connect", ProtocolMapper = "oidc-audience-mapper",
                Config = new() { ["included.custom.audience"] = uri.AbsoluteUri, ["access.token.claim"] = "true" } }).ToList() }, cancellationToken: ct);
        var client = OAuthClientAuthentication.SecretBasic("resource-client", _ => ValueTask.FromResult(secret));
        string Access(ProtocolResponse response) => response.Json!.Value.GetProperty("access_token").GetString()!;
        var credential = await oidc.ClientCredentialsAsync(client, cancellationToken: ct, resources: [first]);
        var verified = await new KeycloakAccessTokenValidator(oidc, first.AbsoluteUri).ValidateAsync(Access(credential), ct);
        bool wrongAudience = false;
        try { await new KeycloakAccessTokenValidator(oidc, second.AbsoluteUri).ValidateAsync(Access(credential), ct); } catch (InvalidDataException) { wrongAudience = true; }
        check(wrongAudience && OnlyAudience(verified.Claims, first.AbsoluteUri), "Resource indicators narrow a real client-credentials token to exactly the requested authorized resource");
        bool arbitraryResource = false;
        try { await oidc.ClientCredentialsAsync(client, cancellationToken: ct, resources: [new("https://attacker.invalid/resource")]); }
        catch (KeycloakProtocolException error) when (error.Error == OAuthError.InvalidTarget) { arbitraryResource = true; }
        check(arbitraryResource, "Resource indicators reject an audience that was never granted to the client");
        var transaction = new OidcLoginTransaction(oidc, "resource-client", callback, options: new() { Resources = [first] });
        var login = await ProtocolBrowserFixture.LoginAsync(transaction.AuthorizationUri, callback, "account-user", secret, ct);
        var result = await transaction.CompleteAsync(login.Callback, client, new(oidc, "resource-client"), ct);
        var browserToken = await new KeycloakAccessTokenValidator(oidc, first.AbsoluteUri).ValidateAsync(Access(result.Tokens), ct);
        check(browserToken.Subject == result.Identity.Subject && OnlyAudience(browserToken.Claims, first.AbsoluteUri), "Resource indicators bind the actual browser authorization code and its verified access-token audience");
        string refresh = result.Tokens.Json!.Value.GetProperty("refresh_token").GetString()!;
        bool broaden = false;
        try { await oidc.RefreshAsync(client, refresh, cancellationToken: ct, resources: [second]); }
        catch (KeycloakProtocolException error) when (error.Error == OAuthError.InvalidTarget) { broaden = true; }
        var refreshed = await oidc.RefreshAsync(client, refresh, cancellationToken: ct);
        var refreshedIdentity = await new KeycloakAccessTokenValidator(oidc, first.AbsoluteUri).ValidateAsync(Access(refreshed), ct);
        check(broaden && OnlyAudience(refreshedIdentity.Claims, first.AbsoluteUri), "Resource-constrained refresh inherits the original audience and refuses switching to another otherwise authorized resource");
    }
    private static bool OnlyAudience(JsonElement claims, string audience)
    { var value = claims.GetProperty("aud"); return value.ValueKind == JsonValueKind.String ? value.GetString() == audience : value.GetArrayLength() == 1 && value[0].GetString() == audience; }
}
