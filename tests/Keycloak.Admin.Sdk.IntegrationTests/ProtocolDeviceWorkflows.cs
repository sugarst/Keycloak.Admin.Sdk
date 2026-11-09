using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Protocols;

internal static class ProtocolDeviceWorkflows
{
    internal static async Task RunAsync(KeycloakAdminClient admin, ProtocolTransport transport, string realm, string secret, Action<bool, string> check, CancellationToken ct)
    {
        var oidc = new OidcClient(transport); const string id = "device-app";
        await admin.RealmAdmin.UpdateRealmAsync(realm, new RealmRepresentation { Oauth2DeviceCodeLifespan = 120, Oauth2DevicePollingInterval = 1 }, ct);
        await admin.Clients.CreateClientAsync(realm, new ClientRepresentation { ClientId = id, Protocol = "openid-connect", Enabled = true, PublicClient = false, Secret = secret, ConsentRequired = true,
            Attributes = new() { ["oauth2.device.authorization.grant.enabled"] = "true" }, ProtocolMappers = [new ProtocolMapperRepresentation { Name = "own-audience", Protocol = "openid-connect", ProtocolMapper = "oidc-audience-mapper",
                Config = new() { ["included.client.audience"] = id, ["access.token.claim"] = "true" } }] }, cancellationToken: ct);
        var auth = OAuthClientAuthentication.SecretBasic(id, _ => ValueTask.FromResult(secret));
        var response = await oidc.RequestDeviceCodeAsync(auth, "openid", ct); var lease = OAuthPollingLease.FromDeviceResponse(response);
        bool pending = false, slow = false;
        try { await oidc.RedeemDeviceCodeAsync(auth, lease.Identifier, ct); } catch (KeycloakProtocolException e) when (e.Error == OAuthError.AuthorizationPending) { pending = true; }
        try { await oidc.RedeemDeviceCodeAsync(auth, lease.Identifier, ct); } catch (KeycloakProtocolException e) when (e.Error == OAuthError.SlowDown) { slow = true; }
        check(pending && slow, "Device flow reports real authorization_pending and slow_down before the user approves the request");
        var completion = new Uri(oidc.Issuer.AbsoluteUri + "/device/status");
        var approval = await ProtocolBrowserFixture.LoginAsync(new(response.Json!.Value.GetProperty("verification_uri_complete").GetString()!), completion, "account-user", secret, ct);
        check(approval.Consented && approval.Callback.Query.Length == 0, "Device flow requires actual browser login and explicit user consent for the verification code");
        // Earlier deliberately-fast polling increased the server interval. Start the polling helper with the updated lease interval.
        var updated = System.Text.Json.Nodes.JsonNode.Parse(response.Json.Value.GetRawText())!; updated["interval"] = (int)lease.Interval.TotalSeconds + 5;
        using var document = System.Text.Json.JsonDocument.Parse(updated.ToJsonString());
        var tokens = await oidc.PollDeviceAsync(auth, OAuthPollingLease.FromDeviceResponse(new(response.StatusCode, document.RootElement)), cancellationToken: ct);
        var identity = await new KeycloakAccessTokenValidator(oidc, id).ValidateAsync(tokens.Json!.Value.GetProperty("access_token").GetString()!, ct);
        var user = (await admin.Users.GetUsersAsync(realm, username: "account-user", exact: true, cancellationToken: ct)).Body!.Single();
        check(identity.Subject == user.Id, "Device polling completes with an independently verified token for the consenting user");
        bool reused = false;
        try { await oidc.RedeemDeviceCodeAsync(auth, lease.Identifier, ct); } catch (KeycloakProtocolException e) when (e.Error is OAuthError.InvalidGrant or OAuthError.ExpiredToken) { reused = true; }
        check(reused, "Device authorization credentials cannot be redeemed again after successful issuance");
        // A different client has no previous consent to silently reuse.
        await admin.Clients.CreateClientAsync(realm, new ClientRepresentation { ClientId = "device-denied-app", Protocol = "openid-connect", Enabled = true, PublicClient = false, Secret = secret, ConsentRequired = true,
            Attributes = new() { ["oauth2.device.authorization.grant.enabled"] = "true" } }, cancellationToken: ct);
        var deniedAuth = OAuthClientAuthentication.SecretBasic("device-denied-app", _ => ValueTask.FromResult(secret));
        var deniedResponse = await oidc.RequestDeviceCodeAsync(deniedAuth, "openid", ct);
        var deniedCallback = await ProtocolBrowserFixture.DenyConsentAsync(new(deniedResponse.Json!.Value.GetProperty("verification_uri_complete").GetString()!), completion, "account-user", secret, ct);
        bool denied = false;
        try { await oidc.RedeemDeviceCodeAsync(deniedAuth, OAuthPollingLease.FromDeviceResponse(deniedResponse).Identifier, ct); }
        catch (KeycloakProtocolException e) when (e.Error == OAuthError.AccessDenied) { denied = true; }
        check(denied && deniedCallback.Query.Contains("error=access_denied", StringComparison.Ordinal), "Device consent denial yields access_denied and no user credential");
        await admin.RealmAdmin.UpdateRealmAsync(realm, new RealmRepresentation { Oauth2DeviceCodeLifespan = 1 }, ct);
        var expiring = await oidc.RequestDeviceCodeAsync(auth, "openid", ct); await Task.Delay(TimeSpan.FromSeconds(2), ct);
        bool expired = false;
        try { await oidc.RedeemDeviceCodeAsync(auth, OAuthPollingLease.FromDeviceResponse(expiring).Identifier, ct); }
        catch (KeycloakProtocolException e) when (e.Error == OAuthError.ExpiredToken) { expired = true; }
        check(expired, "Device authorization rejects a real server-expired device credential");
        await admin.RealmAdmin.UpdateRealmAsync(realm, new RealmRepresentation { Oauth2DeviceCodeLifespan = 120 }, ct);
    }
}
