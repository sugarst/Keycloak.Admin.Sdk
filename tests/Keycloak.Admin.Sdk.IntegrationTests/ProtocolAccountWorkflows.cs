using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Protocols;

internal static class ProtocolAccountWorkflows
{
    internal static async Task RunAsync(KeycloakAdminClient admin, HttpClient http, Uri server, ProtocolTransport transport, string realm, string secret, string userToken,
        Action<bool, string> check, CancellationToken ct)
    {
        var account = new AccountClient(transport);
        var user = (await admin.Users.GetUsersAsync(realm, username: "account-user", exact: true, cancellationToken: ct)).Body!.Single();
        JsonElement Element(JsonNode value) { using var doc = JsonDocument.Parse(value.ToJsonString()); return doc.RootElement.Clone(); }
        async Task<JsonNode?> Setup(HttpMethod method, string path, JsonNode? body = null)
        {
            var response = await admin.SendAsync(method, "/admin/realms/" + realm + "/" + path,
                content: body is null ? null : new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json"), cancellationToken: ct);
            return response.Content.IsEmpty ? null : JsonNode.Parse(response.Content.Span);
        }
        await admin.RealmAdmin.UpdateRealmAsync(realm, new() { InternationalizationEnabled = true, SupportedLocales = ["en", "zh-CN"], OrganizationsEnabled = true }, ct);
        var profile = (await account.GetProfileAsync(userToken, [new("userProfileMetadata", "false")], ct)).Json!.Value;
        check(profile.GetProperty("id").GetString() == user.Id && !profile.TryGetProperty("userProfileMetadata", out _)
            && (await account.GetSupportedLocalesAsync(userToken, ct)).Json!.Value.EnumerateArray().Any(l => l.GetString() == "zh-CN"),
            "Account profile projection and realm locales use the authenticated user context");
        await Setup(HttpMethod.Post, "groups", new JsonObject { ["name"] = "account-own-group" });
        string groupId = (await Setup(HttpMethod.Get, "groups"))!.AsArray().Single(g => g!["name"]!.GetValue<string>() == "account-own-group")!["id"]!.GetValue<string>();
        await Setup(HttpMethod.Put, "users/" + user.Id + "/groups/" + groupId);
        check((await account.GetGroupsAsync(userToken, ct)).Json!.Value.EnumerateArray().Any(g => g.GetProperty("id").GetString() == groupId), "Account groups show the user's actual persisted membership");
        var organization = await Setup(HttpMethod.Post, "organizations", new JsonObject { ["name"] = "Account Organization", ["alias"] = "account-org", ["enabled"] = true });
        string organizationId = organization?["id"]?.GetValue<string>() ?? (await Setup(HttpMethod.Get, "organizations"))![0]!["id"]!.GetValue<string>();
        await Setup(HttpMethod.Post, "organizations/" + organizationId + "/members", JsonValue.Create(user.Id));
        check((await account.GetOrganizationsAsync(userToken, ct)).Json!.Value.EnumerateArray().Any(o => o.GetProperty("id").GetString() == organizationId), "Account organizations expose the user's real organization membership");
        await admin.Clients.CreateClientAsync(realm, new ClientRepresentation { ClientId = "self-service-app", Name = "self-service-app", Enabled = true, PublicClient = true, ConsentRequired = true, Protocol = "openid-connect" }, cancellationToken: ct);
        var scopes = await Setup(HttpMethod.Get, "client-scopes");
        string scopeId = scopes!.AsArray().Single(s => s!["name"]!.GetValue<string>() == "profile")!["id"]!.GetValue<string>();
        var consent = new JsonObject { ["grantedScopes"] = new JsonArray(new JsonObject { ["id"] = scopeId }) };
        await account.UpdateConsentAsync("self-service-app", Element(consent), userToken, ct);
        var granted = (await account.GetConsentAsync("self-service-app", userToken, ct)).Json!.Value;
        check(granted.GetProperty("grantedScopes").EnumerateArray().Any(s => s.GetProperty("id").GetString() == scopeId)
            && (await account.GetApplicationsAsync(userToken, [new("name", "self-service-app")], ct)).Json!.Value.EnumerateArray().Any(a => a.GetProperty("clientId").GetString() == "self-service-app"),
            "Account consent writes persist and make the application visible");
        await account.RevokeConsentAsync("self-service-app", userToken, ct);
        check((await account.GetConsentAsync("self-service-app", userToken, ct)).Json is null, "Account consent revocation removes the persisted grant");
        await admin.IdentityProviders.CreateAsync(realm, new IdentityProviderRepresentation { Alias = "account-broker", ProviderId = "oidc", Enabled = true,
            Config = new() { ["clientId"] = "no-remote-login", ["authorizationUrl"] = new Uri(server, "realms/master/protocol/openid-connect/auth").AbsoluteUri,
                ["tokenUrl"] = new Uri(server, "realms/master/protocol/openid-connect/token").AbsoluteUri } }, ct);
        await admin.User.AddFederatedIdentityAsync(realm, user.Id!, "account-broker", new FederatedIdentityRepresentation { IdentityProvider = "account-broker", UserId = "external-account-user", UserName = "external-user" }, ct);
        check((await account.GetLinkedAccountsAsync(userToken, [new("linked", "true")], ct)).Json!.Value.EnumerateArray().Any(a => a.GetProperty("providerAlias").GetString() == "account-broker" && a.GetProperty("connected").GetBoolean()),
            "Account linked-account discovery reflects the real federated identity");
        await account.UnlinkAccountAsync("account-broker", userToken, ct);
        check((await admin.User.GetFederatedIdentityAsync(realm, user.Id!, ct)).Body!.Count == 0, "Account unlink removes only the current user's federated identity");
        await admin.User.UpdateUserAsync(realm, user.Id!, new UserRepresentation { Credentials = [new CredentialRepresentation { Type = "otp", UserLabel = "self-otp",
            SecretData = "{\"value\":\"JBSWY3DPEHPK3PXP\"}", CredentialData = "{\"subType\":\"totp\",\"digits\":6,\"counter\":0,\"period\":30,\"algorithm\":\"HmacSHA1\"}" }] }, ct);
        var credentials = (await account.GetCredentialsAsync(userToken, [new("type", "otp"), new("user-credentials", "true")], ct)).Json!.Value;
        string otpId = credentials.EnumerateArray().Single(c => c.GetProperty("type").GetString() == "otp").GetProperty("userCredentialMetadatas")[0].GetProperty("credential").GetProperty("id").GetString()!;
        await account.SetCredentialLabelAsync(otpId, "User renamed OTP", userToken, ct);
        check((await admin.User.CredentialsAsync(realm, user.Id!, ct)).Body!.Any(c => c.Id == otpId && c.UserLabel == "User renamed OTP"), "Account credential label updates persist on the user's actual OTP credential");
        await account.DeleteCredentialAsync(otpId, userToken, ct);
        check((await admin.User.CredentialsAsync(realm, user.Id!, ct)).Body!.All(c => c.Id != otpId), "Account credential deletion removes the selected OTP while preserving password authentication");
        await account.RevokeApplicationSessionsAsync("browser-app", userToken, ct);
        var sessions = (await account.GetSessionsAsync(userToken, ct)).Json!.Value;
        check(sessions.EnumerateArray().All(s => s.GetProperty("clients").EnumerateArray().All(c => c.GetProperty("clientId").GetString() != "browser-app")), "Account application-session revocation removes browser-app sessions without ending the current session");
        string otherSession = sessions.EnumerateArray().First(s => !s.TryGetProperty("current", out var current) || !current.GetBoolean()).GetProperty("id").GetString()!;
        await account.DeleteSessionAsync(otherSession, userToken, ct);
        check((await account.GetSessionsAsync(userToken, ct)).Json!.Value.EnumerateArray().All(s => s.GetProperty("id").GetString() != otherSession)
            && (await account.GetDevicesAsync(userToken, ct)).Json!.Value.ValueKind == JsonValueKind.Array, "Account single-session deletion persists and device discovery remains authorized");
        await admin.Users.CreateUserAsync(realm, new UserRepresentation { Username = "account-other", Enabled = true, FirstName = "Other", LastName = "User", Email = "other@example.invalid", EmailVerified = true,
            Credentials = [new CredentialRepresentation { Type = "password", Value = secret, Temporary = false }] }, cancellationToken: ct);
        using var form = new FormUrlEncodedContent(new Dictionary<string, string> { ["grant_type"] = "password", ["client_id"] = "sdk-protocols", ["client_secret"] = secret, ["username"] = "account-other", ["password"] = secret });
        using var reply = await http.PostAsync(new Uri(transport.Issuer.AbsoluteUri + "/protocol/openid-connect/token"), form, ct); reply.EnsureSuccessStatusCode();
        var other = (await admin.Users.GetUsersAsync(realm, username: "account-other", exact: true, cancellationToken: ct)).Body!.Single();
        string otherUserSession = (await admin.User.GetSessionsAsync(realm, other.Id!, ct)).Body!.Single().Id!;
        string otherCredential = (await admin.User.CredentialsAsync(realm, other.Id!, ct)).Body!.Single().Id!;
        await account.DeleteSessionAsync(otherUserSession, userToken, ct); // Pinned server deliberately returns 204 without revealing ownership.
        bool otherCredentialDenied = false;
        try { await account.SetCredentialLabelAsync(otherCredential, "Forbidden", userToken, ct); }
        catch (KeycloakProtocolException e) when (e.StatusCode == HttpStatusCode.NotFound) { otherCredentialDenied = true; }
        check(otherCredentialDenied && (await admin.User.GetSessionsAsync(realm, other.Id!, ct)).Body!.Any(s => s.Id == otherUserSession)
            && (await admin.User.CredentialsAsync(realm, other.Id!, ct)).Body!.All(c => c.UserLabel != "Forbidden"), "Account cross-user session and credential operations leave the other user's data unchanged");
        await account.DeleteSessionsAsync(false, userToken, ct);
        check((await account.GetProfileAsync(userToken, ct)).Json!.Value.GetProperty("id").GetString() == user.Id, "Account logout-other-sessions preserves the authenticated current session");
        await account.DeleteSessionsAsync(true, userToken, ct);
        bool loggedOut = false;
        try { await account.GetProfileAsync(userToken, ct); }
        catch (KeycloakProtocolException e) when (e.StatusCode == HttpStatusCode.Unauthorized) { loggedOut = true; }
        check(loggedOut, "Account logout-all-sessions invalidates the current account token");
    }
}
