using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Protocols;

internal static class ProtocolUmaAccountWorkflows
{
    internal static async Task RunAsync(KeycloakAdminClient admin, HttpClient http, ProtocolTransport transport, string realm, string secret, string ownerToken, string pat,
        string ownerId, Action<bool, string> check, CancellationToken ct)
    {
        var resources = RealmResourceClient.UmaResources(transport); var uma = new UmaClient(transport); var account = new AccountResourcesClient(transport);
        JsonElement Element(JsonNode value) { using var doc = JsonDocument.Parse(value.ToJsonString()); return doc.RootElement.Clone(); }
        var resource = new JsonObject { ["name"] = "user-owned-document", ["ownerManagedAccess"] = true,
            ["resource_scopes"] = new JsonArray(new JsonObject { ["name"] = "read" }) };
        using var ownerForm = new FormUrlEncodedContent(new Dictionary<string, string> { ["grant_type"] = "password", ["client_id"] = "uma-app", ["client_secret"] = secret, ["username"] = "account-user", ["password"] = secret });
        using var ownerReply = await http.PostAsync(new Uri(transport.Issuer.AbsoluteUri + "/protocol/openid-connect/token"), ownerForm, ct); ownerReply.EnsureSuccessStatusCode();
        using var ownerTokens = JsonDocument.Parse(await ownerReply.Content.ReadAsStringAsync(ct)); string ownerProtectionToken = ownerTokens.RootElement.GetProperty("access_token").GetString()!;
        string id = (await resources.CreateAsync(Element(resource), ownerProtectionToken, ct)).Json!.Value.GetProperty("_id").GetString()!;
        check((await account.GetOwnedAsync(ownerToken, [new("name", "user-owned-document"), new("first", "0"), new("max", "10")], ct)).Json!.Value.GetArrayLength() == 1
            && (await account.GetAsync(id, ownerToken, ct)).Json!.Value.GetProperty("name").GetString() == "user-owned-document"
            && (await account.FindPermissionUserAsync(id, "account-user", ownerToken, ct)).Json!.Value.GetProperty("id").GetString() == ownerId,
            "UMA account ownership listing resource detail and owner lookup use the current user's identity");
        await admin.Users.CreateUserAsync(realm, new UserRepresentation { Username = "uma-requester", Enabled = true, FirstName = "Requester", LastName = "User", Email = "uma-requester@example.invalid", EmailVerified = true,
            Credentials = [new CredentialRepresentation { Type = "password", Value = secret, Temporary = false }] }, cancellationToken: ct);
        var requester = (await admin.Users.GetUsersAsync(realm, username: "uma-requester", exact: true, cancellationToken: ct)).Body!.Single();
        using var form = new FormUrlEncodedContent(new Dictionary<string, string> { ["grant_type"] = "password", ["client_id"] = "sdk-protocols", ["client_secret"] = secret, ["username"] = "uma-requester", ["password"] = secret });
        using var reply = await http.PostAsync(new Uri(transport.Issuer.AbsoluteUri + "/protocol/openid-connect/token"), form, ct); reply.EnsureSuccessStatusCode();
        using var tokens = JsonDocument.Parse(await reply.Content.ReadAsStringAsync(ct)); string requesterToken = tokens.RootElement.GetProperty("access_token").GetString()!;
        await uma.CreateTicketAsync(Element(new JsonObject { ["resource"] = id, ["scopeName"] = "read", ["requester"] = requester.Id, ["granted"] = false }), pat, ct);
        check((await account.GetPermissionRequestsAsync(id, ownerToken, ct)).Json!.Value.EnumerateArray().Any(p => p.GetProperty("username").GetString() == "uma-requester")
            && (await account.GetPendingAsync(requesterToken, ct)).Json!.Value.GetArrayLength() > 0
            && (await account.FindPermissionUserAsync(id, "uma-requester", ownerToken, ct)).Json!.Value.GetProperty("id").GetString() == requester.Id,
            "UMA owner sees the actual pending requester and scoped user lookup");
        var permissions = new JsonArray(new JsonObject { ["username"] = "uma-requester", ["scopes"] = new JsonArray("read") });
        await account.UpdatePermissionsAsync(id, Element(permissions), ownerToken, ct);
        check((await account.GetPermissionsAsync(id, ownerToken, ct)).Json!.Value.EnumerateArray().Any(p => p.GetProperty("username").GetString() == "uma-requester")
            && (await account.GetSharedWithOthersAsync(ownerToken, cancellationToken: ct)).Json!.Value.GetArrayLength() > 0
            && (await account.GetSharedWithMeAsync(requesterToken, cancellationToken: ct)).Json!.Value.GetArrayLength() > 0,
            "UMA account permission approval persists and updates both sides of resource sharing");
        bool notOwner = false;
        try { await account.UpdatePermissionsAsync(id, Element(permissions), requesterToken, ct); }
        catch (KeycloakProtocolException e) when (e.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.Forbidden) { notOwner = true; }
        check(notOwner, "UMA requester cannot change the owner's resource permissions");
        permissions[0]!["scopes"] = new JsonArray();
        await account.UpdatePermissionsAsync(id, Element(permissions), ownerToken, ct);
        check((await account.GetPermissionsAsync(id, ownerToken, ct)).Json!.Value.GetArrayLength() == 0
            && (await account.GetSharedWithMeAsync(requesterToken, cancellationToken: ct)).Json!.Value.GetArrayLength() == 0,
            "UMA account permission revocation removes the persisted share");
        await resources.DeleteAsync(id, ownerProtectionToken, ct);
    }
}
