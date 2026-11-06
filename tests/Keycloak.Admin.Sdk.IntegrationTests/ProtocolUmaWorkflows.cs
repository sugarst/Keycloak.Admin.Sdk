using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Protocols;

internal static class ProtocolUmaWorkflows
{
    internal static async Task RunAsync(KeycloakAdminClient admin, HttpClient http, ProtocolTransport transport, string realm, string secret, string userToken, Action<bool, string> check, CancellationToken ct)
    {
        await admin.RealmAdmin.UpdateRealmAsync(realm, new() { UserManagedAccessAllowed = true }, ct);
        await admin.Clients.CreateClientAsync(realm, new ClientRepresentation { ClientId = "uma-app", Enabled = true, Protocol = "openid-connect", PublicClient = false,
            Secret = secret, ServiceAccountsEnabled = true, DirectAccessGrantsEnabled = true, AuthorizationServicesEnabled = true }, cancellationToken: ct);
        var app = (await admin.Clients.GetClientsAsync(realm, clientId: "uma-app", cancellationToken: ct)).Body!.Single();
        var user = (await admin.Users.GetUsersAsync(realm, username: "account-user", exact: true, cancellationToken: ct)).Body!.Single();
        var oidc = new OidcClient(transport); var auth = OAuthClientAuthentication.SecretBasic("uma-app", _ => ValueTask.FromResult(secret));
        string pat = (await oidc.ClientCredentialsAsync(auth, cancellationToken: ct)).Json!.Value.GetProperty("access_token").GetString()!;
        var uma = new UmaClient(transport); var resources = RealmResourceClient.UmaResources(transport);
        JsonElement Element(JsonNode value) { using var doc = JsonDocument.Parse(value.ToJsonString()); return doc.RootElement.Clone(); }
        var discovery = (await uma.DiscoverAsync(ct)).Json!.Value;
        check(discovery.GetProperty("issuer").GetString() == transport.Issuer.AbsoluteUri
            && discovery.GetProperty("permission_endpoint").GetString() == transport.Issuer.AbsoluteUri + "/authz/protection/permission", "UMA discovery pins issuer and protection endpoints to the realm");
        var document = new JsonObject { ["name"] = "uma-document", ["type"] = "urn:sdk:uma:document", ["ownerManagedAccess"] = true,
            ["uris"] = new JsonArray("/documents/one"), ["resource_scopes"] = new JsonArray(new JsonObject { ["name"] = "read" }) };
        string id = (await resources.CreateAsync(Element(document), pat, ct)).Json!.Value.GetProperty("_id").GetString()!;
        var persisted = (await resources.GetAsync(id, pat, ct)).Json!.Value;
        check(persisted.GetProperty("name").GetString() == "uma-document" && (await resources.ListAsync(pat, [new("name", "uma-document")], ct)).Json!.Value.EnumerateArray().Any(v => v.GetString() == id),
            "UMA protection registers an actual resource and resolves it by id and name");
        document["_id"] = id; document["displayName"] = "Updated document"; document["scopes"] = document["resource_scopes"]!.DeepClone(); document.Remove("resource_scopes");
        await resources.ReplaceAsync(id, Element(document), pat, ct);
        check((await resources.GetAsync(id, pat, ct)).Json!.Value.GetProperty("displayName").GetString() == "Updated document", "UMA protection resource replacement persists");
        var permission = await uma.CreatePermissionAsync(Element(new JsonArray(new JsonObject { ["resource_id"] = id, ["resource_scopes"] = new JsonArray("read") })), pat, ct);
        string signedTicket = permission.Json!.Value.GetProperty("ticket").GetString()!;
        check(signedTicket.Length > 100, "UMA protection issues a permission ticket for a persisted resource and scope");
        var ticket = new JsonObject { ["resource"] = id, ["scopeName"] = "read", ["requester"] = user.Id, ["granted"] = false };
        var pending = (await uma.CreateTicketAsync(Element(ticket), pat, ct)).Json!.Value;
        string ticketId = pending.GetProperty("id").GetString()!;
        check((await uma.GetTicketsAsync(pat, [new("resourceId", id), new("requester", user.Id!)], ct)).Json!.Value.EnumerateArray().Any(t => t.GetProperty("id").GetString() == ticketId)
            && (await uma.CountTicketsAsync(pat, [new("resourceId", id)], ct)).Json!.Value.GetInt32() == 1, "UMA persistent permission-ticket creation list and count reflect actual state");
        ticket["id"] = ticketId; ticket["granted"] = true;
        await uma.UpdateTicketAsync(Element(ticket), pat, ct);
        check((await uma.GetTicketsAsync(pat, [new("resourceId", id), new("granted", "true")], ct)).Json!.Value.GetArrayLength() == 1,
            "UMA ticket update persists the resource owner's grant");
        // A user-specific policy supplies an independent runtime policy grant, separate from the stored UMA ticket.
        string prefix = "/admin/realms/" + realm + "/clients/" + app.Id + "/authz/resource-server";
        async Task<JsonNode> Post(string path, JsonNode body)
        { var response = await admin.SendAsync(HttpMethod.Post, prefix + path, content: new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json"), cancellationToken: ct); return JsonNode.Parse(response.Content.Span)!; }
        var policy = await Post("/policy/user", new JsonObject { ["name"] = "uma-account-user", ["logic"] = "POSITIVE", ["users"] = new JsonArray(user.Id) });
        await Post("/permission/scope", new JsonObject { ["name"] = "uma-read-policy", ["resources"] = new JsonArray(id), ["scopes"] = new JsonArray("read"), ["policies"] = new JsonArray(policy["id"]!.GetValue<string>()) });
        check(await uma.EvaluateAsync(userToken, "uma-app", [id + "#read"], ct), "UMA runtime decision permits the user under the actual resource and scope policy");
        var rpt = await uma.AuthorizeAsync(userToken, "uma-app", ticket: signedTicket, cancellationToken: ct);
        check(rpt.Json!.Value.GetProperty("access_token").GetString()!.Length > 100
            && (await uma.AuthorizeAsync(userToken, "uma-app", [id + "#read"], responseMode: UmaResponseMode.Permissions, cancellationToken: ct)).Json!.Value.GetArrayLength() > 0,
            "UMA permission-ticket grant returns an RPT and explicit runtime permissions");
        bool protectedDenied = false;
        try { await resources.DeleteAsync(id, userToken, ct); }
        catch (KeycloakProtocolException e) when (e.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.Unauthorized) { protectedDenied = true; }
        check(protectedDenied && (await resources.GetAsync(id, pat, ct)).Json!.Value.GetProperty("_id").GetString() == id, "UMA rejects an unrelated user token as a protection credential without deleting the resource");
        await uma.DeleteTicketAsync(ticketId, pat, ct);
        await admin.SendAsync(HttpMethod.Delete, prefix + "/policy/" + policy["id"]!.GetValue<string>(), cancellationToken: ct);
        check(!await uma.EvaluateAsync(userToken, "uma-app", [id + "#read"], ct), "UMA ticket and policy revocation change a real runtime permit to deny");
        var ownedPolicy = new JsonObject { ["name"] = "owner-shared-read", ["users"] = new JsonArray(user.Id), ["scopes"] = new JsonArray("read") };
        string ownedId = (await uma.CreatePolicyAsync(id, Element(ownedPolicy), pat, ct)).Json!.Value.GetProperty("id").GetString()!;
        check((await uma.GetPolicyAsync(ownedId, pat, ct)).Json!.Value.GetProperty("name").GetString() == "owner-shared-read"
            && (await uma.GetPoliciesAsync(pat, [new("name", "owner-shared-read")], ct)).Json!.Value.GetArrayLength() == 1,
            "UMA owner-managed policy creation read and list refer to a persisted resource policy");
        ownedPolicy["description"] = "Updated owner grant";
        await uma.UpdatePolicyAsync(ownedId, Element(ownedPolicy), pat, ct);
        check((await uma.GetPolicyAsync(ownedId, pat, ct)).Json!.Value.GetProperty("description").GetString() == "Updated owner grant"
            && await uma.EvaluateAsync(userToken, "uma-app", [id + "#read"], ct), "UMA owner-managed policy update persists and permits the intended user");
        await uma.DeletePolicyAsync(ownedId, pat, ct);
        check(!await uma.EvaluateAsync(userToken, "uma-app", [id + "#read"], ct), "UMA owner-managed policy deletion restores runtime denial");
        await resources.DeleteAsync(id, pat, ct);
        check((await resources.ListAsync(pat, [new("name", "uma-document")], ct)).Json!.Value.GetArrayLength() == 0, "UMA protection deletion removes the registered resource");
        var protectionRole = (await admin.RoleContainer.GetRoleAsync(realm, app.Id!, "uma_protection", ct)).Body!;
        await admin.ClientRoleMappings.AddClientRoleMappingPOSTAdminRealmsRealmUsersUserIdRoleMappingsClientsClientIdAsync(realm, user.Id!, app.Id!, [protectionRole], ct);
        await ProtocolUmaAccountWorkflows.RunAsync(admin, http, transport, realm, secret, userToken, pat, user.Id!, check, ct);
    }
}
