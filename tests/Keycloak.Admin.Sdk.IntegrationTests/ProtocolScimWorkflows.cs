using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Protocols;

internal static class ProtocolScimWorkflows
{
    internal static async Task RunAsync(KeycloakAdminClient admin, HttpClient http, Uri server, ProtocolTransport transport, string realm, string serviceToken, string ordinaryToken,
        Action<bool, string> check, CancellationToken ct)
    {
        const string extension = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
        string profilePath = "/admin/realms/" + realm + "/users/profile";
        var profile = JsonNode.Parse((await admin.SendAsync(HttpMethod.Get, profilePath, cancellationToken: ct)).Content.Span)!;
        profile["attributes"]!.AsArray().Add((JsonNode)new JsonObject { ["name"] = "department", ["multivalued"] = false,
            ["permissions"] = new JsonObject { ["view"] = new JsonArray("admin", "user"), ["edit"] = new JsonArray("admin", "user") },
            ["annotations"] = new JsonObject { ["kc.scim.schema.attribute"] = extension + ":department" } });
        await admin.SendAsync(HttpMethod.Put, profilePath, content: new StringContent(profile.ToJsonString(), Encoding.UTF8, "application/json"), cancellationToken: ct);
        var discovery = new ScimClient(transport);
        var config = (await discovery.GetServiceProviderConfigurationAsync(serviceToken, ct)).Json!.Value;
        var schemas = (await discovery.GetSchemasAsync(serviceToken, ct)).Json!.Value;
        var types = (await discovery.GetResourceTypesAsync(serviceToken, ct)).Json!.Value;
        check(config.GetProperty("patch").GetProperty("supported").GetBoolean() && config.GetProperty("filter").GetProperty("supported").GetBoolean()
            && !config.GetProperty("bulk").GetProperty("supported").GetBoolean() && schemas.GetProperty("totalResults").GetInt32() >= 2 && types.GetProperty("totalResults").GetInt32() >= 2,
            "SCIM discovery negotiates actual PATCH filter bulk schema and resource-type capabilities");
        check((await discovery.GetSchemaAsync("urn:ietf:params:scim:schemas:core:2.0:User", serviceToken, ct)).Json!.Value.GetProperty("name").GetString() == "User"
            && (await discovery.GetResourceTypeAsync("User", serviceToken, ct)).Json!.Value.GetProperty("endpoint").GetString() == "/Users",
            "SCIM individual schema and resource-type discovery resolve declared identifiers");
        var users = RealmResourceClient.ScimUsers(transport); var groups = RealmResourceClient.ScimGroups(transport);
        JsonElement Element(JsonNode value) { using var doc = JsonDocument.Parse(value.ToJsonString()); return doc.RootElement.Clone(); }
        var user = new JsonObject { ["schemas"] = new JsonArray("urn:ietf:params:scim:schemas:core:2.0:User", extension), ["userName"] = "scim-full-one", ["active"] = true,
            [extension] = new JsonObject { ["department"] = "Engineering" } };
        var created = (await users.CreateAsync(Element(user), serviceToken, ct)).Json!.Value;
        string userId = created.GetProperty("id").GetString()!;
        var persisted = (await users.GetAsync(userId, serviceToken, ct)).Json!.Value;
        check(persisted.GetProperty(extension).GetProperty("department").GetString() == "Engineering", "SCIM enterprise extension mapping survives create and independent read");
        user["userName"] = "scim-full-two";
        string secondId = (await users.CreateAsync(Element(user), serviceToken, ct)).Json!.Value.GetProperty("id").GetString()!;
        var page = (await users.ListAsync(serviceToken, [new("filter", "userName sw \"scim-full-\""), new("startIndex", "2"), new("count", "1")], ct)).Json!.Value;
        var search = (await users.SearchAsync(Element(new JsonObject { ["schemas"] = new JsonArray("urn:ietf:params:scim:api:messages:2.0:SearchRequest"),
            ["filter"] = "userName eq \"scim-full-one\"", ["startIndex"] = 1, ["count"] = 1 }), serviceToken, ct)).Json!.Value;
        check(page.GetProperty("totalResults").GetInt32() == 2 && page.GetProperty("startIndex").GetInt32() == 2 && page.GetProperty("Resources").GetArrayLength() == 1
            && search.GetProperty("totalResults").GetInt32() == 1 && search.GetProperty("Resources")[0].GetProperty("id").GetString() == userId,
            "SCIM filtering pagination and POST search return the actual persisted user set");
        var projected = (await users.GetAsync(userId, serviceToken, [new("attributes", extension)], ct)).Json!.Value;
        check(projected.GetProperty(extension).GetProperty("department").GetString() == "Engineering" && !projected.TryGetProperty("userName", out _),
            "SCIM projection returns requested extension attributes without unrelated user fields");
        var replacement = JsonNode.Parse(persisted.GetRawText())!; replacement["active"] = false;
        await users.ReplaceAsync(userId, Element(replacement), serviceToken, ct);
        var patch = new JsonObject { ["schemas"] = new JsonArray("urn:ietf:params:scim:api:messages:2.0:PatchOp"), ["Operations"] = new JsonArray(new JsonObject
            { ["op"] = "replace", ["path"] = extension + ":department", ["value"] = "Operations" }) };
        await users.PatchAsync(userId, Element(patch), serviceToken, ct);
        persisted = (await users.GetAsync(userId, serviceToken, ct)).Json!.Value;
        check(!persisted.GetProperty("active").GetBoolean() && persisted.GetProperty(extension).GetProperty("department").GetString() == "Operations",
            "SCIM user replace and extension PATCH persist independently");
        var group = new JsonObject { ["schemas"] = new JsonArray("urn:ietf:params:scim:schemas:core:2.0:Group"), ["displayName"] = "scim-team" };
        string groupId = (await groups.CreateAsync(Element(group), serviceToken, ct)).Json!.Value.GetProperty("id").GetString()!;
        patch["Operations"] = new JsonArray(new JsonObject { ["op"] = "add", ["path"] = "members", ["value"] = new JsonArray(new JsonObject { ["value"] = userId }) });
        await groups.PatchAsync(groupId, Element(patch), serviceToken, ct);
        var readGroup = (await groups.GetAsync(groupId, serviceToken, [new("attributes", "displayName,members")], ct)).Json!.Value;
        check(readGroup.GetProperty("members").EnumerateArray().Any(m => m.GetProperty("value").GetString() == userId), "SCIM group create and membership PATCH persist an actual user membership");
        group["displayName"] = "scim-team-replaced"; group["id"] = groupId;
        await groups.ReplaceAsync(groupId, Element(group), serviceToken, ct);
        patch["Operations"] = new JsonArray(new JsonObject { ["op"] = "replace", ["path"] = "displayName", ["value"] = "scim-team-patched" },
            new JsonObject { ["op"] = "remove", ["path"] = "members[value eq \"" + userId + "\"]" });
        await groups.PatchAsync(groupId, Element(patch), serviceToken, ct);
        var foundGroups = (await groups.SearchAsync(Element(new JsonObject { ["schemas"] = new JsonArray("urn:ietf:params:scim:api:messages:2.0:SearchRequest"),
            ["filter"] = "displayName eq \"scim-team-patched\"" }), serviceToken, ct)).Json!.Value;
        check(foundGroups.GetProperty("totalResults").GetInt32() == 1 && foundGroups.GetProperty("Resources")[0].GetProperty("id").GetString() == groupId,
            "SCIM group replace PATCH and search operate on the same stored resource");
        var membership = await admin.SendAsync(HttpMethod.Get, "/admin/realms/" + realm + "/users/" + userId + "/groups", cancellationToken: ct);
        using var membershipJson = JsonDocument.Parse(membership.Content);
        check(membershipJson.RootElement.EnumerateArray().All(g => g.GetProperty("id").GetString() != groupId), "SCIM membership removal is confirmed through the independent Admin API");
        bool duplicate = false, invalidFilter = false, unauthorized = false;
        try { await users.CreateAsync(Element(user), serviceToken, ct); }
        catch (KeycloakProtocolException e) when (e.StatusCode == HttpStatusCode.Conflict) { duplicate = true; }
        try { await users.ListAsync(serviceToken, [new("filter", "userName ???")], ct); }
        catch (KeycloakProtocolException e) when (e.StatusCode == HttpStatusCode.BadRequest && e.ScimError == ScimError.InvalidFilter) { invalidFilter = true; }
        try { await groups.GetAsync(groupId, ordinaryToken, ct); }
        catch (KeycloakProtocolException e) when (e.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.NotFound) { unauthorized = true; }
        check(duplicate && invalidFilter && unauthorized, "SCIM uniqueness filter errors and ordinary-user group denial fail with the expected protocol statuses");
        bool userWriteDenied = false, groupWriteDenied = false;
        try { await users.DeleteAsync(userId, ordinaryToken, ct); }
        catch (KeycloakProtocolException e) when (e.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.NotFound) { userWriteDenied = true; }
        try { await groups.DeleteAsync(groupId, ordinaryToken, ct); }
        catch (KeycloakProtocolException e) when (e.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.NotFound) { groupWriteDenied = true; }
        check(userWriteDenied && groupWriteDenied && (await users.GetAsync(userId, serviceToken, ct)).Json!.Value.GetProperty("id").GetString() == userId
            && (await groups.GetAsync(groupId, serviceToken, ct)).Json!.Value.GetProperty("id").GetString() == groupId,
            "SCIM denies ordinary-user mutations and leaves both protected resources unchanged");
        string otherRealm = "sdk-scim-other-" + Guid.NewGuid().ToString("N");
        await admin.RealmsAdmin.ImportRealmAsync(new StringContent(new JsonObject { ["realm"] = otherRealm, ["enabled"] = true, ["scimApiEnabled"] = true }.ToJsonString(), Encoding.UTF8, "application/json"), cancellationToken: ct);
        try
        {
            bool crossRealm = false;
            try { await RealmResourceClient.ScimUsers(new(http, server, otherRealm)).GetAsync(userId, serviceToken, ct); }
            catch (KeycloakProtocolException e) when (e.StatusCode == HttpStatusCode.Unauthorized) { crossRealm = true; }
            check(crossRealm, "SCIM rejects a correctly signed token from another realm");
        }
        finally { using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(30)); await admin.RealmAdmin.DeleteRealmAsync(otherRealm, cleanup.Token); }
        await groups.DeleteAsync(groupId, serviceToken, ct); await users.DeleteAsync(userId, serviceToken, ct); await users.DeleteAsync(secondId, serviceToken, ct);
        var remaining = (await groups.ListAsync(serviceToken, [new("filter", "displayName eq \"scim-team-patched\"")], ct)).Json!.Value;
        check(remaining.GetProperty("totalResults").GetInt32() == 0 && (await users.ListAsync(serviceToken, [new("filter", "userName sw \"scim-full-\"")], ct)).Json!.Value.GetProperty("totalResults").GetInt32() == 0,
            "SCIM user and group deletion remove every created resource");
    }
}
