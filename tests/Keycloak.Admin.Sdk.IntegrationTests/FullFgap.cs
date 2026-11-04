using System.Net;
using System.Text.Json.Nodes;
using Keycloak.Admin.Sdk;
using static LiveContext;

internal static class FullFgap
{
    public static async Task RunAsync(LiveContext c, LiveFacts f, HttpClient http, Uri server)
    {
        if (c.Route.FgapVersion == 2)
        {
            await c.Put("", O("""{"adminPermissionsEnabled":true}"""));
            var realm = await c.Get("");
            c.Prove(realm.J?["adminPermissionsEnabled"]?.GetValue<bool>() == true, "FGAP v2 is explicitly enabled for the isolated realm", realm);
        }
        var create = await c.Post("users", O("""{"username":"full-delegated-admin","firstName":"Delegated","lastName":"Admin","email":"delegated@example.invalid","emailVerified":true,"enabled":true,"credentials":[{"type":"password","value":"Delegated-admin-Password-123!","temporary":false}]}"""));
        string admin = create.Id;
        var management = await c.Get("clients", O("""{"clientId":"realm-management"}"""));
        string managementId = S(management.J![0], "id");
        var queryRole = await c.Get("clients/{client-uuid}/roles/{role-name}", null, ("client-uuid", managementId), ("role-name", "query-users"));
        await c.Post("users/{user-id}/role-mappings/clients/{client-id}", new JsonArray(queryRole.J!.DeepClone()), paths: [("user-id", admin), ("client-id", managementId)]);
        await c.Post("clients", O("""{"clientId":"full-delegated-login","publicClient":false,"protocol":"openid-connect","secret":"full-delegated-secret","directAccessGrantsEnabled":true,"fullScopeAllowed":true}"""));
        using var form = new FormUrlEncodedContent(new Dictionary<string, string> { ["grant_type"] = "password", ["client_id"] = "full-delegated-login", ["client_secret"] = "full-delegated-secret", ["username"] = "full-delegated-admin", ["password"] = "Delegated-admin-Password-123!" });
        using var login = await http.PostAsync(new Uri(server, "realms/" + c.Realm + "/protocol/openid-connect/token"), form);
        login.EnsureSuccessStatusCode();
        var token = JsonNode.Parse(await login.Content.ReadAsStringAsync());
        var delegated = new KeycloakAdminClient(http, server, new StaticAccessTokenProvider(S(token, "access_token")));
        async Task Denied()
        {
            try { await delegated.User.UpdateUserAsync(c.Realm, f.User, new UserRepresentation { FirstName = "Unauthorized change" }); }
            catch (KeycloakAdminException e) when (e.StatusCode == HttpStatusCode.Forbidden) { return; }
            throw new InvalidOperationException("Delegated admin mutation must be denied without FGAP grant.");
        }
        await Denied();
        string authzClient;
        LiveReply? legacy = null;
        if (c.Route.FgapVersion == 2)
        {
            var clients = await c.Get("clients", O("""{"clientId":"admin-permissions"}"""));
            authzClient = S(clients.J![0], "id");
            var settings = await c.Get("clients/{client-uuid}/authz/resource-server", null, ("client-uuid", authzClient));
            c.Prove(settings.J?["authorizationSchema"] is not null, "FGAP v2 uses the released admin-permissions authorization schema", settings);
        }
        else
        {
            legacy = await c.Put("users-management-permissions", O("""{"enabled":true}"""));
            legacy = await c.Get("users-management-permissions"); authzClient = managementId;
        }
        const string root = "clients/{client-uuid}/authz/resource-server";
        var p = new[] { ("client-uuid", authzClient) };
        var policy = await c.Post(root + "/policy/{policy-type}", new JsonObject { ["name"] = "full-delegated-admin-policy", ["logic"] = "POSITIVE", ["users"] = new JsonArray(admin) }, paths: [.. p, ("policy-type", "user")]);
        string policyId = S(policy.J, "id");
        if (c.Route.FgapVersion == 2)
        {
            await c.Post(root + "/permission/{policy-type}", new JsonObject { ["name"] = "full-user-management", ["resourceType"] = "Users", ["scopes"] = new JsonArray("view", "manage"), ["policies"] = new JsonArray(policyId) }, paths: [.. p, ("policy-type", "scope")]);
        }
        else
        {
            foreach (string scope in new[] { "view", "manage" })
            {
                string permissionId = S(legacy!.J?["scopePermissions"], scope);
                var permissionPaths = p.Concat(new[] { ("id", permissionId), ("policy-type", "scope") }).ToArray();
                var permission = await c.Get(root + "/permission/{policy-type}/{id}", null, permissionPaths);
                var edit = permission.J!.DeepClone(); edit["policies"] = new JsonArray(policyId);
                await c.Put(root + "/permission/{policy-type}/{id}", edit, permissionPaths);
            }
        }
        await delegated.User.UpdateUserAsync(c.Realm, f.User, new UserRepresentation { FirstName = "FGAP delegated update" });
        var persisted = await c.Get("users/{user-id}", null, ("user-id", f.User));
        var viewed = await delegated.User.GetUserAsync(c.Realm, f.User);
        c.Prove(S(persisted.J, "firstName") == "FGAP delegated update" && viewed.Body!.FirstName == "FGAP delegated update", "Declared FGAP v" + c.Route.FgapVersion + " policy grants real delegated admin read/write after an initial 403", policy, persisted);
        var remove = await c.Delete(root + "/policy/{id}", [.. p, ("id", policyId)]);
        await Denied(); persisted = await c.Get("users/{user-id}", null, ("user-id", f.User));
        c.Prove(S(persisted.J, "firstName") == "FGAP delegated update", "Revoking FGAP policy restores actual 403 and prevents unauthorized data change", remove, persisted);
        c.Evidence("fgapDelegation", O("""{"initialDenied":true,"grantAllowsReadAndWrite":true,"revocationDenied":true}"""));
        Console.WriteLine("PASS declared FGAP v" + c.Route.FgapVersion + ": real delegated admin denied -> granted/persisted -> revoked/denied.");
    }
}
