using System.Text.Json.Nodes;
using static LiveContext;

internal static class FullRoles
{
    public static async Task RunAsync(LiveContext c, LiveFacts f)
    {
        var p = new[] { ("client-uuid", f.Client), ("client-id", f.Client), ("targetClientUuid", f.Client), ("clientUuid", f.Client), ("client", f.Client), ("user-id", f.User), ("group-id", f.Group), ("client-scope-id", f.Scope) };
        var roles = new Dictionary<string, JsonNode>();
        foreach (string prefix in new[] { "roles", "clients/{client-uuid}/roles" })
        {
            string suffix = prefix == "roles" ? "realm" : "client";
            foreach (string kind in new[] { "parent", "leaf" })
            {
                string name = "full-" + suffix + "-" + kind;
                var create = await c.Post(prefix, new JsonObject { ["name"] = name }, null, p);
                var values = p.Append(("role-name", name)).ToArray();
                var read = await c.Get(prefix + "/{role-name}", null, values);
                c.Prove(S(read.J, "name") == name && S(read.J, "id").Length > 0, "Role creation persists a unique role and ID", create, read);
                roles[suffix + "-" + kind] = read.J!;
            }
            var list = await c.Get(prefix, null, p);
            c.Prove(Has(list.J, "id", S(roles[suffix + "-parent"], "id")), "Role listing contains newly created role", list);
            string parent = "full-" + suffix + "-parent";
            var paths = p.Append(("role-name", parent)).ToArray();
            var update = await c.Put(prefix + "/{role-name}", new JsonObject { ["name"] = parent, ["description"] = "role-updated" }, paths);
            var item = await c.Get(prefix + "/{role-name}", null, paths);
            c.Prove(S(item.J, "description") == "role-updated", "Role update changes persisted description", update, item);
        }
        JsonArray leaves() => new(roles["realm-leaf"].DeepClone(), roles["client-leaf"].DeepClone());
        foreach (string prefix in new[] { "roles", "clients/{client-uuid}/roles" })
        {
            string suffix = prefix == "roles" ? "realm" : "client";
            var paths = p.Append(("role-name", "full-" + suffix + "-parent")).ToArray();
            string path = prefix + "/{role-name}/composites";
            var add = await c.Post(path, leaves(), null, paths);
            var all = await c.Get(path, null, paths);
            var rr = await c.Get(path + "/realm", null, paths);
            var cr = await c.Get(path + "/clients/{targetClientUuid}", null, paths);
            c.Prove(Has(all.J, "id", S(roles["realm-leaf"], "id")) && Has(all.J, "id", S(roles["client-leaf"], "id")) && Has(rr.J, "id", S(roles["realm-leaf"], "id")) && Has(cr.J, "id", S(roles["client-leaf"], "id")), "Composite role writes and realm/client filters reflect real child relationships", add, all, rr, cr);
            var remove = await c.Call("DELETE", path, leaves(), paths: paths); all = await c.Get(path, null, paths);
            c.Prove(!Has(all.J, "id", S(roles["realm-leaf"], "id")) && !Has(all.J, "id", S(roles["client-leaf"], "id")), "Removing composites removes both child role relationships", remove, all);
            if (c.Route.FgapVersion == 1) await Permissions(c, prefix + "/{role-name}/management/permissions", paths);
        }
        string rid = S(roles["realm-parent"], "id"); var rp = p.Append(("role-id", rid)).ToArray();
        var idRead = await c.Get("roles-by-id/{role-id}", null, rp);
        c.Prove(S(idRead.J, "name") == "full-realm-parent", "Role-by-ID returns the role created by name", idRead);
        var idUpdate = await c.Put("roles-by-id/{role-id}", O("""{"name":"full-realm-parent","description":"updated-by-id"}"""), rp);
        idRead = await c.Get("roles-by-id/{role-id}", null, rp);
        c.Prove(S(idRead.J, "description") == "updated-by-id", "Role-by-ID update persists", idUpdate, idRead);
        var idAdd = await c.Post("roles-by-id/{role-id}/composites", leaves(), null, rp);
        var idAll = await c.Get("roles-by-id/{role-id}/composites", null, rp);
        var idRealm = await c.Get("roles-by-id/{role-id}/composites/realm", null, rp);
        var idClient = await c.Get("roles-by-id/{role-id}/composites/clients/{clientUuid}", null, rp);
        c.Prove(Has(idAll.J, "id", S(roles["realm-leaf"], "id")) && Has(idRealm.J, "id", S(roles["realm-leaf"], "id")) && Has(idClient.J, "id", S(roles["client-leaf"], "id")), "Role-by-ID composite filters expose actual child roles", idAdd, idAll, idRealm, idClient);
        var idDel = await c.Call("DELETE", "roles-by-id/{role-id}/composites", leaves(), paths: rp); idAll = await c.Get("roles-by-id/{role-id}/composites", null, rp);
        c.Prove(idAll.J is JsonArray { Count: 0 }, "Role-by-ID composite deletion removes persisted children", idDel, idAll);
        if (c.Route.FgapVersion == 1) await Permissions(c, "roles-by-id/{role-id}/management/permissions", rp);
        await c.Post("roles/{role-name}/composites", leaves(), null, ("role-name", "full-realm-parent"));
        await c.Post("clients/{client-uuid}/roles/{role-name}/composites", new JsonArray(roles["client-leaf"].DeepClone()), null, ("client-uuid", f.Client), ("role-name", "full-client-parent"));

        foreach (string owner in new[] { "users/{user-id}", "groups/{group-id}" })
        {
            await Mappings(c, owner + "/role-mappings", roles, p, "client-id");
            // Keep one direct assignment while checking role-centric member listings.
            await c.Post(owner + "/role-mappings/realm", new JsonArray(roles["realm-parent"].DeepClone()), null, p);
            await c.Post(owner + "/role-mappings/clients/{client-id}", new JsonArray(roles["client-parent"].DeepClone()), null, p);
            foreach (string rolePath in new[] { "roles/{role-name}", "clients/{client-uuid}/roles/{role-name}" })
            {
                string name = rolePath.StartsWith("clients", StringComparison.Ordinal) ? "full-client-parent" : "full-realm-parent";
                string list = owner.StartsWith("users", StringComparison.Ordinal) ? "users" : "groups";
                var read = await c.Get(rolePath + "/" + list, null, [.. p, ("role-name", name)]);
                c.Prove(Has(read.J, "id", list == "users" ? f.User : f.Group), "Role-centric member listing reflects assigned user/group", read);
            }
        }
        await c.Put("clients/{client-uuid}", O("""{"fullScopeAllowed":false,"authorizationServicesEnabled":true}"""), ("client-uuid", f.Client));
        var scopeOwner = await c.Post("clients", O("""{"clientId":"full-scope-owner","protocol":"openid-connect","fullScopeAllowed":false}"""));
        foreach (string prefix in new[] { "clients/{client-uuid}", "client-scopes/{client-scope-id}", "client-templates/{client-scope-id}" })
            await Mappings(c, prefix + "/scope-mappings", roles, prefix.StartsWith("clients/", StringComparison.Ordinal) ? p.Select(v => v.Item1 == "client-uuid" ? (v.Item1, scopeOwner.Id) : v).ToArray() : p, "client");
        foreach (var target in new[] { (Path: "groups/{group-id}/management/permissions", Values: p), (Path: "clients/{client-uuid}/management/permissions", Values: p), (Path: "users-management-permissions", Values: p) })
            if (c.Route.FgapVersion == 1) await Permissions(c, target.Path, target.Values);
        foreach (string prefix in new[] { "roles", "clients/{client-uuid}/roles" })
        {
            string name = "full-delete-by-name";
            await c.Post(prefix, new JsonObject { ["name"] = name }, null, p);
            var values = p.Append(("role-name", name)).ToArray();
            var remove = await c.Delete(prefix + "/{role-name}", values);
            c.Prove(await c.Missing(prefix + "/{role-name}", values), "Role deletion by name removes persisted role", remove);
        }
        var extra = await c.Post("roles", O("""{"name":"full-delete-by-id"}"""));
        var extraRole = await c.Get("roles/{role-name}", null, ("role-name", "full-delete-by-id"));
        var byIdDelete = await c.Delete("roles-by-id/{role-id}", ("role-id", S(extraRole.J, "id")));
        c.Prove(await c.Missing("roles-by-id/{role-id}", ("role-id", S(extraRole.J, "id"))), "Role deletion by ID removes persisted role", byIdDelete);
        Console.WriteLine("PASS full roles: role CRUD, composite inheritance, subjects/scope mappings" + (c.Route.FgapVersion == 1 ? " and FGAP v1 compatibility permission lifecycle." : "."));
    }
    internal static async Task Permissions(LiveContext c, string path, (string, string)[] values)
    {
        var enable = await c.Put(path, O("""{"enabled":true}"""), values);
        var read = await c.Get(path, null, values);
        c.Prove(read.J?["enabled"]?.GetValue<bool>() == true && S(read.J, "resource").Length > 0, "Enabling legacy permissions persists authorization resource: " + path, enable, read);
        var disable = await c.Put(path, O("""{"enabled":false}"""), values); read = await c.Get(path, null, values);
        c.Prove(read.J?["enabled"]?.GetValue<bool>() == false, "Disabling legacy permissions changes persisted state: " + path, disable, read);
    }
    internal static async Task Mappings(LiveContext c, string prefix, Dictionary<string, JsonNode> roles, (string, string)[] paths, string clientParameter)
    {
        string clientPath = prefix + "/clients/{" + clientParameter + "}";
        var availableRealm = await c.Get(prefix + "/realm/available", null, paths);
        var availableClient = await c.Get(clientPath + "/available", null, paths);
        c.Prove(Has(availableRealm.J, "id", S(roles["realm-parent"], "id")) && Has(availableClient.J, "id", S(roles["client-parent"], "id")), "Available mappings contain unassigned real realm and client roles: " + prefix, availableRealm, availableClient);
        var addRealm = await c.Post(prefix + "/realm", new JsonArray(roles["realm-parent"].DeepClone()), null, paths);
        var addClient = await c.Post(clientPath, new JsonArray(roles["client-parent"].DeepClone()), null, paths);
        var realm = await c.Get(prefix + "/realm", null, paths); var client = await c.Get(clientPath, null, paths);
        var rc = await c.Get(prefix + "/realm/composite", null, paths); var cc = await c.Get(clientPath + "/composite", null, paths);
        var all = await c.Get(prefix, null, paths);
        c.Prove(Has(realm.J, "id", S(roles["realm-parent"], "id")) && Has(client.J, "id", S(roles["client-parent"], "id")) && Has(rc.J, "id", S(roles["realm-leaf"], "id")) && Has(cc.J, "id", S(roles["client-leaf"], "id")) && all.J?["realmMappings"] is JsonArray { Count: > 0 } && all.J?["clientMappings"] is JsonObject { Count: > 0 }, "Assigned roles and effective composite mappings persist: " + prefix, addRealm, addClient, realm, client, rc, cc, all);
        var dr = await c.Call("DELETE", prefix + "/realm", new JsonArray(roles["realm-parent"].DeepClone()), paths: paths);
        var dc = await c.Call("DELETE", clientPath, new JsonArray(roles["client-parent"].DeepClone()), paths: paths);
        realm = await c.Get(prefix + "/realm", null, paths); client = await c.Get(clientPath, null, paths);
        c.Prove(!Has(realm.J, "id", S(roles["realm-parent"], "id")) && !Has(client.J, "id", S(roles["client-parent"], "id")), "Deleting mappings removes direct role relationships: " + prefix, dr, dc, realm, client);
    }
}
