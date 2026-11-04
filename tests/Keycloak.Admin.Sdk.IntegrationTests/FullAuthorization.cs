using System.Text.Json.Nodes;
using static LiveContext;

internal static class FullAuthorization
{
    public static async Task RunAsync(LiveContext c, LiveFacts f)
    {
        string root = "clients/{client-uuid}/authz/resource-server";
        var p = new[] { ("client-uuid", f.Client) };
        var server = await c.Get(root, null, p);
        c.Prove(S(server.J, "id") == f.Client, "Resource server belongs to the actual authorization-enabled client", server);
        var sb = server.J!.DeepClone(); sb["policyEnforcementMode"] = "PERMISSIVE";
        var su = await c.Put(root, sb, p); server = await c.Get(root, null, p);
        c.Prove(S(server.J, "policyEnforcementMode") == "PERMISSIVE", "Resource-server policy mode change persists", su, server);
        sb["policyEnforcementMode"] = "ENFORCING"; await c.Put(root, sb, p);
        var scope = await c.Post(root + "/scope", O("""{"name":"full-read","displayName":"Read"}"""), null, p);
        string sid = S(scope.J, "id");
        if (sid.Length == 0) sid = scope.Id;
        var sp = p.Append(("scope-id", sid)).ToArray();
        var sr = await c.Get(root + "/scope/{scope-id}", null, sp);
        var scopes = await c.Get(root + "/scope", O("""{"name":"full-read"}"""), p);
        var searchScope = await c.Get(root + "/scope/search", O("""{"name":"full-read"}"""), p);
        c.Prove(S(sr.J, "name") == "full-read" && Has(scopes.J, "id", sid) && S(searchScope.J, "id") == sid, "Authorization scope persists and exact search returns its single model", scope, sr, scopes, searchScope);
        var scopeUpdate = await c.Put(root + "/scope/{scope-id}", O("""{"name":"full-read","displayName":"Read updated"}"""), sp); sr = await c.Get(root + "/scope/{scope-id}", null, sp);
        c.Prove(S(sr.J, "displayName") == "Read updated", "Scope update persists display name", scopeUpdate, sr);
        var resource = await c.Post(root + "/resource", new JsonObject
        {
            ["name"] = "full-resource", ["displayName"] = "Full document", ["type"] = "urn:full:document",
            ["uris"] = new JsonArray("/full/document"), ["scopes"] = new JsonArray(new JsonObject { ["id"] = sid, ["name"] = "full-read" }),
            ["attributes"] = O("""{"classification":["internal"]}""")
        }, null, p);
        string rid = S(resource.J, "_id"); if (rid.Length == 0) rid = resource.Id;
        var rp = p.Append(("resource-id", rid)).ToArray();
        var rr = await c.Get(root + "/resource/{resource-id}", null, rp);
        var resources = await c.Get(root + "/resource", O("""{"name":"full-resource"}"""), p);
        var searchResource = await c.Get(root + "/resource/search", O("""{"name":"full-resource"}"""), p);
        var attrs = await c.Get(root + "/resource/{resource-id}/attributes", null, rp);
        var rs = await c.Get(root + "/resource/{resource-id}/scopes", null, rp);
        var scopeResources = await c.Get(root + "/scope/{scope-id}/resources", null, sp);
        c.Prove(S(rr.J, "name") == "full-resource" && Has(resources.J, "_id", rid) && S(searchResource.J, "_id") == rid && attrs.J?["classification"]?[0]?.GetValue<string>() == "internal" && Has(rs.J, "id", sid) && Has(scopeResources.J, "_id", rid), "Resource CRUD/search/attributes and bidirectional scope relationship persist", resource, rr, resources, searchResource, attrs, rs, scopeResources);
        var rb = rr.J!.DeepClone(); rb["displayName"] = "Full document updated";
        var ru = await c.Put(root + "/resource/{resource-id}", rb, rp); rr = await c.Get(root + "/resource/{resource-id}", null, rp);
        c.Prove(S(rr.J, "displayName") == "Full document updated", "Resource update persists display name", ru, rr);

        var roots = new Dictionary<string, (string Policy, string Permission)>();
        foreach (string family in new[] { "policy", "permission" })
        {
            var providers = await c.Get(root + "/" + family + "/providers", null, p);
            c.Prove(Has(providers.J, "type", family == "policy" ? "user" : "scope") || Has(providers.J, "id", family == "policy" ? "user" : "scope"), "Authorization provider discovery exposes installed provider for " + family, providers);
            string userName = "full-" + family + "-user";
            JsonObject userBody = new() { ["name"] = userName, ["type"] = "user", ["logic"] = "POSITIVE", ["decisionStrategy"] = "UNANIMOUS", ["config"] = new JsonObject { ["users"] = LiveJson.String(new JsonArray(f.User)) } };
            // PermissionService's generic create accepts PolicyRepresentation; type-specific user creation is exercised under policy/user.
            var userCreate = await c.Post(root + "/policy", userBody, null, p);
            string userPolicy = S(userCreate.J, "id");
            var permissionBody = new JsonObject { ["name"] = "full-" + family + "-scope", ["type"] = "scope", ["logic"] = "POSITIVE", ["decisionStrategy"] = "UNANIMOUS", ["resources"] = new JsonArray(rid), ["scopes"] = new JsonArray(sid), ["policies"] = new JsonArray(userPolicy) };
            var permissionCreate = await c.Post(root + "/" + family, permissionBody, null, p);
            string permission = S(permissionCreate.J, "id");
            var listing = await c.Get(root + "/" + family, new JsonObject { ["name"] = "full-" + family + "-scope", ["fields"] = "*" }, p);
            var search = await c.Get(root + "/" + family + "/search", new JsonObject { ["name"] = "full-" + family + "-scope", ["fields"] = "*" }, p);
            c.Prove(userPolicy.Length > 0 && permission.Length > 0 && Has(listing.J, "id", permission) && S(search.J, "id") == permission, "Policy/permission creation persists actual user policy and resource/scope permission", userCreate, permissionCreate, listing, search);
            roots[family] = (userPolicy, permission);
            var pp = p.Append(("type", permission)).ToArray();
            await Links(c, root + "/" + family + "/{type}", pp, rid, sid, userPolicy);
            var dep = await c.Get(root + "/" + family + "/{type}/dependentPolicies", null, [.. p, ("type", userPolicy)]);
            c.Prove(Has(dep.J, "id", permission), "Dependent policy query follows persisted permission-to-user-policy edge", dep);
            var typedUser = await c.Post(root + "/" + family + "/{type}", new JsonObject { ["name"] = "full-" + family + "-typed-user", ["users"] = new JsonArray(f.User), ["logic"] = "POSITIVE", ["decisionStrategy"] = "UNANIMOUS" }, null, [.. p, ("type", "user")]);
            string typedUserId = S(typedUser.J, "id");
            var typedPerm = await c.Post(root + "/" + family + "/{type}", new JsonObject { ["name"] = "full-" + family + "-typed-scope", ["resources"] = new JsonArray(rid), ["scopes"] = new JsonArray(sid), ["policies"] = new JsonArray(typedUserId), ["logic"] = "POSITIVE", ["decisionStrategy"] = "UNANIMOUS" }, null, [.. p, ("type", "scope")]);
            string typedPermId = S(typedPerm.J, "id");
            var tp = p.Concat(new[] { ("type", "scope"), ("policy-id", typedPermId) }).ToArray();
            var typedRead = await c.Get(root + "/" + family + "/{type}/{policy-id}", O("""{"fields":"*"}"""), tp);
            c.Prove(typedUserId.Length > 0 && S(typedRead.J, "id") == typedPermId, "Provider-specific creation and ID dispatch persist typed policies", typedUser, typedPerm, typedRead);
            await Links(c, root + "/" + family + "/{type}/{policy-id}", tp, rid, sid, typedUserId);
            var typedDep = await c.Get(root + "/" + family + "/{type}/{policy-id}/dependentPolicies", null, [.. p, ("type", "user"), ("policy-id", typedUserId)]);
            c.Prove(Has(typedDep.J, "id", typedPermId), "Provider-specific dependent-policy lookup follows persisted edge", typedDep);
            var typedList = await c.Get(root + "/" + family + "/{type}", new JsonObject { ["name"] = "full-" + family + "-typed-scope", ["first"] = 0, ["max"] = 1 }, [.. p, ("type", "scope")]);
            var typedSearch = await c.Get(root + "/" + family + "/{type}/search", new JsonObject { ["name"] = "full-" + family + "-typed-scope" }, [.. p, ("type", "scope")]);
            var typedProviders = await c.Get(root + "/" + family + "/{type}/providers", null, [.. p, ("type", "scope")]);
            c.Prove(Has(typedList.J, "id", typedPermId) && S(typedSearch.J, "id") == typedPermId && (Has(typedProviders.J, "type", "user") || Has(typedProviders.J, "id", "user")), "Provider-type listing/search/paging and provider discovery operate on real data", typedList, typedSearch, typedProviders);
            foreach (var target in new[] { (Path: root + "/" + family + "/{type}", Values: pp, Id: permission), (Path: root + "/" + family + "/{type}/{policy-id}", Values: tp, Id: typedPermId) })
            {
                var body = permissionBody.DeepClone(); body["id"] = target.Id; body["description"] = "Permission changed";
                if (target.Id == typedPermId) { body["name"] = "full-" + family + "-typed-scope"; body["policies"] = new JsonArray(typedUserId); }
                var change = await c.Put(target.Path, body, target.Values);
                var reread = await c.Get(target.Path, O("""{"fields":"*"}"""), target.Values);
                c.Prove(S(reread.J, "description") == "Permission changed", "Policy update persists through root or provider-specific ID route", change, reread);
            }
            var evaluation = new JsonObject { ["clientId"] = f.Client, ["userId"] = f.User, ["resources"] = new JsonArray(new JsonObject { ["_id"] = rid, ["scopes"] = new JsonArray(new JsonObject { ["id"] = sid, ["name"] = "full-read" }) }) };
            foreach (var eval in new[] { (Path: root + "/" + family + "/evaluate", Values: p), (Path: root + "/" + family + "/{type}/evaluate", Values: p.Append(("type", "scope")).ToArray()) })
            {
                var result = await c.Post(eval.Path, evaluation, null, eval.Values);
                c.Prove(S(result.J, "status") == "PERMIT" && result.J?["results"] is JsonArray { Count: > 0 }, "Authorization engine evaluates persisted user/resource/scope policies as PERMIT", result);
            }
            var td = await c.Delete(root + "/" + family + "/{type}/{policy-id}", tp);
            c.Prove(await c.Missing(root + "/" + family + "/{type}/{policy-id}", tp), "Typed policy deletion removes persisted permission", td);
        }
        var resourcePermissions = await c.Get(root + "/resource/{resource-id}/permissions", null, rp);
        var scopePermissions = await c.Get(root + "/scope/{scope-id}/permissions", null, sp);
        c.Prove(Has(resourcePermissions.J, "id", roots["permission"].Permission) && Has(scopePermissions.J, "id", roots["permission"].Permission), "Resource and scope permission queries reflect actual linked permissions", resourcePermissions, scopePermissions);
        var settings = await c.Get(root + "/settings", null, p);
        c.Prove(Has(settings.J?["resources"], "name", "full-resource") && Has(settings.J?["scopes"], "name", "full-read"), "Portable settings export contains created resource/scope names (server strips internal IDs)", settings);
        foreach (string family in new[] { "policy", "permission" })
        {
            var negative = new JsonObject { ["name"] = "full-" + family + "-user", ["type"] = "user", ["logic"] = "NEGATIVE", ["decisionStrategy"] = "UNANIMOUS", ["config"] = new JsonObject { ["users"] = LiveJson.String(new JsonArray(f.User)) } };
            await c.Put(root + "/policy/{type}", negative, [.. p, ("type", roots[family].Policy)]);
        }
        var deny = await c.Post(root + "/permission/evaluate", new JsonObject { ["clientId"] = f.Client, ["userId"] = f.User, ["resources"] = new JsonArray(new JsonObject { ["_id"] = rid, ["scopes"] = new JsonArray(new JsonObject { ["id"] = sid, ["name"] = "full-read" }) }) }, null, p);
        c.Prove(S(deny.J, "status") == "DENY", "Changing persisted user-policy logic from POSITIVE to NEGATIVE changes real authorization result from PERMIT to DENY", deny);
        var import = await c.Post(root + "/import", O("""{"policyEnforcementMode":"ENFORCING","resources":[{"name":"full-imported-resource","type":"urn:full:imported","uris":["/full/imported"]}]}"""), null, p);
        var imported = await c.Get(root + "/resource", O("""{"name":"full-imported-resource"}"""), p);
        c.Prove(Has(imported.J, "name", "full-imported-resource"), "Import changes persisted authorization resources", import, imported);
        foreach (string family in new[] { "policy", "permission" })
        {
            var del = await c.Delete(root + "/" + family + "/{type}", [.. p, ("type", roots[family].Permission)]);
            c.Prove(await c.Missing(root + "/" + family + "/{type}", [.. p, ("type", roots[family].Permission)]), "Root policy deletion removes persisted permission", del);
        }
        var dr = await c.Delete(root + "/resource/{resource-id}", rp);
        c.Prove(await c.Missing(root + "/resource/{resource-id}", rp), "Resource deletion persists", dr);
        var ds = await c.Delete(root + "/scope/{scope-id}", sp);
        c.Prove(await c.Missing(root + "/scope/{scope-id}", sp), "Scope deletion persists", ds);
        Console.WriteLine("PASS full authorization: resource/scope storage, dynamic policy routes, dependency graph, real evaluation and settings import/export.");
    }
    private static async Task Links(LiveContext c, string path, (string, string)[] values, string resource, string scope, string policy)
    {
        var own = await c.Get(path, O("""{"fields":"*"}"""), values);
        var resources = await c.Get(path + "/resources", null, values);
        var scopes = await c.Get(path + "/scopes", null, values);
        var associated = await c.Get(path + "/associatedPolicies", null, values);
        c.Prove(S(own.J, "id").Length > 0 && Has(resources.J, "_id", resource) && Has(scopes.J, "id", scope) && Has(associated.J, "id", policy), "Policy ID lookup and resource/scope/associated-policy links reflect stored dependency graph", own, resources, scopes, associated);
    }
}
