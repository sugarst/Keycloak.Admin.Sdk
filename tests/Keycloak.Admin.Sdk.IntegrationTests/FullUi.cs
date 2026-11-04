using System.Text.Json.Nodes;
using static LiveContext;

internal static class FullUi
{
    public static async Task RunAsync(LiveContext c, LiveFacts f)
    {
        var rr = await c.Get("roles/{role-name}", null, ("role-name", "full-realm-parent"));
        var cr = await c.Get("clients/{client-uuid}/roles/{role-name}", null, ("client-uuid", f.Client), ("role-name", "full-client-parent"));
        var leaf = await c.Get("clients/{client-uuid}/roles/{role-name}", null, ("client-uuid", f.Client), ("role-name", "full-client-leaf"));
        string rid = S(rr.J, "id"), cid = S(cr.J, "id"), lid = S(leaf.J, "id");
        var realm = await c.Get(""); string defaultName = S(realm.J?["defaultRole"], "name");
        // The released EffectiveRoleMappingResource.roles ignores {id} and reads default role.
        await c.Post("roles/{role-name}/composites", new JsonArray(cr.J!.DeepClone()), paths: [("role-name", defaultName)]);
        var uiOwner = await c.Post("clients", O("""{"clientId":"full-ui-scope-owner","protocol":"openid-connect","fullScopeAllowed":false}"""));
        var owners = new[] { ("clientScopes", f.Scope, "client-scopes/{client-scope-id}/scope-mappings/clients/{client}", new[] { ("client-scope-id", f.Scope), ("client", f.Client) }),
            ("clients", uiOwner.Id, "clients/{client-uuid}/scope-mappings/clients/{client}", new[] { ("client-uuid", uiOwner.Id), ("client", f.Client) }),
            ("groups", f.Group, "groups/{group-id}/role-mappings/clients/{client-id}", new[] { ("group-id", f.Group), ("client-id", f.Client) }),
            ("users", f.User, "users/{user-id}/role-mappings/clients/{client-id}", new[] { ("user-id", f.User), ("client-id", f.Client) }),
            ("roles", rid, "roles/{role-name}/composites", new[] { ("role-name", "full-realm-parent") }) };
        foreach (var (type, id, prefix, paths) in owners)
        {
            await c.Post(prefix, new JsonArray(cr.J!.DeepClone()), paths: paths);
            var effective = await c.Get("ui-ext/effective-roles/" + type + "/{id}", null, ("id", id));
            var all = await c.Get("ui-ext/effective-roles-all/" + type + "/{id}", null, ("id", id));
            c.Prove(Has(effective.J, "id", lid) && Has(all.J, "id", lid), "UI effective-role projections resolve actual composite child for " + type + (type == "roles" ? " (legacy endpoint uses realm default role in released source)" : ""), effective, all);
            var remove = await c.Post("ui-ext/role-mapping-delete/" + type + "/{id}", new JsonArray(new JsonObject { ["roleId"] = cid, ["roleName"] = "full-client-parent", ["clientId"] = f.Client }), paths: [("id", id)]);
            var mappings = await c.Get(prefix, null, paths);
            c.Prove(!Has(mappings.J, "id", cid), "UI bulk mapping deletion removes actual direct client role for " + type, remove, mappings);
            var available = await c.Get("ui-ext/available-roles/" + type + "/{id}", O("""{"search":"full-client-parent","max":100}"""), ("id", id));
            c.Prove(Has(available.J, "id", cid), "UI available-role search exposes removed client role for " + type, available);
            await c.Post(prefix, new JsonArray(cr.J.DeepClone()), paths: paths);
        }
        var composites = await c.Get("ui-ext/role-mappings/roles/{id}", null, ("id", rid));
        c.Prove(Has(composites.J?["clientMappings"]?["full-client"]?["mappings"], "id", cid), "UI composite mapping groups persisted client role under owning client", composites);
        var flows = await c.Get("ui-ext/authentication-management/flows");
        c.Prove(Has(flows.J, "alias", "browser"), "UI authentication graph lists actual built-in browser flow", flows);
        string browser = S(flows.J!.AsArray().Single(n => S(n, "alias") == "browser"), "id");
        await c.Put("clients/{client-uuid}", new JsonObject { ["authorizationServicesEnabled"] = true, ["authenticationFlowBindingOverrides"] = new JsonObject { ["browser"] = browser } }, ("client-uuid", f.Client));
        var used = await c.Get("ui-ext/authentication-management/{type}/{id}", null, ("type", "clients"), ("id", browser));
        c.Prove(Has(used.J, "id", f.Client) && Has(used.J, "label", "full-client"), "UI flow usage resolves real client binding override", used);
        var actions = await c.Get("ui-ext/authentication-management/required-actions");
        c.Prove(Has(actions.J, "alias", "UPDATE_PASSWORD"), "UI required actions contain configured password action", actions);
        var names = await c.Get("ui-ext/realms/names");
        c.Prove(Has(names.J, "realm", c.Realm) || Has(names.J, "name", c.Realm), "UI realm names includes isolated persisted realm", names);
        var info = await c.Get("ui-ext/info");
        c.Prove(info.J?["userProfileProvidersEnabled"]?.GetValue<bool>() == false, "UI realm info reports no configured external user provider", info);
        var updated = await c.Put("ui-ext/", O("""{"displayName":"Updated via UI API"}"""));
        realm = await c.Get("");
        c.Prove(S(realm.J, "displayName") == "Updated via UI API", "UI realm update changes actual realm display name", updated, realm);
        var listeners = await c.Get("ui-ext/available-event-listeners/");
        c.Prove(Has(listeners.J, "id", "jboss-logging"), "UI event-listener discovery exposes installed logging listener", listeners);
        var deleteOwner = await c.Delete("clients/{client-uuid}", ("client-uuid", uiOwner.Id));
        c.Prove(await c.Missing("clients/{client-uuid}", ("client-uuid", uiOwner.Id)), "Deleting client removes actual scope owner", deleteOwner);
        Console.WriteLine("PASS full UI extensions: effective/available roles, bulk deletion, composites, flow bindings and realm configuration.");
    }
}
