using System.Text;
using System.Text.Json.Nodes;
using static LiveContext;

internal static class FullCore
{
    public static async Task<LiveFacts> RunAsync(LiveContext c)
    {
        var realms = await c.Get("/admin/realms");
        c.Prove(Has(realms.J, "realm", c.Realm), "Realm listing includes the newly persisted realm", realms);
        var info = await c.Get("/admin/serverinfo");
        c.Prove(S(info.J?["systemInfo"], "version") == "26.8.1", "Authenticated serverinfo reports actual pinned server version", info);
        var update = await c.Put("", O("""{"displayName":"Full acceptance","accessTokenLifespan":123}"""));
        var realm = await c.Get("");
        c.Prove(S(realm.J, "displayName") == "Full acceptance" && realm.J?["accessTokenLifespan"]?.GetValue<int>() == 123, "Realm configuration writes change persisted fields", update, realm);
        var keys = await c.Get("keys");
        c.Prove(keys.J?["keys"] is JsonArray { Count: > 0 } && keys.J?["active"]?["RS256"] is not null, "Realm key metadata contains active RSA signing key", keys);
        var registrators = await c.Get("credential-registrators");
        c.Prove(registrators.J is JsonArray a && a.Any(n => n?.GetValue<string>() == "webauthn-register"), "Credential registrar discovery contains installed WebAuthn provider", registrators);

        string scope = "";
        foreach (string collection in new[] { "client-scopes", "client-templates" })
        {
            var create = await c.Post(collection, new JsonObject { ["name"] = "full-" + collection, ["protocol"] = "openid-connect" });
            string id = create.Id;
            string path = collection + "/{client-scope-id}";
            var read = await c.Get(path, null, ("client-scope-id", id));
            c.Prove(S(read.J, "name") == "full-" + collection, "Client scope creation persists through its collection alias", create, read);
            var list = await c.Get(collection);
            c.Prove(Has(list.J, "id", id), "Scope collection lists created scope", list);
            var put = await c.Put(path, new JsonObject { ["name"] = "full-" + collection, ["protocol"] = "openid-connect", ["description"] = "scope persisted" }, ("client-scope-id", id));
            read = await c.Get(path, null, ("client-scope-id", id));
            c.Prove(S(read.J, "description") == "scope persisted", "Scope update changes persisted description", put, read);
            if (collection == "client-scopes") scope = id;
            else
            {
                var remove = await c.Delete(path, ("client-scope-id", id));
                c.Prove(await c.Missing(path, ("client-scope-id", id)), "Legacy template deletion removes scope", remove);
            }
        }
        foreach (string type in new[] { "default-default-client-scopes", "default-optional-client-scopes" })
        {
            string path = type + "/{clientScopeId}";
            var add = await c.Put(path, null, ("clientScopeId", scope));
            var read = await c.Get(type);
            c.Prove(Has(read.J, "id", scope), "Realm default scope relationship persisted: " + type, add, read);
            var del = await c.Delete(path, ("clientScopeId", scope)); read = await c.Get(type);
            c.Prove(!Has(read.J, "id", scope), "Realm default scope relationship removed: " + type, del, read);
        }
        var group = await c.Post("groups", O("""{"name":"full-parent"}"""));
        string gid = group.Id;
        var groupRead = await c.Get("groups/{group-id}", null, ("group-id", gid));
        c.Prove(S(groupRead.J, "name") == "full-parent", "Group creation persists name", group, groupRead);
        var gp = await c.Put("groups/{group-id}", O("""{"name":"full-parent","attributes":{"marker":["persisted"]}}"""), ("group-id", gid));
        groupRead = await c.Get("groups/{group-id}", null, ("group-id", gid));
        c.Prove(groupRead.J?["attributes"]?["marker"]?[0]?.GetValue<string>() == "persisted", "Group attribute update persists multivalue data", gp, groupRead);
        var child = await c.Post("groups/{group-id}/children", O("""{"name":"full-child"}"""), null, ("group-id", gid));
        string childId = child.Id;
        var children = await c.Get("groups/{group-id}/children", null, ("group-id", gid));
        c.Prove(Has(children.J, "id", childId), "Child creation persists parent-child relationship", child, children);
        var byPath = await c.Get("group-by-path/{path}", null, ("path", "full-parent/full-child"));
        c.Prove(S(byPath.J, "id") == childId, "Nested group path resolves actual persisted child", byPath);
        var groups = await c.Get("groups", O("""{"search":"full-parent","exact":true}"""));
        var count = await c.Get("groups/count");
        c.Prove(Has(groups.J, "id", gid) && count.J?["count"]?.GetValue<int>() == 2, "Group search and count reflect two created groups", groups, count);
        var defaultGroup = await c.Put("default-groups/{groupId}", null, ("groupId", gid));
        var defaults = await c.Get("default-groups");
        c.Prove(Has(defaults.J, "id", gid), "Realm default group assignment persisted", defaultGroup, defaults);

        const string password = "Full-acceptance-Password-123!";
        var userCreate = await c.Post("users", new JsonObject
        {
            ["username"] = "full-user", ["enabled"] = true, ["firstName"] = "Full", ["lastName"] = "Acceptance",
            ["email"] = "full-user@example.invalid", ["emailVerified"] = true,
            ["credentials"] = new JsonArray(new JsonObject { ["type"] = "password", ["value"] = password, ["temporary"] = false })
        });
        string uid = userCreate.Id;
        var user = await c.Get("users/{user-id}", null, ("user-id", uid));
        c.Prove(S(user.J, "username") == "full-user", "User creation persists profile", userCreate, user);
        var membership = await c.Get("users/{user-id}/groups", null, ("user-id", uid));
        c.Prove(Has(membership.J, "id", gid), "Default group applied to newly created user", membership);
        var removeDefault = await c.Delete("default-groups/{groupId}", ("groupId", gid)); defaults = await c.Get("default-groups");
        c.Prove(!Has(defaults.J, "id", gid), "Removing default group changes realm assignment", removeDefault, defaults);
        var leave = await c.Delete("users/{user-id}/groups/{groupId}", ("user-id", uid), ("groupId", gid));
        membership = await c.Get("users/{user-id}/groups", null, ("user-id", uid));
        c.Prove(!Has(membership.J, "id", gid), "Leaving group removes membership", leave, membership);
        var join = await c.Put("users/{user-id}/groups/{groupId}", null, ("user-id", uid), ("groupId", gid));
        var members = await c.Get("groups/{group-id}/members", null, ("group-id", gid));
        var memberCount = await c.Get("users/{user-id}/groups/count", null, ("user-id", uid));
        c.Prove(Has(members.J, "id", uid) && memberCount.J?["count"]?.GetValue<int>() == 1, "Joining group updates member listing and user membership count", join, members, memberCount);
        var updateUser = await c.Put("users/{user-id}", O("""{"firstName":"Updated","attributes":{"full-unmanaged":["persisted"]}}"""), ("user-id", uid));
        user = await c.Get("users/{user-id}", null, ("user-id", uid));
        c.Prove(S(user.J, "firstName") == "Updated", "User profile update persisted", updateUser, user);
        var listUsers = await c.Get("users", O("""{"username":"full-user","exact":true}"""));
        var usersCount = await c.Get("users/count", O("""{"username":"full-user","exact":true}"""));
        c.Prove(Has(listUsers.J, "id", uid) && usersCount.J?.GetValue<int>() == 1, "Exact user search and count select the created user", listUsers, usersCount);
        var clientCreate = await c.Post("clients", O("""{"clientId":"full-client","name":"Full client","enabled":true,"protocol":"openid-connect","publicClient":false,"secret":"full-client-secret","directAccessGrantsEnabled":true,"serviceAccountsEnabled":true,"authorizationServicesEnabled":true,"redirectUris":["http://localhost/callback"]}"""));
        string cid = clientCreate.Id;
        var client = await c.Get("clients/{client-uuid}", null, ("client-uuid", cid));
        c.Prove(S(client.J, "clientId") == "full-client", "Client creation persisted internal ID and public client ID", clientCreate, client);
        var clientUpdate = await c.Put("clients/{client-uuid}", O("""{"name":"Client updated","authorizationServicesEnabled":true}"""), ("client-uuid", cid));
        client = await c.Get("clients/{client-uuid}", null, ("client-uuid", cid));
        c.Prove(S(client.J, "name") == "Client updated" && client.J?["authorizationServicesEnabled"]?.GetValue<bool>() == true, "Client update persists while preserving authorization services", clientUpdate, client);
        var clients = await c.Get("clients", O("""{"clientId":"full-client"}"""));
        c.Prove(Has(clients.J, "id", cid), "Client query resolves created internal ID", clients);
        foreach (string type in new[] { "default-client-scopes", "optional-client-scopes" })
        {
            string path = "clients/{client-uuid}/" + type;
            var add = await c.Put(path + "/{clientScopeId}", null, ("client-uuid", cid), ("clientScopeId", scope));
            var read = await c.Get(path, null, ("client-uuid", cid));
            c.Prove(Has(read.J, "id", scope), "Client scope relationship persisted: " + type, add, read);
            var del = await c.Delete(path + "/{clientScopeId}", ("client-uuid", cid), ("clientScopeId", scope));
            read = await c.Get(path, null, ("client-uuid", cid));
            c.Prove(!Has(read.J, "id", scope), "Client scope relationship removed: " + type, del, read);
        }
        var initial = await c.Post("clients-initial-access", O("""{"count":2,"expiration":300}"""));
        string initialId = S(initial.J, "id");
        var initials = await c.Get("clients-initial-access");
        c.Prove(initialId.Length > 0 && S(initial.J, "token").Length > 0 && Has(initials.J, "id", initialId), "Initial access token is issued and persisted", initial, initials);
        var delInitial = await c.Delete("clients-initial-access/{id}", ("id", initialId)); initials = await c.Get("clients-initial-access");
        c.Prove(!Has(initials.J, "id", initialId), "Initial access token deletion persisted", delInitial, initials);
        foreach (string key in new[] { "first", "second" })
        {
            var save = await c.Call("PUT", "localization/{locale}/{key}", raw: new StringContent("value-" + key, Encoding.UTF8, "text/plain"), paths: [("locale", "zz"), ("key", key)]);
            var text = await c.Get("localization/{locale}/{key}", null, ("locale", "zz"), ("key", key));
            c.Prove(Encoding.UTF8.GetString(text.Response.Content.Span).Contains("value-" + key, StringComparison.Ordinal), "Localization key write is readable", save, text);
        }
        var locales = await c.Get("localization");
        c.Prove(locales.J is JsonArray la && la.Any(v => v?.GetValue<string>() == "zz"), "Locale enumeration reflects persisted translations", locales);
        var delText = await c.Delete("localization/{locale}/{key}", ("locale", "zz"), ("key", "first"));
        var texts = await c.Get("localization/{locale}", null, ("locale", "zz"));
        c.Prove(texts.J?["first"] is null && S(texts.J, "second") == "value-second", "Deleting a localization key preserves its sibling", delText, texts);
        var delLocale = await c.Delete("localization/{locale}", ("locale", "zz")); texts = await c.Get("localization/{locale}", null, ("locale", "zz"));
        c.Prove(texts.J is JsonObject { Count: 0 }, "Locale deletion removes all persisted translations", delLocale, texts);
        Console.WriteLine("PASS full core: realm, users, nested groups, scopes, client relationships, initial tokens and localization persisted.");
        return new(cid, uid, gid, scope, password);
    }
}
