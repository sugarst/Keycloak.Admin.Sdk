using System.Text.Json.Nodes;
using static LiveContext;

internal static class FullStorage
{
    public static async Task RunAsync(LiveContext c)
    {
        await using var ldap = await LdapFixture.Connect(c.Cancellation);
        string baseDn = "ou=" + c.Realm + ",dc=example,dc=org", usersDn = "ou=users," + baseDn, groupsDn = "ou=groups," + baseDn;
        string userDn = "uid=full-ldap-user," + usersDn, groupDn = "cn=full-ldap-group," + groupsDn;
        try
        {
            await ldap.Add(baseDn, c.Cancellation, ("objectClass", ["organizationalUnit"]), ("ou", [c.Realm]));
            await ldap.Add(usersDn, c.Cancellation, ("objectClass", ["organizationalUnit"]), ("ou", ["users"]));
            await ldap.Add(groupsDn, c.Cancellation, ("objectClass", ["organizationalUnit"]), ("ou", ["groups"]));
            await ldap.Add(userDn, c.Cancellation, ("objectClass", ["inetOrgPerson"]), ("uid", ["full-ldap-user"]), ("cn", ["LDAP Initial"]), ("sn", ["Acceptance"]), ("givenName", ["LDAP"]), ("mail", ["ldap@example.invalid"]), ("userPassword", ["LDAP-test-password"]));
            await ldap.Add(groupDn, c.Cancellation, ("objectClass", ["groupOfNames"]), ("cn", ["full-ldap-group"]), ("member", [userDn]));
            var connection = new JsonObject { ["action"] = "testAuthentication", ["connectionUrl"] = "ldap://ldap:389", ["bindDn"] = "cn=admin,dc=example,dc=org", ["bindCredential"] = Environment.GetEnvironmentVariable("KC_TEST_LDAP_PASSWORD"), ["authType"] = "simple", ["startTls"] = "false", ["useTruststoreSpi"] = "never", ["connectionTimeout"] = "5000" };
            var test = await c.Post("testLDAPConnection", connection);
            connection["action"] = "queryServerCapabilities";
            var capabilities = await c.Post("ldap-server-capabilities", connection);
            await File.WriteAllTextAsync("artifacts/ldap-capabilities.json", LiveJson.String(capabilities.J!), cancellationToken: c.Cancellation);
            c.Prove(capabilities.J is JsonArray { Count: > 0 } && capabilities.J.AsArray().Any(n => S(n, "oid").StartsWith("1.3.6.", StringComparison.Ordinal)), "Keycloak binds to actual OpenLDAP and discovers root-DSE supported capabilities", test, capabilities);
            var config = new JsonObject();
            foreach (var (key, value) in new[] { ("enabled", "true"), ("priority", "0"), ("vendor", "other"), ("connectionUrl", "ldap://ldap:389"), ("bindDn", "cn=admin,dc=example,dc=org"), ("bindCredential", Environment.GetEnvironmentVariable("KC_TEST_LDAP_PASSWORD")!), ("authType", "simple"), ("usersDn", usersDn), ("usernameLDAPAttribute", "uid"), ("rdnLDAPAttribute", "uid"), ("uuidLDAPAttribute", "entryUUID"), ("userObjectClasses", "inetOrgPerson, organizationalPerson"), ("editMode", "READ_ONLY"), ("importEnabled", "true"), ("syncRegistrations", "false"), ("cachePolicy", "DEFAULT"), ("pagination", "true"), ("searchScope", "1"), ("connectionPooling", "false") }) config[key] = new JsonArray(value);
            var component = new JsonObject { ["name"] = "full-ldap", ["providerId"] = "ldap", ["providerType"] = "org.keycloak.storage.UserStorageProvider", ["parentId"] = c.RealmId, ["config"] = config };
            var create = await c.Post("components", component); string id = create.Id; var p = new[] { ("id", id) };
            var read = await c.Get("components/{id}", null, p);
            var list = await c.Get("components", new JsonObject { ["parent"] = c.RealmId, ["type"] = "org.keycloak.storage.UserStorageProvider" });
            var name = await c.Get("user-storage/{id}/name", null, p);
            c.Prove(S(read.J, "providerId") == "ldap" && Has(list.J, "id", id) && S(name.J, "name") == "full-ldap", "LDAP component creation persists provider, parent and discoverable storage name", create, read, list, name);
            component["id"] = id; component["name"] = "full-ldap-updated";
            var update = await c.Put("components/{id}", component, p); read = await c.Get("components/{id}", null, p);
            c.Prove(S(read.J, "name") == "full-ldap-updated", "Component update persists renamed LDAP provider", update, read);
            var subTypes = await c.Get("components/{id}/sub-component-types", O("""{"type":"org.keycloak.storage.ldap.mappers.LDAPStorageMapper"}"""), p);
            c.Prove(Has(subTypes.J, "id", "group-ldap-mapper"), "Subcomponent discovery exposes installed LDAP group mapper", subTypes);
            var sync = await c.Post("user-storage/{id}/sync", query: O("""{"action":"triggerFullSync"}"""), paths: p);
            var users = await c.Get("users", O("""{"username":"full-ldap-user","exact":true}"""));
            string uid = S(users.J!.AsArray().Single(), "id");
            c.Prove(sync.J?["added"]?.GetValue<int>() == 1 && Has(users.J, "federationLink", id), "Full LDAP sync imports actual directory user with provider link", sync, users);
            // The released "other" vendor's default first-name mapper reads cn.
            await ldap.Replace(userDn, "cn", "LDAP Changed", c.Cancellation);
            var cache = await c.Post("clear-user-cache");
            var user = await c.Get("users/{user-id}", null, ("user-id", uid));
            c.Prove(S(user.J, "firstName") == "LDAP Changed", "Clearing user cache exposes external LDAP attribute mutation", cache, user);
            var mapperConfig = O("""{"mode":["IMPORT"],"group.name.ldap.attribute":["cn"],"group.object.classes":["groupOfNames"],"membership.ldap.attribute":["member"],"membership.attribute.type":["DN"],"membership.user.ldap.attribute":["uid"],"preserve.group.inheritance":["false"],"ignore.missing.groups":["false"],"user.roles.retrieve.strategy":["LOAD_GROUPS_BY_MEMBER_ATTRIBUTE"],"groups.path":["/"]}"""); mapperConfig["groups.dn"] = new JsonArray(groupsDn);
            var mapper = await c.Post("components", new JsonObject { ["name"] = "full-ldap-groups", ["parentId"] = id, ["providerType"] = "org.keycloak.storage.ldap.mappers.LDAPStorageMapper", ["providerId"] = "group-ldap-mapper", ["config"] = mapperConfig });
            var mapperSync = await c.Post("user-storage/{parentId}/mappers/{id}/sync", query: O("""{"direction":"fedToKeycloak"}"""), paths: [("parentId", id), ("id", mapper.Id)]);
            var groups = await c.Get("groups", O("""{"search":"full-ldap-group","exact":true}"""));
            c.Prove(mapperSync.J?["added"]?.GetValue<int>() == 1 && Has(groups.J, "name", "full-ldap-group"), "LDAP group mapper sync imports actual directory group", mapperSync, groups);
            var remove = await c.Post("user-storage/{id}/remove-imported-users", paths: p);
            // Disable provider before lookup, otherwise lookup immediately reimports the directory user.
            config["enabled"] = new JsonArray("false"); await c.Put("components/{id}", component, p);
            c.Prove(await c.Missing("users/{user-id}", ("user-id", uid)), "Remove-imported-users deletes previously imported local user", remove);
            config["enabled"] = new JsonArray("true"); await c.Put("components/{id}", component, p);
            await c.Post("user-storage/{id}/sync", query: O("""{"action":"triggerFullSync"}"""), paths: p);
            users = await c.Get("users", O("""{"username":"full-ldap-user","exact":true}""")); uid = S(users.J!.AsArray().Single(), "id");
            var unlink = await c.Post("user-storage/{id}/unlink-users", paths: p);
            config["enabled"] = new JsonArray("false"); await c.Put("components/{id}", component, p);
            user = await c.Get("users/{user-id}", null, ("user-id", uid));
            c.Prove(S(user.J, "federationLink").Length == 0 && S(user.J, "username") == "full-ldap-user", "Unlink-users preserves imported user while removing federation link", unlink, user);
            var deleted = await c.Delete("components/{id}", p);
            c.Prove(await c.Missing("components/{id}", p), "Deleting LDAP component removes its persisted provider configuration", deleted);
        }
        finally
        {
            // Cancellation can leave an incomplete LDAP frame; clean up on a fresh connection.
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            await using var cleanupLdap = await LdapFixture.Connect(cleanup.Token);
            await cleanupLdap.Delete(groupDn, cleanup.Token, ignoreMissing: true); await cleanupLdap.Delete(userDn, cleanup.Token, ignoreMissing: true);
            await cleanupLdap.Delete(groupsDn, cleanup.Token, ignoreMissing: true); await cleanupLdap.Delete(usersDn, cleanup.Token, ignoreMissing: true); await cleanupLdap.Delete(baseDn, cleanup.Token, ignoreMissing: true);
        }
        Console.WriteLine("PASS full LDAP storage: actual bind/capabilities, component lifecycle, user/group sync, external mutation/cache, unlink/remove.");
    }
}
