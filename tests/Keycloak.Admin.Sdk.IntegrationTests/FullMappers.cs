using System.Text.Json.Nodes;
using static LiveContext;

internal static class FullMappers
{
    public static async Task RunAsync(LiveContext c, LiveFacts f)
    {
        var paths = new[] { ("client-uuid", f.Client), ("client-scope-id", f.Scope), ("protocol", "openid-connect") };
        foreach (string owner in new[] { "clients/{client-uuid}", "client-scopes/{client-scope-id}", "client-templates/{client-scope-id}" })
        {
            string root = owner + "/protocol-mappers";
            JsonObject Mapper(string name, string claim) => O("""{"protocol":"openid-connect","protocolMapper":"oidc-usermodel-property-mapper","config":{"user.attribute":"firstName","jsonType.label":"String","access.token.claim":"true","id.token.claim":"true","userinfo.token.claim":"true"}}""").With("name", name).WithConfig("claim.name", claim);
            var add = await c.Post(root + "/models", Mapper("full-single-mapper", "full_single"), null, paths);
            string id = add.Id;
            var get = await c.Get(root + "/models/{id}", null, [.. paths, ("id", id)]);
            var list = await c.Get(root + "/models", null, paths);
            var protocol = await c.Get(root + "/protocol/{protocol}", null, paths);
            c.Prove(S(get.J, "name") == "full-single-mapper" && Has(list.J, "id", id) && Has(protocol.J, "id", id), "Protocol mapper creation persists and is visible through ID/list/protocol queries: " + owner, add, get, list, protocol);
            var body = get.J!.DeepClone(); body["config"]!["claim.name"] = "full_changed";
            var update = await c.Put(root + "/models/{id}", body, [.. paths, ("id", id)]);
            get = await c.Get(root + "/models/{id}", null, [.. paths, ("id", id)]);
            c.Prove(S(get.J?["config"], "claim.name") == "full_changed", "Protocol mapper update changes stored claim configuration", update, get);
            var batch = await c.Post(root + "/add-models", new JsonArray(Mapper("full-batch-one", "full_first"), Mapper("full-batch-two", "full_other")), null, paths);
            list = await c.Get(root + "/models", null, paths);
            c.Prove(Has(list.J, "name", "full-batch-one") && Has(list.J, "name", "full-batch-two"), "Bulk mapper creation persists both model definitions", batch, list);
            var delete = await c.Delete(root + "/models/{id}", [.. paths, ("id", id)]);
            list = await c.Get(root + "/models", null, paths);
            c.Prove(!Has(list.J, "id", id) && Has(list.J, "name", "full-batch-one"), "Mapper deletion removes only selected persisted model", delete, list);
            // Legacy template paths and client-scope paths address the same store; avoid name conflicts.
            if (owner != "clients/{client-uuid}")
                foreach (var model in list.J!.AsArray().Where(m => S(m, "name").StartsWith("full-", StringComparison.Ordinal)))
                    await c.Delete(root + "/models/{id}", [.. paths, ("id", S(model, "id"))]);
        }
        string evaluate = "clients/{client-uuid}/evaluate-scopes";
        var query = new JsonObject { ["userId"] = f.User, ["scope"] = "openid" };
        foreach (string kind in new[] { "access-token", "id-token", "userinfo" })
        {
            var result = await c.Get(evaluate + "/generate-example-" + kind, query, paths);
            c.Prove(S(result.J, "full_first") == "Updated" && S(result.J, "sub") == f.User, "Evaluated " + kind + " contains actual user ID and claim emitted by persisted mapper", result);
        }
        var effective = await c.Get(evaluate + "/protocol-mappers", new JsonObject { ["scope"] = "openid" }, paths);
        c.Prove(effective.J is JsonArray ea && ea.Any(m => S(m, "mapperName") == "full-batch-one" || S(m?["mapper"], "name") == "full-batch-one" || S(m, "name") == "full-batch-one"), "Effective mapper evaluation includes persisted client mapper", effective);
        var realmRole = await c.Get("roles/{role-name}", null, ("role-name", "full-realm-parent"));
        var notGranted = await c.Get(evaluate + "/scope-mappings/{roleContainerId}/not-granted", null, ("client-uuid", f.Client), ("roleContainerId", c.Realm));
        c.Prove(Has(notGranted.J, "id", S(realmRole.J, "id")), "Evaluation identifies a real realm role outside client scope", notGranted);
        await c.Post("clients/{client-uuid}/scope-mappings/realm", new JsonArray(realmRole.J!.DeepClone()), null, ("client-uuid", f.Client));
        var granted = await c.Get(evaluate + "/scope-mappings/{roleContainerId}/granted", null, ("client-uuid", f.Client), ("roleContainerId", c.Realm));
        c.Prove(Has(granted.J, "id", S(realmRole.J, "id")), "Adding client scope mapping changes effective granted roles", granted);
        var saml = await c.Post("clients", O("""{"clientId":"full-saml","protocol":"saml","enabled":true,"redirectUris":["http://localhost/callback"],"attributes":{"saml.client.signature":"false","saml.assertion.signature":"true"}}"""));
        var example = await c.Get(evaluate + "/generate-example-saml-response", query, ("client-uuid", saml.Id));
        string text = System.Text.Encoding.UTF8.GetString(example.Response.Content.Span);
        c.Prove(text.Contains("Response", StringComparison.Ordinal) && text.Contains("Assertion", StringComparison.Ordinal) && text.Contains("full-user", StringComparison.Ordinal), "SAML evaluation builds an assertion for the actual persisted user", example);
        Console.WriteLine("PASS full mappers: mapper CRUD, bulk/legacy aliases, actual token claims, SAML assertion and granted/not-granted scope changes.");
    }
    private static JsonObject With(this JsonObject obj, string key, string value) { obj[key] = value; return obj; }
    private static JsonObject WithConfig(this JsonObject obj, string key, string value) { obj["config"]![key] = value; return obj; }
}
