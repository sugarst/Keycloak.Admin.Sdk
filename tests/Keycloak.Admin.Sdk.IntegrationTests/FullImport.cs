using System.Text;
using System.Text.Json.Nodes;
using static LiveContext;

internal static class FullImport
{
    public static async Task RunAsync(LiveContext c, LiveFacts f)
    {
        const string metadata = """
        <EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="full-saml-converted">
          <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.invalid/acs" index="0"/>
          </SPSSODescriptor>
        </EntityDescriptor>
        """;
        var converted = await c.Call("POST", "client-description-converter", raw: new StringContent(metadata, Encoding.UTF8, "application/xml"));
        c.Prove(S(converted.J, "clientId") == "full-saml-converted" && S(converted.J, "protocol") == "saml" && converted.J?["redirectUris"]?.AsArray().Any(n => n?.GetValue<string>() == "https://sp.example.invalid/acs") == true, "SAML metadata converter parses actual entity ID, protocol and assertion consumer URL", converted);
        var imported = await c.Post("partialImport", O("""{"ifResourceExists":"FAIL","users":[{"username":"full-partial-user","enabled":true}],"groups":[{"name":"full-partial-group","path":"/full-partial-group"}],"clients":[{"clientId":"full-partial-client","protocol":"openid-connect"}],"roles":{"realm":[{"name":"full-partial-role"}]}}"""));
        var users = await c.Get("users", O("""{"username":"full-partial-user","exact":true}"""));
        var groups = await c.Get("groups", O("""{"search":"full-partial-group","exact":true}"""));
        var clients = await c.Get("clients", O("""{"clientId":"full-partial-client"}"""));
        var role = await c.Get("roles/{role-name}", null, ("role-name", "full-partial-role"));
        c.Prove(imported.J?["added"]?.GetValue<int>() == 4 && Has(users.J, "username", "full-partial-user") && Has(groups.J, "name", "full-partial-group") && Has(clients.J, "clientId", "full-partial-client") && S(role.J, "name") == "full-partial-role", "Partial import persists all four real resource kinds with added count", imported);
        var exported = await c.Post("partial-export", query: O("""{"exportClients":true,"exportGroupsAndRoles":true}"""));
        c.Prove(Has(exported.J?["clients"], "clientId", "full-partial-client") && Has(exported.J?["groups"], "name", "full-partial-group") && Has(exported.J?["roles"]?["realm"], "name", "full-partial-role"), "Partial export contains imported client, group and realm role", exported);
        var groupDelete = await c.Delete("groups/{group-id}", ("group-id", S(groups.J![0], "id")));
        c.Prove(await c.Missing("groups/{group-id}", ("group-id", S(groups.J![0], "id"))), "Deleting group removes actual imported group", groupDelete);
        var scopeDelete = await c.Delete("client-scopes/{client-scope-id}", ("client-scope-id", f.Scope));
        c.Prove(await c.Missing("client-scopes/{client-scope-id}", ("client-scope-id", f.Scope)), "Deleting client scope removes actual scope and its configuration", scopeDelete);
        Console.WriteLine("PASS full import/export: SAML conversion, persisted resource import and portable export, group/scope deletion.");
    }
}
