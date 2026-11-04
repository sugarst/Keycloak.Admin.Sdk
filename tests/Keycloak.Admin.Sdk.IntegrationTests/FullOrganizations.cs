using System.Text.Json.Nodes;
using static LiveContext;

internal static class FullOrganizations
{
    public static async Task RunAsync(LiveContext c, LiveFacts f)
    {
        var org = await c.Post("organizations", O("""{"name":"Full organization","alias":"full-org","enabled":true,"domains":[{"name":"example.invalid","verified":true}]}"""));
        string oid = org.Id;
        var p = new[] { ("org-id", oid), ("member-id", f.User), ("userId", f.User), ("alias", "full-oidc-idp") };
        string root = "organizations/{org-id}";
        var read = await c.Get(root, null, p);
        var all = await c.Get("organizations", O("""{"search":"Full organization","exact":true}"""));
        var count = await c.Get("organizations/count");
        c.Prove(S(read.J, "alias") == "full-org" && Has(all.J, "id", oid) && count.J!.GetValue<int>() == 1, "Organization creation persists and participates in search/count", org, read, all, count);
        var edit = read.J!.DeepClone(); edit["description"] = "Organization updated";
        var update = await c.Put(root, edit, p); read = await c.Get(root, null, p);
        c.Prove(S(read.J, "description") == "Organization updated", "Organization update persists description", update, read);
        var link = await c.Post(root + "/identity-providers", JsonValue.Create("full-oidc-idp"), null, p);
        var provider = await c.Get(root + "/identity-providers/{alias}", null, p);
        var providers = await c.Get(root + "/identity-providers", null, p);
        c.Prove(S(provider.J, "alias") == "full-oidc-idp" && Has(providers.J, "alias", "full-oidc-idp"), "Organization identity-provider association persists", link, provider, providers);
        var linkEdit = await c.Put(root + "/identity-providers/{alias}", O("""{"autoMembership":false,"membershipType":"UNMANAGED"}"""), p);
        provider = await c.Get(root + "/identity-providers/{alias}", null, p);
        c.Prove(LiveJson.String(provider.J!).Contains("\"autoMembership\":false", StringComparison.Ordinal), "Per-organization identity-provider link stores auto-membership setting", linkEdit, provider);
        var member = await c.Post(root + "/members", JsonValue.Create(f.User), null, p);
        var mr = await c.Get(root + "/members/{member-id}", null, p);
        var members = await c.Get(root + "/members", null, p);
        var mc = await c.Get(root + "/members/count", null, p);
        var userOrgs = await c.Get("organizations/members/{member-id}/organizations", null, p);
        var userOrgsNested = await c.Get(root + "/members/{member-id}/organizations", null, p);
        c.Prove(S(mr.J, "id") == f.User && Has(members.J, "id", f.User) && mc.J!.GetValue<int>() == 1 && Has(userOrgs.J, "id", oid) && Has(userOrgsNested.J, "id", oid), "Organization membership is visible through member, count and reverse-organization queries", member, mr, members, mc, userOrgs, userOrgsNested);
        var managed = await c.Put(root + "/members/{member-id}/membership-type", JsonValue.Create("MANAGED"), p);
        mr = await c.Get(root + "/members/{member-id}", null, p);
        c.Prove(S(mr.J, "membershipType") == "MANAGED", "Changing membership type persists managed state", managed, mr);
        var unmanaged = await c.Put(root + "/members/{member-id}/membership-type", JsonValue.Create("UNMANAGED"), p);
        mr = await c.Get(root + "/members/{member-id}", null, p);
        c.Prove(S(mr.J, "membershipType") == "UNMANAGED", "Changing membership type restores unmanaged state", unmanaged, mr);
        var group = await c.Post(root + "/groups", O("""{"name":"FullOrgTeam"}"""), null, p);
        string gid = group.Id; var gp = p.Append(("group-id", gid)).ToArray();
        var gr = await c.Get(root + "/groups/{group-id}", null, gp);
        var groups = await c.Get(root + "/groups", null, p);
        c.Prove(S(gr.J, "name") == "FullOrgTeam" && Has(groups.J, "id", gid), "Organization group creation persists within its organization", group, gr, groups);
        var gu = await c.Put(root + "/groups/{group-id}", O("""{"name":"FullOrgTeam","description":"Organization group updated"}"""), gp);
        gr = await c.Get(root + "/groups/{group-id}", null, gp);
        c.Prove(S(gr.J, "description") == "Organization group updated", "Organization group update persists description", gu, gr);
        var child = await c.Post(root + "/groups/{group-id}/children", O("""{"name":"FullOrgChild"}"""), null, gp);
        var children = await c.Get(root + "/groups/{group-id}/children", null, gp);
        var path = await c.Get(root + "/groups/group-by-path/{path}", null, [.. p, ("path", "FullOrgTeam/FullOrgChild")]);
        c.Prove(Has(children.J, "id", child.Id) && S(path.J, "id") == child.Id, "Organization nested group creation and path lookup agree on persisted child", child, children, path);
        var join = await c.Put(root + "/groups/{group-id}/members/{userId}", null, gp);
        var gm = await c.Get(root + "/groups/{group-id}/members", null, gp);
        var mg = await c.Get(root + "/members/{member-id}/groups", null, p);
        var providerGroups = await c.Get(root + "/identity-providers/{alias}/groups", null, p);
        c.Prove(Has(gm.J, "id", f.User) && Has(mg.J, "id", gid) && Has(providerGroups.J, "id", gid), "Organization member/group and linked provider group queries reflect actual membership", join, gm, mg, providerGroups);
        var roles = new Dictionary<string, JsonNode>();
        foreach (string suffix in new[] { "realm-parent", "realm-leaf", "client-parent", "client-leaf" })
        {
            bool clientRole = suffix.StartsWith("client", StringComparison.Ordinal);
            var role = await c.Get(clientRole ? "clients/{client-uuid}/roles/{role-name}" : "roles/{role-name}", null, ("client-uuid", f.Client), ("role-name", "full-" + suffix));
            roles[suffix] = role.J!;
        }
        await FullRoles.Mappings(c, root + "/groups/{group-id}/role-mappings", roles, [.. gp, ("client-id", f.Client)], "client-id");
        var leave = await c.Delete(root + "/groups/{group-id}/members/{userId}", gp); gm = await c.Get(root + "/groups/{group-id}/members", null, gp);
        c.Prove(!Has(gm.J, "id", f.User), "Organization group leave removes persisted membership", leave, gm);
        var deleteGroup = await c.Delete(root + "/groups/{group-id}", gp); groups = await c.Get(root + "/groups", null, p);
        c.Prove(!Has(groups.J, "id", gid), "Deleting organization group removes group subtree", deleteGroup, groups);
        var unlink = await c.Delete(root + "/identity-providers/{alias}", p); providers = await c.Get(root + "/identity-providers", null, p);
        c.Prove(!Has(providers.J, "alias", "full-oidc-idp"), "Organization unlink removes identity-provider association", unlink, providers);
        var leaveOrg = await c.Delete(root + "/members/{member-id}", p); members = await c.Get(root + "/members", null, p);
        c.Prove(!Has(members.J, "id", f.User) && !await c.Missing("users/{user-id}", ("user-id", f.User)), "Unmanaged member removal preserves underlying user", leaveOrg, members);
        var deleteOrg = await c.Delete(root, p);
        c.Prove(await c.Missing(root, p), "Deleting organization removes persisted entity", deleteOrg);
        Console.WriteLine("PASS full organizations: organization/group/member CRUD, managed/unmanaged state, provider links and organization-scoped role mappings.");
    }
}
