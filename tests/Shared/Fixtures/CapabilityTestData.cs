using System.Text;
using Keycloak.Admin.Sdk;

public static class CapabilityTestData
{
    public static byte[] ServerInfo(string version = KeycloakTarget.Version, int route = 2, string? missing = null, string? disabled = null)
    {
        var features = new Dictionary<string, bool> { ["ADMIN_API"] = true, ["AUTHORIZATION"] = true, ["ORGANIZATION"] = true,
            ["ADMIN_V2"] = true, ["WORKFLOWS"] = true, ["CLIENT_POLICIES"] = true, ["IMPERSONATION"] = true, ["ADMIN_FINE_GRAINED_AUTHZ"] = route == 1,
            ["ADMIN_FINE_GRAINED_AUTHZ_V2"] = route == 2, ["OID4VC_VCI"] = true, ["SSF"] = true, ["CLIENT_TYPES"] = true };
        if (missing is not null) features.Remove(missing);
        if (disabled is not null) features[disabled] = false;
        return Encoding.UTF8.GetBytes("{\"systemInfo\":{\"version\":\"" + version + "\"},\"features\":[" + string.Join(',', features.Select(f => "{\"name\":\"" + f.Key + "\",\"enabled\":" + (f.Value ? "true" : "false") + "}")) + "]}");
    }
}
