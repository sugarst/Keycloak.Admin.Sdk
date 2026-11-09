using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Keycloak.Admin.Sdk.Protocols;

internal static class ProtocolClientV2Workflows
{
    internal static async Task RunAsync(ProtocolTransport transport, ProtocolTransport managementTransport, string adminToken, string userToken, Action<bool, string> check, CancellationToken ct)
    {
        var client = new ClientAdminV2Client(transport);
        JsonElement Element(JsonNode value) { using var doc = JsonDocument.Parse(value.ToJsonString()); return doc.RootElement.Clone(); }
        var openApi = (await new RuntimeOpenApiClient(managementTransport).GetAsync(ct)).Json!.Value;
        check(openApi.GetProperty("openapi").GetString()!.StartsWith("3.", StringComparison.Ordinal)
            && openApi.GetProperty("paths").EnumerateObject().Any(p => p.Name.Contains("/clients/v2", StringComparison.Ordinal)),
            "Runtime OpenAPI management endpoint publishes the actual Client Admin v2 contract");
        var schemas = openApi.GetProperty("components").GetProperty("schemas");
        var discriminator = schemas.GetProperty("BaseClientRepresentation").GetProperty("discriminator");
        check(discriminator.GetProperty("propertyName").GetString() == "protocol"
            && discriminator.GetProperty("mapping").GetProperty("openid-connect").GetString() == "#/components/schemas/OIDCClientRepresentation"
            && discriminator.GetProperty("mapping").GetProperty("saml").GetString() == "#/components/schemas/SAMLClientRepresentation"
            && schemas.GetProperty("OIDCClientRepresentation").GetProperty("allOf")[0].GetProperty("$ref").GetString() == "#/components/schemas/BaseClientRepresentation"
            && schemas.GetProperty("SAMLClientRepresentation").GetProperty("allOf")[0].GetProperty("$ref").GetString() == "#/components/schemas/BaseClientRepresentation",
            "Runtime OpenAPI preserves the pinned OIDC and SAML schema discrimination and subtype inheritance");
        var body = new JsonObject { ["clientId"] = "v2-json-client", ["protocol"] = "openid-connect", ["displayName"] = "Before", ["enabled"] = true,
            ["redirectUris"] = new JsonArray("https://app.invalid/callback"), ["loginFlows"] = new JsonArray("STANDARD") };
        var created = (await client.CreateAsync(Element(body), adminToken, ct)).Json!.Value;
        string uuid = created.GetProperty("uuid").GetString()!;
        check((await client.GetAsync("v2-json-client", adminToken, ct)).Json!.Value.GetProperty("displayName").GetString() == "Before", "Client Admin v2 creates and reads a declarative OIDC client by clientId");
        bool duplicate = false, uuidNotId = false;
        try { await client.CreateAsync(Element(body), adminToken, ct); }
        catch (KeycloakProtocolException e) when (e.StatusCode == HttpStatusCode.Conflict) { duplicate = true; }
        try { await client.GetAsync(uuid, adminToken, ct); }
        catch (KeycloakProtocolException e) when (e.StatusCode == HttpStatusCode.NotFound) { uuidNotId = true; }
        check(duplicate && uuidNotId, "Client Admin v2 rejects duplicates and does not confuse internal UUID with clientId");
        var page = (await client.ListAsync(adminToken, [new("q", "clientId eq \"v2-json-client\""), new("fields", "clientId,displayName"), new("limit", "1"), new("offset", "0"), new("sort", "displayName|desc")], ct)).Json!.Value;
        check(page.GetArrayLength() == 1 && page[0].GetProperty("clientId").GetString() == "v2-json-client" && !page[0].TryGetProperty("uuid", out _), "Client Admin v2 query projection sorting and pagination preserve the requested fields");
        body["displayName"] = "After"; body["enabled"] = false;
        await client.UpsertAsync("v2-json-client", Element(body), adminToken, ct);
        var updated = (await client.GetAsync("v2-json-client", adminToken, ct)).Json!.Value;
        check(updated.GetProperty("uuid").GetString() == uuid && updated.GetProperty("displayName").GetString() == "After" && !updated.GetProperty("enabled").GetBoolean(), "Client Admin v2 replacement reconciles the existing client without changing its UUID");
        await client.PatchAsync("v2-json-client", Element(new JsonObject { ["description"] = "Patched", ["enabled"] = true }), adminToken, ct);
        var patched = (await client.GetAsync("v2-json-client", adminToken, ct)).Json!.Value;
        check(patched.GetProperty("description").GetString() == "Patched" && patched.GetProperty("displayName").GetString() == "After" && patched.GetProperty("enabled").GetBoolean(), "Client Admin v2 JSON merge patch preserves unspecified configuration");
        bool invalid = false, denied = false;
        try { await client.PatchAsync("v2-json-client", Element(new JsonObject { ["uuid"] = Guid.NewGuid().ToString() }), adminToken, ct); }
        catch (KeycloakProtocolException e) when (e.StatusCode == HttpStatusCode.BadRequest) { invalid = true; }
        try { await client.DeleteAsync("v2-json-client", userToken, ct); }
        catch (KeycloakProtocolException e) when (e.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.Unauthorized) { denied = true; }
        check(invalid && denied && (await client.GetAsync("v2-json-client", adminToken, ct)).Json!.Value.GetProperty("uuid").GetString() == uuid,
            "Client Admin v2 invalid and unauthorized mutations leave the existing client unchanged");
        body["clientId"] = "v2-upsert-client";
        await client.UpsertAsync("v2-upsert-client", Element(body), adminToken, ct);
        await client.CreateAsync(Element(new JsonObject { ["clientId"] = "v2-saml-client", ["protocol"] = "saml", ["displayName"] = "SAML client", ["enabled"] = true }), adminToken, ct);
        check((await client.GetAsync("v2-upsert-client", adminToken, ct)).Json!.Value.GetProperty("clientId").GetString() == "v2-upsert-client"
            && (await client.GetAsync("v2-saml-client", adminToken, ct)).Json!.Value.GetProperty("protocol").GetString() == "saml", "Client Admin v2 upsert creation and SAML subtype creation both persist");
        foreach (string id in new[] { "v2-json-client", "v2-upsert-client", "v2-saml-client" }) await client.DeleteAsync(id, adminToken, ct);
        check((await client.ListAsync(adminToken, [new("q", "clientId sw \"v2-\"")], ct)).Json!.Value.GetArrayLength() == 0, "Client Admin v2 deletion removes every declarative test client");
    }
}
