using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Protocols;

internal static class ProtocolAuthZenWorkflows
{
    internal static async Task RunAsync(KeycloakAdminClient admin, ProtocolTransport transport, string realm, string secret, string ordinaryUserToken,
        Action<bool, string> check, CancellationToken ct)
    {
        await admin.Clients.CreateClientAsync(realm, new ClientRepresentation { ClientId = "authzen-app", Protocol = "openid-connect", PublicClient = false,
            Enabled = true, Secret = secret, ServiceAccountsEnabled = true, AuthorizationServicesEnabled = true }, cancellationToken: ct);
        var app = (await admin.Clients.GetClientsAsync(realm, clientId: "authzen-app", cancellationToken: ct)).Body!.Single();
        var user = (await admin.Users.GetUsersAsync(realm, username: "account-user", exact: true, cancellationToken: ct)).Body!.Single();
        string prefix = "/admin/realms/" + realm + "/clients/" + app.Id + "/authz/resource-server";
        async Task<JsonNode> Post(string suffix, JsonNode body)
        {
            var result = await admin.SendAsync(HttpMethod.Post, prefix + suffix, content: new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json"), cancellationToken: ct);
            return JsonNode.Parse(result.Content.Span)!;
        }
        var scope = await Post("/scope", new JsonObject { ["name"] = "read" });
        var resource = await Post("/resource", new JsonObject { ["name"] = "document", ["type"] = "urn:sdk:document",
            ["scopes"] = new JsonArray(new JsonObject { ["name"] = "read" }) });
        var policy = await Post("/policy/user", new JsonObject { ["name"] = "account-user-only", ["logic"] = "POSITIVE", ["users"] = new JsonArray(user.Id) });
        await Post("/permission/scope", new JsonObject { ["name"] = "document-read", ["resources"] = new JsonArray(resource["_id"]!.GetValue<string>()),
            ["scopes"] = new JsonArray(scope["id"]!.GetValue<string>()), ["policies"] = new JsonArray(policy["id"]!.GetValue<string>()) });
        var auth = OAuthClientAuthentication.SecretBasic("authzen-app", _ => ValueTask.FromResult(secret));
        string token = (await new OidcClient(transport).ClientCredentialsAsync(auth, cancellationToken: ct)).Json!.Value.GetProperty("access_token").GetString()!;
        var client = new AuthZenClient(transport);
        var discovery = (await client.DiscoverAsync(ct)).Json!.Value;
        check(discovery.GetProperty("policy_decision_point").GetString() == transport.Issuer.AbsoluteUri
            && discovery.GetProperty("access_evaluation_endpoint").GetString() == transport.Issuer.AbsoluteUri + "/authzen/access/v1/evaluation"
            && discovery.GetProperty("access_evaluations_endpoint").GetString() == transport.Issuer.AbsoluteUri + "/authzen/access/v1/evaluations", "AuthZen discovery pins PDP single and batch endpoints to the realm");
        var request = new JsonObject { ["subject"] = new JsonObject { ["type"] = "user", ["id"] = "username:account-user" },
            ["resource"] = new JsonObject { ["type"] = "urn:sdk:document", ["id"] = "document" }, ["action"] = new JsonObject { ["name"] = "read" } };
        JsonElement Element(JsonNode value) { using var doc = JsonDocument.Parse(value.ToJsonString()); return doc.RootElement.Clone(); }
        check(await client.EvaluateAsync(Element(request), token, ct), "AuthZen permits the persisted user resource and scope policy");
        var missing = request.DeepClone(); missing["resource"]!["id"] = "missing";
        check(!await client.EvaluateAsync(Element(missing), token, ct), "AuthZen returns decision false for an unknown resource");
        var batch = request.DeepClone(); batch["evaluations"] = new JsonArray(new JsonObject(), new JsonObject { ["resource"] = missing["resource"]!.DeepClone() }, new JsonObject());
        var decisions = (await client.EvaluateBatchAsync(Element(batch), token, ct)).Json!.Value.GetProperty("evaluations");
        check(decisions.GetArrayLength() == 3 && decisions[0].GetProperty("decision").GetBoolean() && !decisions[1].GetProperty("decision").GetBoolean()
            && decisions[2].GetProperty("decision").GetBoolean(), "AuthZen execute_all merges defaults and preserves mixed permit and deny decisions");
        batch["options"] = new JsonObject { ["evaluations_semantic"] = "deny_on_first_deny" };
        var denied = (await client.EvaluateBatchAsync(Element(batch), token, ct)).Json!.Value.GetProperty("evaluations");
        batch["options"] = new JsonObject { ["evaluations_semantic"] = "permit_on_first_permit" };
        var permitted = (await client.EvaluateBatchAsync(Element(batch), token, ct)).Json!.Value.GetProperty("evaluations");
        var fallback = (await client.EvaluateBatchAsync(Element(request), token, ct)).Json!.Value;
        check(denied.GetArrayLength() == 2 && !denied[1].GetProperty("decision").GetBoolean() && permitted.GetArrayLength() == 1
            && permitted[0].GetProperty("decision").GetBoolean() && fallback.GetProperty("decision").GetBoolean(), "AuthZen short-circuit and empty-batch semantics match the pinned server");
        bool unauthorized = false;
        try { await client.EvaluateAsync(Element(request), ordinaryUserToken, ct); }
        catch (KeycloakProtocolException e) when (e.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden) { unauthorized = true; }
        check(unauthorized, "AuthZen rejects ordinary user tokens as PDP callers");
        await admin.SendAsync(HttpMethod.Delete, prefix + "/policy/" + policy["id"]!.GetValue<string>(), cancellationToken: ct);
        check(!await client.EvaluateAsync(Element(request), token, ct), "AuthZen policy revocation changes the real decision from permit to deny");
    }
}
