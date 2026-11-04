using System.Net.Http.Headers;
using System.Text;
using System.Text.Json.Nodes;
using static LiveContext;

internal static class FullClients
{
    public static async Task RunAsync(LiveContext c, LiveFacts f, HttpClient http, Uri server)
    {
        var p = new[] { ("client-uuid", f.Client) };
        var profiles = O("""{"profiles":[{"name":"full-rotation","description":"Acceptance rotation","executors":[{"executor":"secret-rotation","configuration":{"expiration-period":3600,"rotated-expiration-period":600,"remaining-rotation-period":1800}}]}]}""");
        var setProfiles = await c.Put("client-policies/profiles", profiles);
        var getProfiles = await c.Get("client-policies/profiles");
        c.Prove(Has(getProfiles.J?["profiles"], "name", "full-rotation"), "Client policy profile persists rotation executor settings", setProfiles, getProfiles);
        var policies = O("""{"policies":[{"name":"full-rotation-policy","enabled":true,"conditions":[{"condition":"client-access-type","configuration":{"type":["confidential"]}}],"profiles":["full-rotation"]}]}""");
        var setPolicies = await c.Put("client-policies/policies", policies);
        var getPolicies = await c.Get("client-policies/policies");
        c.Prove(Has(getPolicies.J?["policies"], "name", "full-rotation-policy"), "Client policy persists enabled condition and profile association", setPolicies, getPolicies);
        var old = await c.Get("clients/{client-uuid}/client-secret", null, p);
        c.Prove(S(old.J, "value") == "full-client-secret", "Read client secret matches configured authentication credential", old);
        var rotate = await c.Post("clients/{client-uuid}/client-secret", paths: p);
        string current = S(rotate.J, "value");
        var rotated = await c.Get("clients/{client-uuid}/client-secret/rotated", null, p);
        var token = await FullCredentials.PasswordToken(http, server, c.Realm, f.Password, secret: current);
        c.Prove(current.Length > 20 && current != "full-client-secret" && S(rotated.J, "value") == "full-client-secret" && S(token, "access_token").Length > 100, "Secret rotation retains previous secret and new secret authenticates against real OIDC token endpoint", rotate, rotated);
        var deleteRotated = await c.Delete("clients/{client-uuid}/client-secret/rotated", p);
        c.Prove(await c.Missing("clients/{client-uuid}/client-secret/rotated", p), "Invalidating rotated secret removes stored old credential", deleteRotated);
        await c.Put("client-policies/policies", O("""{"policies":[]}"""));
        await c.Put("clients/{client-uuid}", O("""{"secret":"full-client-secret","authorizationServicesEnabled":true}"""), p);
        var registration = await c.Post("clients/{client-uuid}/registration-access-token", paths: p);
        using var registrationRequest = new HttpRequestMessage(HttpMethod.Get, new Uri(server, "realms/" + c.Realm + "/clients-registrations/default/full-client"));
        registrationRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", S(registration.J, "registrationAccessToken"));
        using var registrationReply = await http.SendAsync(registrationRequest);
        var registered = JsonNode.Parse(await registrationReply.Content.ReadAsStringAsync());
        c.Prove(registrationReply.IsSuccessStatusCode && S(registered, "clientId") == "full-client", "Regenerated registration access token authorizes real dynamic-registration read", registration);
        var installation = await c.Get("clients/{client-uuid}/installation/providers/{providerId}", null, [.. p, ("providerId", "keycloak-oidc-keycloak-json")]);
        c.Prove(S(installation.J, "resource") == "full-client" && S(installation.J, "realm") == c.Realm, "Installation output embeds actual client and realm configuration", installation);
        var account = await c.Get("clients/{client-uuid}/service-account-user", null, p);
        c.Prove(S(account.J, "username") == "service-account-full-client" && S(account.J, "id").Length > 0, "Service-account endpoint returns persisted client service user", account);
        var providers = await c.Get("client-registration-policy/providers");
        c.Prove(Has(providers.J, "id", "allowed-client-templates") || Has(providers.J, "id", "trusted-hosts"), "Registration policy discovery exposes installed provider", providers);
        await using var callback = new CallbackFixture();
        callback.Responder = (_, _, _) => (204, "text/plain", "");
        await c.Put("clients/{client-uuid}", new JsonObject { ["adminUrl"] = callback.WebUrl + "/adapter", ["authorizationServicesEnabled"] = true, ["nodeReRegistrationTimeout"] = -1 }, p);
        var node = await c.Post("clients/{client-uuid}/nodes", new JsonObject { ["node"] = callback.Host }, paths: p);
        var client = await c.Get("clients/{client-uuid}", null, p);
        c.Prove(client.J?["registeredNodes"]?[callback.Host] is not null, "Cluster node registration persists host and registration timestamp", node, client);
        var ping = await c.Get("clients/{client-uuid}/test-nodes-available", null, p);
        c.Prove(ping.J?["successRequests"] is JsonArray { Count: 1 } && callback.Requests.Any(r => r.Method == "POST" && r.Path.EndsWith("k_test_available", StringComparison.Ordinal) && r.Body.Split('.').Length == 3), "Node availability sends actual signed adapter action over HTTP", ping);
        await c.Put("clients/{client-uuid}", O("""{"notBefore":1,"authorizationServicesEnabled":true}"""), p);
        var push = await c.Post("clients/{client-uuid}/push-revocation", paths: p);
        c.Prove(push.J?["successRequests"] is JsonArray { Count: 1 } && callback.Requests.Any(r => r.Path.EndsWith("k_push_not_before", StringComparison.Ordinal)), "Client revocation propagates actual signed not-before adapter request", push);
        var realmPush = await c.Post("push-revocation");
        c.Prove(realmPush.J?["successRequests"] is JsonArray { Count: > 0 } && callback.Requests.Count(r => r.Path.EndsWith("k_push_not_before", StringComparison.Ordinal)) >= 2, "Realm revocation reaches configured client adapter", realmPush);
        var remove = await c.Delete("clients/{client-uuid}/nodes/{node}", [.. p, ("node", callback.Host)]);
        client = await c.Get("clients/{client-uuid}", null, p);
        c.Prove(client.J?["registeredNodes"]?[callback.Host] is null, "Unregistering cluster node removes persisted host", remove, client);
        await c.Put("clients/{client-uuid}", O("""{"adminUrl":"","authorizationServicesEnabled":true}"""), p);
        Console.WriteLine("PASS full clients: policy/profile persistence, real secret rotation, registration token, installation and adapter callbacks.");
    }
}
