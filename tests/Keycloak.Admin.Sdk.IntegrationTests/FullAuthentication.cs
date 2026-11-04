using System.Text.Json.Nodes;
using static LiveContext;

internal static class FullAuthentication
{
    public static async Task RunAsync(LiveContext c)
    {
        foreach (var provider in new[] { ("authenticator-providers", "auth-cookie"), ("client-authenticator-providers", "client-secret"), ("form-providers", "registration-page-form"), ("form-action-providers", "registration-user-creation") })
        {
            var read = await c.Get("authentication/" + provider.Item1);
            c.Prove(Has(read.J, "id", provider.Item2), "Discovery contains installed executable authentication provider: " + provider.Item2, read);
        }
        var description = await c.Get("authentication/config-description/{providerId}", null, ("providerId", "identity-provider-redirector"));
        c.Prove(description.J?["properties"] is JsonArray props && props.Any(n => S(n, "name") == "defaultProvider"), "Provider configuration description exposes supported defaultProvider option", description);
        var perClient = await c.Get("authentication/per-client-config-description");
        c.Prove(perClient.J?["client-secret"] is JsonArray, "Per-client authentication settings describe installed client-secret authenticator", perClient);
        var flow = await c.Post("authentication/flows", O("""{"alias":"full-auth-flow","providerId":"basic-flow","topLevel":true,"builtIn":false,"description":"created"}"""));
        string flowId = flow.Id;
        var flowGet = await c.Get("authentication/flows/{id}", null, ("id", flowId));
        c.Prove(S(flowGet.J, "alias") == "full-auth-flow", "Authentication flow creation persists alias and generated ID", flow, flowGet);
        var flowBody = flowGet.J!.DeepClone(); flowBody["description"] = "flow updated";
        var update = await c.Put("authentication/flows/{id}", flowBody, ("id", flowId));
        flowGet = await c.Get("authentication/flows/{id}", null, ("id", flowId));
        var flows = await c.Get("authentication/flows");
        c.Prove(S(flowGet.J, "description") == "flow updated" && Has(flows.J, "id", flowId), "Authentication flow update persists and appears in realm flow list", update, flowGet, flows);
        var e1 = await c.Post("authentication/flows/{flowAlias}/executions/execution", O("""{"provider":"auth-cookie"}"""), null, ("flowAlias", "full-auth-flow"));
        var e2 = await c.Post("authentication/executions", new JsonObject { ["parentFlow"] = flowId, ["authenticator"] = "identity-provider-redirector", ["authenticatorFlow"] = false, ["requirement"] = "ALTERNATIVE" });
        string executionId = e2.Id;
        var list = await c.Get("authentication/flows/{flowAlias}/executions", null, ("flowAlias", "full-auth-flow"));
        var execution = await c.Get("authentication/executions/{executionId}", null, ("executionId", executionId));
        c.Prove(Has(list.J, "providerId", "auth-cookie") && Has(list.J, "id", executionId) && S(execution.J, "parentFlow") == flowId && S(execution.J, "authenticator") == "identity-provider-redirector", "Both execution creation endpoints persist provider and parent flow", e1, e2, list, execution);
        var executionBody = list.J!.AsArray().Single(n => S(n, "id") == executionId)!.DeepClone(); executionBody["requirement"] = "DISABLED";
        var require = await c.Put("authentication/flows/{flowAlias}/executions", executionBody, ("flowAlias", "full-auth-flow"));
        list = await c.Get("authentication/flows/{flowAlias}/executions", null, ("flowAlias", "full-auth-flow"));
        c.Prove(list.J!.AsArray().Any(n => S(n, "id") == executionId && S(n, "requirement") == "DISABLED"), "Execution requirement update persists in flow graph", require, list);
        var raise = await c.Post("authentication/executions/{executionId}/raise-priority", null, null, ("executionId", executionId));
        list = await c.Get("authentication/flows/{flowAlias}/executions", null, ("flowAlias", "full-auth-flow"));
        c.Prove(S(list.J?[0], "id") == executionId, "Raise execution priority changes persisted ordering", raise, list);
        var lower = await c.Post("authentication/executions/{executionId}/lower-priority", null, null, ("executionId", executionId));
        list = await c.Get("authentication/flows/{flowAlias}/executions", null, ("flowAlias", "full-auth-flow"));
        c.Prove(S(list.J?[1], "id") == executionId, "Lower execution priority changes persisted ordering", lower, list);
        var subflow = await c.Post("authentication/flows/{flowAlias}/executions/flow", O("""{"alias":"full-subflow","type":"basic-flow","description":"nested"}"""), null, ("flowAlias", "full-auth-flow"));
        list = await c.Get("authentication/flows/{flowAlias}/executions", null, ("flowAlias", "full-auth-flow"));
        c.Prove(Has(list.J, "displayName", "full-subflow"), "Nested flow endpoint creates flow and linking execution", subflow, list);
        var copy = await c.Post("authentication/flows/{flowAlias}/copy", O("""{"newName":"full-auth-copy"}"""), null, ("flowAlias", "full-auth-flow"));
        var copied = await c.Get("authentication/flows/{flowAlias}/executions", null, ("flowAlias", "full-auth-copy"));
        c.Prove(copied.J is JsonArray ca && ca.Count == list.J!.AsArray().Count && Has(ca, "providerId", "auth-cookie"), "Flow copy duplicates the complete execution graph", copy, copied);
        var config = await c.Post("authentication/config", O("""{"alias":"full-unattached","config":{"defaultProvider":"before"}}"""));
        string configId = config.Id;
        var configGet = await c.Get("authentication/config/{id}", null, ("id", configId));
        c.Prove(S(configGet.J?["config"], "defaultProvider") == "before", "Standalone authenticator config persists settings", config, configGet);
        var edit = await c.Put("authentication/config/{id}", O("""{"alias":"full-unattached","config":{"defaultProvider":"after"}}"""), ("id", configId));
        configGet = await c.Get("authentication/config/{id}", null, ("id", configId));
        c.Prove(S(configGet.J?["config"], "defaultProvider") == "after", "Authenticator configuration update persists changed value", edit, configGet);
        var attached = await c.Post("authentication/executions/{executionId}/config", O("""{"alias":"full-attached","config":{"defaultProvider":"full-idp"}}"""), null, ("executionId", executionId));
        string attachedId = attached.Id;
        var attachedGet = await c.Get("authentication/executions/{executionId}/config/{id}", null, ("executionId", executionId), ("id", attachedId));
        execution = await c.Get("authentication/executions/{executionId}", null, ("executionId", executionId));
        c.Prove(S(attachedGet.J?["config"], "defaultProvider") == "full-idp" && S(execution.J, "authenticatorConfig") == attachedId, "Execution configuration creates stored settings and a real execution link", attached, attachedGet, execution);
        var deleteConfig = await c.Delete("authentication/config/{id}", ("id", configId));
        c.Prove(await c.Missing("authentication/config/{id}", ("id", configId)), "Authenticator configuration deletion removes stored object", deleteConfig);
        var deleteExecution = await c.Delete("authentication/executions/{executionId}", ("executionId", executionId));
        list = await c.Get("authentication/flows/{flowAlias}/executions", null, ("flowAlias", "full-auth-flow"));
        c.Prove(!Has(list.J, "id", executionId), "Execution deletion removes graph node", deleteExecution, list);

        var required = await c.Get("authentication/required-actions");
        c.Prove(Has(required.J, "alias", "UPDATE_PASSWORD") && Has(required.J, "alias", "CONFIGURE_TOTP"), "Required-action registry contains installed password/TOTP actions", required);
        var action = await c.Get("authentication/required-actions/{alias}", null, ("alias", "UPDATE_PASSWORD"));
        var actionBody = action.J!.DeepClone(); actionBody["name"] = "Full password action";
        var actionUpdate = await c.Put("authentication/required-actions/{alias}", actionBody, ("alias", "UPDATE_PASSWORD"));
        action = await c.Get("authentication/required-actions/{alias}", null, ("alias", "UPDATE_PASSWORD"));
        c.Prove(S(action.J, "name") == "Full password action", "Required-action update changes persisted display name", actionUpdate, action);
        int before = action.J!["priority"]!.GetValue<int>();
        var actionLower = await c.Post("authentication/required-actions/{alias}/lower-priority", null, null, ("alias", "UPDATE_PASSWORD"));
        action = await c.Get("authentication/required-actions/{alias}", null, ("alias", "UPDATE_PASSWORD"));
        c.Prove(action.J!["priority"]!.GetValue<int>() > before, "Required-action lower-priority changes ordering", actionLower, action);
        var actionRaise = await c.Post("authentication/required-actions/{alias}/raise-priority", null, null, ("alias", "UPDATE_PASSWORD"));
        action = await c.Get("authentication/required-actions/{alias}", null, ("alias", "UPDATE_PASSWORD"));
        c.Prove(action.J!["priority"]!.GetValue<int>() == before, "Required-action raise-priority restores ordering", actionRaise, action);
        var configDescription = await c.Get("authentication/required-actions/{alias}/config-description", null, ("alias", "UPDATE_PASSWORD"));
        c.Prove(configDescription.J?["properties"] is JsonArray { Count: > 0 }, "Required-action configuration description exposes configurable properties", configDescription);
        var actionConfig = await c.Get("authentication/required-actions/{alias}/config", null, ("alias", "UPDATE_PASSWORD"));
        var ac = actionConfig.J!.DeepClone(); ac["config"] ??= new JsonObject(); ac["config"]!["max_auth_age"] = "120";
        var actionConfigUpdate = await c.Put("authentication/required-actions/{alias}/config", ac, ("alias", "UPDATE_PASSWORD"));
        actionConfig = await c.Get("authentication/required-actions/{alias}/config", null, ("alias", "UPDATE_PASSWORD"));
        c.Prove(S(actionConfig.J?["config"], "max_auth_age") == "120", "Required-action configuration is persisted", actionConfigUpdate, actionConfig);
        var removeConfig = await c.Delete("authentication/required-actions/{alias}/config", ("alias", "UPDATE_PASSWORD"));
        actionConfig = await c.Get("authentication/required-actions/{alias}/config", null, ("alias", "UPDATE_PASSWORD"));
        c.Prove(S(actionConfig.J?["config"], "max_auth_age") != "120", "Deleting required-action config removes custom value and recreates defaults", removeConfig, actionConfig);
        var removeAction = await c.Delete("authentication/required-actions/{alias}", ("alias", "CONFIGURE_TOTP"));
        var unregistered = await c.Get("authentication/unregistered-required-actions");
        c.Prove(Has(unregistered.J, "providerId", "CONFIGURE_TOTP"), "Unregistered actions expose removed installed provider", removeAction, unregistered);
        var register = await c.Post("authentication/register-required-action", O("""{"providerId":"CONFIGURE_TOTP","name":"Full TOTP action"}"""));
        required = await c.Get("authentication/required-actions");
        c.Prove(Has(required.J, "alias", "CONFIGURE_TOTP"), "Required-action registration persists provider alias", register, required);
        var removeFlow = await c.Delete("authentication/flows/{id}", ("id", flowId));
        c.Prove(await c.Missing("authentication/flows/{id}", ("id", flowId)), "Authentication flow deletion removes its graph", removeFlow);
        Console.WriteLine("PASS full authentication: installed provider discovery, flow graph CRUD/copy/order, execution/config links and required-action configuration.");
    }
}
