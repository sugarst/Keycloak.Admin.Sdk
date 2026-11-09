using System.Net.Http.Headers;
using System.Text.Json.Nodes;
using static LiveContext;

internal static class FullWorkflows
{
    public static async Task RunAsync(LiveContext c, LiveFacts f, HttpClient http)
    {
        var previous = http.DefaultRequestHeaders.Accept.ToArray();
        http.DefaultRequestHeaders.Accept.Clear(); http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        try
        {
            var empty = await c.Get("workflows/scheduled/{resource-id}", null, ("resource-id", f.User));
            var create = await c.Post("workflows", O("""{"name":"full-workflow","enabled":true,"steps":[{"uses":"disable-user","after":"1d"},{"uses":"delete-user","after":"2d"}]}"""));
            string id = create.Id;
            // Keycloak enqueues activation/migration after transaction completion; HTTP success precedes persistence.
            // Poll only the read endpoint, never replay either write operation.
            async Task<LiveReply> WaitForScheduleAsync(Func<JsonNode, bool> ready)
            {
                for (int attempt = 0; attempt < 100; attempt++)
                {
                    var reply = await c.Get("workflows/scheduled/{resource-id}", null, ("resource-id", f.User));
                    var workflow = reply.J!.AsArray().SingleOrDefault(w => S(w, "id") == id);
                    if (workflow is not null && ready(workflow)) return reply;
                    await Task.Delay(100, c.Cancellation);
                }
                throw new InvalidOperationException("Workflow task did not persist its expected schedule within the bounded wait.");
            }
            var read = await c.Get("workflows/{id}", null, ("id", id));
            var list = await c.Get("workflows", O("""{"search":"full-workflow","exact":true}"""));
            c.Prove(empty.J is JsonArray { Count: 0 } && S(read.J, "name") == "full-workflow" && read.J?["steps"] is JsonArray { Count: 2 } && Has(list.J, "id", id), "Workflow creation persists two real steps and is found in exact list", create, read, list, empty);
            string first = S(read.J!["steps"]![0], "id"), second = S(read.J["steps"]![1], "id");
            var body = read.J.DeepClone(); body["name"] = "full-workflow-updated";
            var update = await c.Put("workflows/{id}", body, ("id", id)); read = await c.Get("workflows/{id}", null, ("id", id));
            // Updating a definition rebuilds its step components; use the current persisted IDs.
            first = S(read.J!["steps"]![0], "id"); second = S(read.J["steps"]![1], "id");
            c.Prove(S(read.J, "name") == "full-workflow-updated", "Workflow update changes persisted definition", update, read);
            var withoutIds = await c.Get("workflows/{id}", O("""{"includeId":false}"""), ("id", id));
            c.Prove(withoutIds.J?["id"] is null && withoutIds.J?["steps"] is JsonArray sa && sa.All(s => s?["id"] is null), "Workflow representation excludes workflow/step IDs when requested", withoutIds);
            var activate = await c.Post("workflows/{id}/activate/{type}/{resourceId}", null, O("""{"notBefore":"86400"}"""), ("id", id), ("type", "USERS"), ("resourceId", f.User));
            var scheduled = await WaitForScheduleAsync(w => S(w["steps"]?[0], "status") == "PENDING");
            var state = scheduled.J!.AsArray().Single(w => S(w, "id") == id)!;
            c.Prove(S(state["steps"]?[0], "status") == "PENDING" && state["steps"]?[0]?["scheduled-at"]?.GetValue<long>() > DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), "Activation creates a persisted future schedule for the actual user", activate, scheduled);
            var migrate = await c.Post("workflows/migrate", null, new JsonObject { ["from"] = first, ["to"] = second });
            scheduled = await WaitForScheduleAsync(w => S(w["steps"]?[0], "status") == "COMPLETED" && S(w["steps"]?[1], "status") == "PENDING");
            state = scheduled.J!.AsArray().Single(w => S(w, "id") == id)!;
            c.Prove(S(state["steps"]?[0], "status") == "COMPLETED" && S(state["steps"]?[1], "status") == "PENDING", "Migration changes the resource's persisted scheduled step", migrate, scheduled);
            var deactivate = await c.Post("workflows/{id}/deactivate/{type}/{resourceId}", null, null, ("id", id), ("type", "USERS"), ("resourceId", f.User));
            scheduled = await c.Get("workflows/scheduled/{resource-id}", null, ("resource-id", f.User));
            c.Prove(!Has(scheduled.J, "id", id), "Deactivation removes the user schedule", deactivate, scheduled);
            var delete = await c.Delete("workflows/{id}", ("id", id));
            c.Prove(await c.Missing("workflows/{id}", ("id", id)), "Workflow deletion removes persisted definition", delete);
            Console.WriteLine("PASS full workflows (current target stable feature): definitions, activation, step migration and schedule removal.");
        }
        finally { http.DefaultRequestHeaders.Accept.Clear(); foreach (var accept in previous) http.DefaultRequestHeaders.Accept.Add(accept); }
    }
}
