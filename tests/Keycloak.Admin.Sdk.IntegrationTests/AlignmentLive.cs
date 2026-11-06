using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using Keycloak.Admin.Sdk;

internal static class AlignmentLive
{
    public static async Task RunAsync(KeycloakAdminClient sdk, string realm, string client, string user, string scope, string policy, CancellationToken cancellationToken = default)
    {
        await using var fixture = new CallbackFixture(cancellationToken);
        var secondPolicy = await sdk.Policy.CreatePOSTAdminRealmsRealmClientsClientUuidAuthzResourceServerPolicyAsync(realm, client,
            new PolicyRepresentation { Name = "sdk-user-policy-second", Type = "user", Logic = "POSITIVE", DecisionStrategy = "UNANIMOUS", Config = new() { ["users"] = "[\"" + user + "\"]" } }, cancellationToken: cancellationToken);
        Check(secondPolicy.Body?.Id is not null, "Second user policy created");
        var page = await sdk.Policy.FindByIdGETAdminRealmsRealmClientsClientUuidAuthzResourceServerPolicyTypeAsync(realm, client, "user", fields: "*", first: 0, max: 1, cancellationToken: cancellationToken);
        Check(page.Body.GetArrayLength() == 1, "Policy provider pagination is applied");
        var selected = await sdk.Policy.FindByIdGETAdminRealmsRealmClientsClientUuidAuthzResourceServerPolicyTypeAsync(realm, client, "user", fields: "*", policyId: policy, name: "sdk-user-policy", typeQuery: "user", permission: false, first: 0, max: 10, cancellationToken: cancellationToken);
        Check(selected.Body.GetArrayLength() == 1 && selected.Body[0].GetProperty("id").GetString() == policy, "Policy provider ID/name filters are applied");
        var policyEntity = await sdk.Policy.FindByIdGETAdminRealmsRealmClientsClientUuidAuthzResourceServerPolicyTypeAsync(realm, client, policy, cancellationToken: cancellationToken);
        Check(policyEntity.Body.ValueKind == JsonValueKind.Object, "Policy ID dispatch still returns an entity");

        var permission = await sdk.Policy.CreateAsync(realm, client,
            new PolicyRepresentation { Name = "sdk-scope-permission", Type = "scope", Scopes = [scope], Policies = [policy], Logic = "POSITIVE", DecisionStrategy = "UNANIMOUS" }, cancellationToken: cancellationToken);
        await sdk.Policy.CreateAsync(realm, client,
            new PolicyRepresentation { Name = "sdk-scope-permission-second", Type = "scope", Scopes = [scope], Policies = [policy], Logic = "POSITIVE", DecisionStrategy = "UNANIMOUS" }, cancellationToken: cancellationToken);
        var permissionsPage = await sdk.Policy.FindByIdAsync(realm, client, "scope", fields: "*", first: 0, max: 1, cancellationToken: cancellationToken);
        Check(permissionsPage.Body.GetArrayLength() == 1, "Permission provider pagination is applied");
        var permissions = await sdk.Policy.FindByIdAsync(realm, client, "scope", fields: "*", policyId: permission.Body!.Id, name: "sdk-scope-permission", typeQuery: "scope", scope: scope, permission: true, first: 0, max: 10, cancellationToken: cancellationToken);
        Check(permissions.Body.GetArrayLength() == 1 && permissions.Body[0].GetProperty("id").GetString() == permission.Body.Id, "Permission provider filters are applied");
        var permissionEntity = await sdk.Policy.FindByIdAsync(realm, client, permission.Body.Id!, cancellationToken: cancellationToken);
        Check(permissionEntity.Body.ValueKind == JsonValueKind.Object, "Permission ID dispatch still returns an entity");

        var idpUpload = new MultipartFormDataContent();
        idpUpload.Add(new StringContent("saml"), "providerId");
        idpUpload.Add(new StringContent(CallbackFixture.Metadata, Encoding.UTF8, "application/xml"), "file", "metadata.xml");
        var uploaded = await sdk.IdentityProviders.ImportFromAsync(realm, idpUpload, cancellationToken: cancellationToken);
        Check(uploaded.Body!.Values.Contains("https://idp.example.invalid/sso"), "IDP uploaded metadata was parsed by Keycloak");
        using var idpJson = JsonDocument.Parse("{\"providerId\":\"saml\",\"fromUrl\":\"" + fixture.MetadataUrl + "\"}");
        var fetched = await sdk.IdentityProviders.ImportFromAsync(realm, Json(idpJson.RootElement), cancellationToken: cancellationToken);
        Check(fetched.Body!.Values.Contains("https://idp.example.invalid/sso") && fixture.MetadataRequests == 1, "IDP JSON URL import made a real metadata callback");

        await sdk.RealmLocalization.CreateOrUpdateRealmLocalizationTextsFromFileAsync(realm, "zh-CN", new StringContent("{\"json-key\":\"JSON 值\"}", Encoding.UTF8, "application/json"), cancellationToken: cancellationToken);
        var localizationFile = new MultipartFormDataContent();
        localizationFile.Add(new StringContent("{\"file-key\":\"文件值\"}", Encoding.UTF8, "application/json"), "file", "zh-CN.json");
        await sdk.RealmLocalization.CreateOrUpdateRealmLocalizationTextsFromFileAsync(realm, "zh-CN", localizationFile, cancellationToken: cancellationToken);
        var messages = (await sdk.RealmLocalization.GetRealmLocalizationTextsAsync(realm, "zh-CN", cancellationToken: cancellationToken)).Body!;
        Check(messages["json-key"] == "JSON 值" && messages["file-key"] == "文件值", "Both JSON and multipart localization persist UTF-8 values");

        var admin = (await sdk.Users.GetUsersAsync("master", username: Environment.GetEnvironmentVariable("KC_TEST_USERNAME") ?? "admin", exact: true, cancellationToken: cancellationToken)).Body!.Single();
        var smtp = new Dictionary<string, string>
        {
            ["host"] = fixture.Host, ["port"] = fixture.SmtpPort.ToString(CultureInfo.InvariantCulture), ["from"] = "test@example.invalid",
            ["auth"] = "false", ["ssl"] = "false", ["starttls"] = "false"
        };
        string smtpJson = JsonSerializer.Serialize(smtp, (JsonTypeInfo<Dictionary<string, string>>)KeycloakJsonContext.Default.GetTypeInfo(typeof(Dictionary<string, string>))!);
        try
        {
            await sdk.User.UpdateUserAsync("master", admin.Id!, new UserRepresentation { Email = "admin@example.invalid" }, cancellationToken: cancellationToken);
            await sdk.RealmAdmin.TestSMTPConnectionAsync(realm, new StringContent(smtpJson, Encoding.UTF8, "application/json"), cancellationToken: cancellationToken);
            await sdk.RealmAdmin.TestSMTPConnectionAsync(realm, new FormUrlEncodedContent(new Dictionary<string, string> { ["config"] = smtpJson }), cancellationToken: cancellationToken);
            Check(fixture.MailCount == 2, "SMTP JSON and legacy form both delivered a real message");
        }
        finally
        {
            // UserResource.updateUser merges missing/null attributes with existing values.
            // An explicit empty email clears it; null would retain the fixture email.
            await sdk.User.UpdateUserAsync("master", admin.Id!, new UserRepresentation { Email = admin.Email ?? "", EmailVerified = admin.EmailVerified }, cancellationToken: cancellationToken);
            var restored = (await sdk.User.GetUserAsync("master", admin.Id!, cancellationToken: cancellationToken)).Body!;
            Check(admin.Email is null ? string.IsNullOrEmpty(restored.Email) : restored.Email == admin.Email, "Bootstrap email restored after SMTP fixture");
        }

        var empty = await sdk.Workflows.GetScheduledWorkflowsAsync(realm, user, cancellationToken: cancellationToken);
        Check(empty.Body is { Count: 0 }, "Scheduled workflow empty list");
        var definition = new WorkflowRepresentation
        {
            Name = "sdk-delayed-workflow", Enabled = true,
            Steps = [new WorkflowStepRepresentation { Uses = "disable-user", After = "1d" }]
        };
        var workflow = await sdk.Workflows.CreateAsync(realm, new StringContent(JsonSerializer.Serialize(definition, KeycloakJsonContext.Default.WorkflowRepresentation), Encoding.UTF8, "application/json"), cancellationToken: cancellationToken);
        string workflowId = Uri.UnescapeDataString(workflow.Location!.OriginalString.TrimEnd('/').Split('/').Last());
        try
        {
            await sdk.Workflow.ActivateAsync(realm, workflowId, "USERS", user, notBefore: "86400", cancellationToken: cancellationToken);
            var scheduled = await sdk.Workflows.GetScheduledWorkflowsAsync(realm, user, cancellationToken: cancellationToken);
            Check(scheduled.Body is { Count: > 0 } && scheduled.Body.Any(w => w.Id == workflowId && w.Name == "sdk-delayed-workflow" && w.Steps is { Count: > 0 }), "Scheduled workflow nonempty list is deserialized with steps");
            await sdk.Workflow.DeactivateAsync(realm, workflowId, "USERS", user, cancellationToken: cancellationToken);
        }
        finally { await sdk.Workflow.DeleteAsync(realm, workflowId, cancellationToken: cancellationToken); }
        Directory.CreateDirectory("artifacts");
        string mode = System.Runtime.CompilerServices.RuntimeFeature.IsDynamicCodeSupported ? "managed" : "native-aot";
        await File.WriteAllLinesAsync("artifacts/six-contracts-live-" + mode + ".txt", new[]
        {
            "mode=" + mode,
            "PASS workflow scheduled arrays: empty and nonempty",
            "PASS policy provider filters/paging and ID dispatch", "PASS permission provider filters/paging and ID dispatch",
            "PASS identity-provider metadata import: multipart upload and JSON URL fetch",
            "PASS localization import: JSON and multipart UTF-8 persistence", "PASS SMTP test: JSON and form delivered two messages"
        }, cancellationToken: cancellationToken);
        Console.WriteLine("PASS: all six repaired paths verified against real Keycloak, including file parsing, persisted localization, SMTP delivery and scheduled workflows.");
    }

    private static HttpContent Json(JsonElement value) => new StringContent(value.GetRawText(), Encoding.UTF8, "application/json");
    private static void Check(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
}
