using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;
using Keycloak.Admin.Sdk;
using static LiveContext;

internal static class FullMail
{
    public static async Task RunAsync(LiveContext c, LiveFacts f)
    {
        await using var callback = new CallbackFixture();
        var smtp = new JsonObject { ["host"] = callback.Host, ["port"] = callback.SmtpPort.ToString(CultureInfo.InvariantCulture), ["from"] = "acceptance@example.invalid", ["auth"] = "false", ["ssl"] = "false", ["starttls"] = "false" };
        await c.Put("", new JsonObject { ["smtpServer"] = smtp.DeepClone() });
        var admin = (await c.Sdk.Users.GetUsersAsync("master", username: Environment.GetEnvironmentVariable("KC_TEST_USERNAME") ?? "admin", exact: true)).Body!.Single();
        try
        {
            await c.Sdk.User.UpdateUserAsync("master", admin.Id!, new UserRepresentation { Email = "full-admin@example.invalid" });
            var test = await c.Call("POST", "testSMTPConnection", raw: new StringContent(LiveJson.String(smtp), Encoding.UTF8, "application/json"));
            var legacy = await c.Call("POST", "testSMTPConnection", raw: new FormUrlEncodedContent(new Dictionary<string, string> { ["config"] = LiveJson.String(smtp) }));
            c.Prove(callback.MailCount == 2 && callback.Messages.All(m => m.Contains("full-admin@example.invalid", StringComparison.Ordinal)), "JSON and form SMTP tests deliver actual messages to authenticated admin", test, legacy);
        }
        finally
        {
            await c.Sdk.User.UpdateUserAsync("master", admin.Id!, new UserRepresentation { Email = admin.Email ?? "", EmailVerified = admin.EmailVerified });
            var restored = (await c.Sdk.User.GetUserAsync("master", admin.Id!)).Body!;
            c.Prove(string.Equals(restored.Email ?? "", admin.Email ?? "", StringComparison.Ordinal), "SMTP fixture restores bootstrap admin email");
        }
        foreach (var (path, body) in new (string, JsonNode?)[] { ("execute-actions-email", new JsonArray("UPDATE_PASSWORD")), ("reset-password-email", null), ("send-verify-email", null) })
        {
            int count = callback.MailCount;
            var sent = await c.Call("PUT", "users/{user-id}/" + path, body, paths: [("user-id", f.User)]);
            string message = callback.Messages.Last();
            c.Prove(callback.MailCount == count + 1 && message.Contains("full-user@example.invalid", StringComparison.Ordinal) && (message.Contains("action-token", StringComparison.Ordinal) || message.Contains("login-actions", StringComparison.Ordinal)), "User " + path + " delivers action-link email to actual persisted user's address", sent);
        }
        var org = await c.Post("organizations", O("""{"name":"full-invitations","alias":"full-invitations","enabled":true}"""));
        var op = new[] { ("org-id", org.Id) };
        int initial = callback.MailCount;
        var invite = await c.Call("POST", "organizations/{org-id}/members/invite-user", raw: new FormUrlEncodedContent(new Dictionary<string, string> { ["email"] = "new-invite@example.invalid", ["firstName"] = "Invited", ["lastName"] = "New" }), paths: op);
        var invitations = await c.Get("organizations/{org-id}/invitations", O("""{"email":"new-invite@example.invalid","status":"PENDING"}"""), op);
        string id = S(invitations.J!.AsArray().Single(), "id");
        var ip = op.Append(("id", id)).ToArray();
        var get = await c.Get("organizations/{org-id}/invitations/{id}", null, ip);
        c.Prove(callback.MailCount == initial + 1 && S(get.J, "email") == "new-invite@example.invalid" && S(get.J, "status") == "PENDING" && S(get.J, "organizationId") == org.Id && get.J?["expiresAt"]?.GetValue<long>() > get.J?["sentDate"]?.GetValue<long>(), "New-user invitation sends email and persists pending invitation with organization/expiry", invite, invitations, get);
        var resend = await c.Post("organizations/{org-id}/invitations/{id}/resend", paths: ip);
        invitations = await c.Get("organizations/{org-id}/invitations", O("""{"email":"new-invite@example.invalid"}"""), op);
        string replaced = S(invitations.J!.AsArray().Single(), "id");
        c.Prove(callback.MailCount == initial + 2 && replaced != id && await c.Missing("organizations/{org-id}/invitations/{id}", ip), "Resending sends a second actual email and replaces invitation ID as released source specifies", resend, invitations);
        var remove = await c.Delete("organizations/{org-id}/invitations/{id}", [.. op, ("id", replaced)]);
        c.Prove(await c.Missing("organizations/{org-id}/invitations/{id}", [.. op, ("id", replaced)]), "Deleting invitation removes pending invitation record", remove);
        var existing = await c.Call("POST", "organizations/{org-id}/members/invite-existing-user", raw: new FormUrlEncodedContent(new Dictionary<string, string> { ["id"] = f.User }), paths: op);
        invitations = await c.Get("organizations/{org-id}/invitations", O("""{"email":"full-user@example.invalid"}"""), op);
        c.Prove(callback.MailCount == initial + 3 && Has(invitations.J, "email", "full-user@example.invalid") && callback.Messages.Last().Contains("full-user@example.invalid", StringComparison.Ordinal), "Existing-user invitation sends actual user email and persists pending membership invitation", existing, invitations);
        await c.Delete("organizations/{org-id}", op);
        var localization = new MultipartFormDataContent(); localization.Add(new StringContent("{\"full-file-key\":\"文件真实值\"}", Encoding.UTF8, "application/json"), "file", "zh-CN.json");
        var imported = await c.Call("POST", "localization/{locale}", raw: localization, paths: [("locale", "zh-CN")]);
        var text = await c.Get("localization/{locale}", null, ("locale", "zh-CN"));
        c.Prove(S(text.J, "full-file-key") == "文件真实值", "Multipart localization import persists UTF8 message", imported, text);
        Console.WriteLine("PASS full mail/invitations: actual SMTP delivery, action links, persisted invitation lifecycle and multipart localization.");
    }
}
