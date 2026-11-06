using System.Text.Json.Nodes;
using static LiveContext;

internal static class FullCredentials
{
    public static async Task RunAsync(LiveContext c, LiveFacts f, HttpClient http, Uri server)
    {
        var p = new[] { ("user-id", f.User) };
        var profile = await c.Get("users/profile");
        var config = profile.J!.DeepClone(); config["unmanagedAttributePolicy"] = "ADMIN_EDIT";
        var updateProfile = await c.Put("users/profile", config);
        profile = await c.Get("users/profile");
        var metadata = await c.Get("users/profile/metadata");
        c.Prove(S(profile.J, "unmanagedAttributePolicy") == "ADMIN_EDIT" && Has(metadata.J?["attributes"], "name", "username"), "User-profile configuration persists and metadata describes required username", updateProfile, profile, metadata);
        await c.Put("users/{user-id}", O("""{"firstName":"Updated","lastName":"Acceptance","email":"full-user@example.invalid","emailVerified":true,"requiredActions":[],"attributes":{"full-unmanaged":["actual-value"]}}"""), p);
        var attributes = await c.Get("users/{user-id}/unmanagedAttributes", null, p);
        c.Prove(attributes.J?["full-unmanaged"]?[0]?.GetValue<string>() == "actual-value", "Unmanaged attributes expose actual persisted admin attribute", attributes);
        var types = await c.Get("users/{user-id}/configured-user-storage-credential-types", null, p);
        var credentials = await c.Get("users/{user-id}/credentials", null, p);
        c.Prove(types.J is JsonArray { Count: 0 } && Has(credentials.J, "type", "password"), "Local user has stored password and no federated credential provider", types, credentials);
        string passwordId = S(credentials.J!.AsArray().Single(n => S(n, "type") == "password"), "id");
        var label = await c.Call("PUT", "users/{user-id}/credentials/{credentialId}/userLabel", raw: new StringContent("Acceptance password", System.Text.Encoding.UTF8, "text/plain"), paths: [.. p, ("credentialId", passwordId)]);
        credentials = await c.Get("users/{user-id}/credentials", null, p);
        c.Prove(Has(credentials.J, "userLabel", "Acceptance password"), "Credential user label is persisted", label, credentials);
        const string changed = "Changed-acceptance-Password-987!";
        var reset = await c.Put("users/{user-id}/reset-password", new JsonObject { ["type"] = "password", ["value"] = changed, ["temporary"] = false }, p);
        var token = await PasswordToken(http, server, c.Realm, changed, c.Cancellation);
        c.Prove(S(token, "access_token").Length > 100, "Password reset allows real OIDC authentication with new password", reset);
        await c.Put("users/{user-id}/reset-password", new JsonObject { ["type"] = "password", ["value"] = f.Password, ["temporary"] = false }, p);
        // Two real OTP credentials make ordering assertions meaningful (password alone cannot).
        JsonObject otp(string labelText) => new() { ["type"] = "otp", ["userLabel"] = labelText,
            ["secretData"] = "{\"value\":\"JBSWY3DPEHPK3PXP\"}",
            ["credentialData"] = "{\"subType\":\"totp\",\"digits\":6,\"counter\":0,\"period\":30,\"algorithm\":\"HmacSHA1\"}" };
        var temporary = await c.Post("users", new JsonObject { ["username"] = "full-credential-order", ["enabled"] = true, ["credentials"] = new JsonArray(otp("first"), otp("second")) });
        var tp = new[] { ("user-id", temporary.Id) };
        var ordered = await c.Get("users/{user-id}/credentials", null, tp);
        string first = S(ordered.J![0], "id"), second = S(ordered.J[1], "id");
        var move = await c.Post("users/{user-id}/credentials/{credentialId}/moveToFirst", paths: [.. tp, ("credentialId", second)]);
        ordered = await c.Get("users/{user-id}/credentials", null, tp);
        c.Prove(S(ordered.J![0], "id") == second && S(ordered.J[1], "id") == first, "Move-to-first changes order of two stored OTP credentials", move, ordered);
        move = await c.Post("users/{user-id}/credentials/{credentialId}/moveAfter/{newPreviousCredentialId}", paths: [.. tp, ("credentialId", second), ("newPreviousCredentialId", first)]);
        ordered = await c.Get("users/{user-id}/credentials", null, tp);
        c.Prove(S(ordered.J![0], "id") == first && S(ordered.J[1], "id") == second, "Move-after restores persisted OTP order", move, ordered);
        var remove = await c.Delete("users/{user-id}/credentials/{credentialId}", [.. tp, ("credentialId", first)]);
        ordered = await c.Get("users/{user-id}/credentials", null, tp);
        c.Prove(!Has(ordered.J, "id", first) && Has(ordered.J, "id", second), "Credential deletion removes selected credential only", remove, ordered);
        var disable = await c.Put("users/{user-id}/disable-credential-types", new JsonArray("otp"), tp);
        ordered = await c.Get("users/{user-id}/credentials", null, tp);
        c.Prove(ordered.J is JsonArray { Count: 1 } && Has(ordered.J, "id", second), "disable-credential-types delegates to storage updaters; released local OTP provider preserves local OTP (UserCredentialManager.disableCredentialType)", disable, ordered);
        var deleted = await c.Delete("users/{user-id}", tp);
        c.Prove(await c.Missing("users/{user-id}", tp), "Deleting temporary user removes persisted user", deleted);
        Console.WriteLine("PASS full credentials: profile policy, unmanaged attributes, real password login, credential labels/order/delete and local disable delegation.");
    }
    internal static async Task<JsonNode> PasswordToken(HttpClient http, Uri server, string realm, string password, CancellationToken cancellationToken, string scope = "openid", string secret = "full-client-secret")
    {
        using var form = new FormUrlEncodedContent(new Dictionary<string, string> { ["grant_type"] = "password", ["client_id"] = "full-client", ["client_secret"] = secret, ["username"] = "full-user", ["password"] = password, ["scope"] = scope });
        using var reply = await http.PostAsync(new Uri(server, "realms/" + realm + "/protocol/openid-connect/token"), form, cancellationToken: cancellationToken);
        string body = await reply.Content.ReadAsStringAsync(cancellationToken: cancellationToken);
        if (!reply.IsSuccessStatusCode) throw new InvalidOperationException("Real password grant failed: " + body);
        return JsonNode.Parse(body)!;
    }
}
