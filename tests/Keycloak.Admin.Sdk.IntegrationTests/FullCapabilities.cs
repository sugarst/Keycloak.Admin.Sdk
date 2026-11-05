using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Capabilities;

internal static class FullCapabilities
{
    public static async Task VerifyAsync(HttpClient http, Uri server, IAccessTokenProvider tokens, KeycloakAdminRoute route, ReadOnlyMemory<byte> info)
    {
        var snapshot = KeycloakServerCapabilities.FromServerInfo(info);
        KeycloakAdminClient Client(KeycloakSupportConfiguration config) => new(http, server, tokens, new() { RequestPolicy = new KeycloakCapabilityPolicy(server, config, snapshot) });
        int before = RecordingHandler.SentCount;
        async Task Denied(KeycloakCapabilityReason reason, Func<Task> call)
        {
            try { await call(); }
            catch (KeycloakCapabilityDeniedException error) when (error.Decision.Reason == reason) { return; }
            throw new InvalidOperationException("Real-client support guard did not reject locally: " + reason);
        }
        var disabled = Client(new("26.8.1", route, disabledCapabilities: ["KeycloakSdk.AdminApi"]));
        await Denied(KeycloakCapabilityReason.DisabledByHost, async () => await disabled.Users.GetUsersAsync("master"));
        await Denied(KeycloakCapabilityReason.DisabledByHost, async () => await disabled.OpenStreamAsync(HttpMethod.Get, "/admin/realms/master/users"));
        var normal = Client(new("26.8.1", route));
        await Denied(KeycloakCapabilityReason.UnknownEndpoint, async () => await normal.SendAsync(HttpMethod.Get, "/admin/unknown/vendor"));
        await Denied(KeycloakCapabilityReason.StageNotAllowed, async () => await normal.SendAsync(HttpMethod.Get, "/admin/realms/master/client-types"));
        var optIn = Client(new("26.8.1", route, allowPreview: true, allowExperimental: true));
        await Denied(KeycloakCapabilityReason.NotSupported, async () => await optIn.SendAsync(HttpMethod.Get, "/admin/realms/master/users/fixture/vc/credentials"));
        await Denied(KeycloakCapabilityReason.NotSupported, async () => await optIn.SendAsync(HttpMethod.Get, "/admin/realms/master/ssf/config"));
        var unknownVersion = Client(new("26.8.2", route));
        await Denied(KeycloakCapabilityReason.UnknownVersion, async () => await unknownVersion.Users.GetUsersAsync("master"));
        if (RecordingHandler.SentCount != before) throw new InvalidOperationException("Rejected requests reached the real HTTP transport.");
        Console.WriteLine("PASS live capability guards: host disable, raw/stream paths, unknown version/endpoint and unverified preview/experimental opt-in send zero HTTP requests.");
    }
}
