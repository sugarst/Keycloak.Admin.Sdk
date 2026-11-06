using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Capabilities;

internal static class FullCapabilities
{
    public static async Task VerifyAsync(HttpClient http, Uri server, IAccessTokenProvider tokens, KeycloakAdminRoute route, ReadOnlyMemory<byte> info, CancellationToken cancellationToken = default)
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
        var disabled = Client(new(KeycloakTarget.Version, route, disabledCapabilities: ["KeycloakSdk.AdminApi"]));
        await Denied(KeycloakCapabilityReason.DisabledByHost, async () => await disabled.Users.GetUsersAsync("master", cancellationToken: cancellationToken));
        await Denied(KeycloakCapabilityReason.DisabledByHost, async () => await disabled.OpenStreamAsync(HttpMethod.Get, "/admin/realms/master/users", cancellationToken: cancellationToken));
        var normal = Client(new(KeycloakTarget.Version, route));
        await Denied(KeycloakCapabilityReason.UnknownEndpoint, async () => await normal.SendAsync(HttpMethod.Get, "/admin/unknown/vendor", cancellationToken: cancellationToken));
        await Denied(KeycloakCapabilityReason.StageNotAllowed, async () => await normal.SendAsync(HttpMethod.Get, "/admin/realms/master/client-types", cancellationToken: cancellationToken));
        var optIn = Client(new(KeycloakTarget.Version, route, allowPreview: true, allowExperimental: true));
        await Denied(KeycloakCapabilityReason.NotSupported, async () => await optIn.SendAsync(HttpMethod.Get, "/admin/realms/master/users/fixture/vc/credentials", cancellationToken: cancellationToken));
        await Denied(KeycloakCapabilityReason.NotSupported, async () => await optIn.SendAsync(HttpMethod.Get, "/admin/realms/master/ssf/config", cancellationToken: cancellationToken));
        var unknownVersion = Client(new("unsupported-release", route));
        await Denied(KeycloakCapabilityReason.UnknownVersion, async () => await unknownVersion.Users.GetUsersAsync("master", cancellationToken: cancellationToken));
        if (RecordingHandler.SentCount != before) throw new InvalidOperationException("Rejected requests reached the real HTTP transport.");
        Console.WriteLine("PASS live capability guards: host disable, raw/stream paths, unknown version/endpoint and unverified preview/experimental opt-in send zero HTTP requests.");
    }
}
