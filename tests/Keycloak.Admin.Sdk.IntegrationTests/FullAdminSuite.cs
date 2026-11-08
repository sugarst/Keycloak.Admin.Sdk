using System.Net;
using System.Text.Json;
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Capabilities;
using Keycloak.Admin.Sdk.Platform;
using static LiveContext;

internal static class FullAdminSuite
{
    public static async Task RunAsync(HttpClient http, Uri server, CancellationToken cancellationToken = default)
    {
        using var tokens = new LivePasswordTokens(http, server);
        var declared = KeycloakRoute.Load(Directory.GetCurrentDirectory());
        bool bootstrap = Environment.GetEnvironmentVariable("KC_TEST_RELEASE_BOOTSTRAP") == "1";
        KeycloakAdminClient sdk;
        var (options, flags) = FullPlatformGate.Create(declared.FgapVersion == 1
            ? KeycloakAdminRoute.FgapV1Compatibility : KeycloakAdminRoute.FgapV2Stable);
        KeycloakPlatformHost? platform = null;
        if (!bootstrap) platform = await KeycloakPlatformHost.CreateAsync(http, server, tokens, options, cancellationToken);
        sdk = bootstrap ? new(http, server, tokens) : platform!.Admin;
        if (!bootstrap) await FullPlatformGate.VerifyAsync(platform!, flags, cancellationToken);
        var ledger = new LiveLedger();
        string realm = "sdk-full-" + Guid.NewGuid().ToString("N");
        var c = new LiveContext(sdk, realm, ledger, cancellationToken);
        c.Evidence("supportPolicy", System.Text.Json.Nodes.JsonValue.Create(bootstrap ? "bootstrap-wire" : "catalog-conjunctive-v1"));
        c.Evidence("platformGate", System.Text.Json.Nodes.JsonValue.Create(bootstrap ? "not-loaded-bootstrap" : "snapshot-v1"));
        c.Evidence("platformGateBusinessGuards", System.Text.Json.Nodes.JsonValue.Create(!bootstrap));
        var serverInfo = await sdk.ServerInfoAdmin.GetInfoAsync(cancellationToken);
        if (!bootstrap) await FullCapabilities.VerifyAsync(http, server, tokens, declared.FgapVersion == 1 ? KeycloakAdminRoute.FgapV1Compatibility : KeycloakAdminRoute.FgapV2Stable, serverInfo.Content, cancellationToken);
        c.Evidence("supportPolicyLocalGuards", System.Text.Json.Nodes.JsonValue.Create(!bootstrap));
        using (var actual = JsonDocument.Parse(serverInfo.Content))
        {
            c.Route.ValidateServer(actual.RootElement);
            c.Evidence("serverVersion", System.Text.Json.Nodes.JsonValue.Create(actual.RootElement.GetProperty("systemInfo").GetProperty("version").GetString()));
            c.Evidence("features", System.Text.Json.Nodes.JsonNode.Parse(actual.RootElement.GetProperty("features").GetRawText()));
        }
        c.Evidence("realm", System.Text.Json.Nodes.JsonValue.Create(realm));
        Console.WriteLine("Acceptance route: " + c.Route.Id + "; no preview or experimental features enabled.");
        bool createAttempted = false, completed = false;
        try
        {
            createAttempted = true;
            var create = await c.Post("/admin/realms", new System.Text.Json.Nodes.JsonObject
            {
                ["realm"] = realm, ["enabled"] = true, ["organizationsEnabled"] = true,
                ["eventsEnabled"] = true, ["adminEventsEnabled"] = true, ["adminEventsDetailsEnabled"] = true
            });
            var get = await c.Get("");
            c.RealmId = S(get.J, "id");
            c.Prove(S(get.J, "realm") == realm, "Created realm is persisted and readable by its unique name", create, get);
            var facts = await FullCore.RunAsync(c);
            await FullRoles.RunAsync(c, facts);
            await FullAuthentication.RunAsync(c);
            await FullMappers.RunAsync(c, facts);
            await FullIdentity.RunAsync(c, facts, server);
            await FullWorkflows.RunAsync(c, facts, http);
            await FullAuthorization.RunAsync(c, facts);
            await FullCredentials.RunAsync(c, facts, http, server);
            await FullCertificates.RunAsync(c, facts);
            await FullUi.RunAsync(c, facts);
            await FullClients.RunAsync(c, facts, http, server);
            await FullMail.RunAsync(c, facts);
            await FullSessions.RunAsync(c, facts, http, server);
            await FullStorage.RunAsync(c);
            await FullImport.RunAsync(c, facts);
            await FullFgap.RunAsync(c, facts, http, server);
            await FullCaches.RunAsync(c, facts, http, server);
            // Further modules share actual resource IDs, never generated mock fixtures.
            completed = true;
        }
        finally
        {
            try
            {
                if (createAttempted)
                {
                    using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(30));
                    var cleanupContext = c.WithCancellation(cleanup.Token);
                    try
                    {
                        var deleted = await cleanupContext.Delete("");
                        c.Prove(await cleanupContext.Missing(""), "Deleting the isolated realm removes its persisted state", deleted);
                    }
                    catch (InvalidOperationException error) when (error.InnerException is KeycloakAdminException { StatusCode: HttpStatusCode.NotFound }) { }
                }
            }
            finally
            {
                using var evidence = new CancellationTokenSource(TimeSpan.FromSeconds(30));
                await ledger.Write(completed, evidence.Token);
            }
        }
    }
}
internal sealed class LivePasswordTokens(HttpClient http, Uri server) : IAccessTokenProvider, IDisposable
{
    private readonly SemaphoreSlim gate = new(1, 1);
    private string? cached;
    private DateTimeOffset expires;
    public async ValueTask<string> GetAccessTokenAsync(CancellationToken cancellationToken = default)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            if (cached is not null && DateTimeOffset.UtcNow < expires) return cached;
            using var body = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "password", ["client_id"] = "admin-cli",
                ["username"] = Environment.GetEnvironmentVariable("KC_TEST_USERNAME") ?? "admin",
                ["password"] = Environment.GetEnvironmentVariable("KC_TEST_PASSWORD")!
            });
            using var response = await http.PostAsync(new Uri(server, "realms/master/protocol/openid-connect/token"), body, cancellationToken);
            response.EnsureSuccessStatusCode();
            var token = JsonSerializer.Deserialize(await response.Content.ReadAsStringAsync(cancellationToken), KeycloakJsonContext.Default.TokenResponse)!;
            cached = token.AccessToken!; expires = DateTimeOffset.UtcNow.AddSeconds(Math.Max(1, token.ExpiresIn - 30));
            return cached;
        }
        finally { gate.Release(); }
    }
    public void Dispose() => gate.Dispose();
}
internal sealed record LiveFacts(string Client, string User, string Group, string Scope, string Password);
