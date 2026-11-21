using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Protocols;

internal static class UpgradeRegressions
{
    private const string MapperAllowlist = "allowedProtocolMapperTypesForClientAdministrators";
    private const string UserAttributeMapper = "oidc-usermodel-attribute-mapper";
    private const string HardcodedClaimMapper = "oidc-hardcoded-claim-mapper";
    private const string Marker = "sdk-regression-marker";

    internal static async Task RunAsync(KeycloakAdminClient admin, HttpClient http, Uri server, CancellationToken ct)
    {
        string realm = "sdk-upgrade-" + Guid.NewGuid().ToString("N");
        using var definition = new StringContent(JsonSerializer.Serialize(new RealmRepresentation
        {
            Realm = realm, Enabled = true, AdminPermissionsEnabled = true
        }, KeycloakJsonContext.Default.RealmRepresentation), Encoding.UTF8, "application/json");
        await admin.RealmsAdmin.ImportRealmAsync(definition, cancellationToken: ct);
        try
        {
            string realmManagement = await FindClientAsync(admin, realm, "realm-management", ct);
            string scopeId = (await admin.ClientScopes.GetClientScopesAsync(realm, ct)).Body!.Single(s => s.Name == "kc-admin-api").Id!;
            string clientManagerSecret = NewPassword();
            await CreateServiceAccountAsync(admin, realm, realmManagement, scopeId, "client-manager",
                clientManagerSecret, "manage-clients", ct);
            using var managerTokens = new ClientCredentialsTokenProvider(http, server, realm, "client-manager",
                _ => ValueTask.FromResult(clientManagerSecret));
            var manager = new KeycloakAdminClient(http, server, managerTokens);
            var transport = new ProtocolTransport(http, server, realm);

            await VerifyMappersAsync(admin, manager, realm, ct);
            await VerifyRegistrationAsync(admin, transport, realm, ct);

            string statsSecret = NewPassword();
            string statsUser = await CreateServiceAccountAsync(admin, realm, realmManagement, scopeId, "stats-reader",
                statsSecret, "view-realm", ct);
            using var statsTokens = new ClientCredentialsTokenProvider(http, server, realm, "stats-reader",
                _ => ValueTask.FromResult(statsSecret));
            await VerifyFgapAsync(admin, manager, new KeycloakAdminClient(http, server, statsTokens), transport, realm, statsUser, ct);
        }
        finally
        {
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            await admin.RealmAdmin.DeleteRealmAsync(realm, cleanup.Token);
        }
    }

    private static async Task VerifyMappersAsync(KeycloakAdminClient admin, KeycloakAdminClient manager, string realm, CancellationToken ct)
    {
        var client = await admin.Clients.CreateClientAsync(realm, new()
        {
            ClientId = "mapper-client", Protocol = "openid-connect", Enabled = true
        }, ct);
        var scope = await admin.ClientScopes.CreateClientScopeAsync(realm, new()
        {
            Name = "mapper-client-scope", Protocol = "openid-connect"
        }, ct);
        string clientId = CreatedId(client), scopeId = CreatedId(scope);
        var mapper = AttributeMapper();
        await ExpectForbiddenAsync("Protocol Mapper: delegated client create without allowlist",
            () => manager.ProtocolMappers.CreateMapperPOSTAdminRealmsRealmClientsClientUuidProtocolMappersModelsAsync(realm, clientId, mapper, ct));
        await ExpectForbiddenAsync("Protocol Mapper: delegated client-scope batch create without allowlist",
            () => manager.ProtocolMappers.CreateMapperAsync(realm, scopeId, [mapper], ct));

        await admin.ProtocolMappers.CreateMapperPOSTAdminRealmsRealmClientsClientUuidProtocolMappersModelsAsync(realm, clientId, mapper, ct);
        // The mapper subresource returns effective settings. The client representation exposes the stored settings.
        var effective = (await admin.ProtocolMappers.GetMappersGETAdminRealmsRealmClientsClientUuidProtocolMappersModelsAsync(realm, clientId, ct)).Body!;
        await ExpectForbiddenAsync("Protocol Mapper: writing effective mapper settings through the client representation",
            () => manager.Client.UpdateAsync(realm, clientId, new() { ProtocolMappers = effective }, ct));
        var stored = (await admin.Client.GetClientAsync(realm, clientId, ct)).Body!.ProtocolMappers!;
        string? markerId = stored.Single(m => m.Name == Marker).Id;
        await manager.Client.UpdateAsync(realm, clientId, new() { Name = "unchanged mapper round-trip", ProtocolMappers = stored }, ct);
        await ExpectForbiddenAsync("Protocol Mapper: delegated removal through the full client representation",
            () => manager.Client.UpdateAsync(realm, clientId, new() { Name = "forbidden change", ProtocolMappers = [] }, ct));
        var unchanged = (await admin.Client.GetClientAsync(realm, clientId, ct)).Body!;
        Check(unchanged.Name == "unchanged mapper round-trip" && unchanged.ProtocolMappers!.Single(m => m.Name == Marker).Id == markerId,
            "Protocol Mapper: admin create persisted, unchanged delegated round-trip succeeded, denied write had no effect");

        var realmAttributes = (await admin.RealmAdmin.GetRealmAsync(realm, ct)).Body!.Attributes ?? [];
        realmAttributes[MapperAllowlist] = UserAttributeMapper + "," + HardcodedClaimMapper;
        await admin.RealmAdmin.UpdateRealmAsync(realm, new() { Attributes = realmAttributes }, ct);
        var allowed = await manager.ProtocolMappers.CreateMapperPOSTAdminRealmsRealmClientScopesClientScopeIdProtocolMappersModelsAsync(realm, scopeId, mapper, ct);
        string mapperId = CreatedId(allowed);
        mapper.Config!["claim.name"] = Marker + "-updated";
        await manager.ProtocolMappers.UpdateAsync(realm, scopeId, mapperId, mapper, ct);
        Check((await admin.ProtocolMappers.GetMapperByIdAsync(realm, scopeId, mapperId, ct)).Body!.Config!["claim.name"] == mapper.Config["claim.name"],
            "Protocol Mapper: allowlisted delegated creation and update persisted");
        await manager.ProtocolMappers.DeleteAsync(realm, scopeId, mapperId, ct);
        Check((await admin.ProtocolMappers.GetMappersAsync(realm, scopeId, ct)).Body!.Count == 0,
            "Protocol Mapper: allowlisted delegated deletion persisted");
    }

    private static async Task VerifyRegistrationAsync(KeycloakAdminClient admin, ProtocolTransport transport, string realm, CancellationToken ct)
    {
        var registration = RealmResourceClient.DefaultClientRegistration(transport);
        var oidc = RealmResourceClient.ClientRegistration(transport);

        async Task<string> InitialTokenAsync()
        {
            var response = await admin.ClientInitialAccess.CreateAsync(realm, new() { Count = 1, Expiration = 120 }, ct);
            using var payload = JsonDocument.Parse(response.Content);
            return payload.RootElement.GetProperty("token").GetString()!;
        }

        async Task<ProtocolResponse> RegisterDefaultAsync(ClientRepresentation client)
            => await registration.CreateAsync(JsonSerializer.SerializeToElement(client, KeycloakJsonContext.Default.ClientRepresentation),
                await InitialTokenAsync(), ct);

        var mapperInRealmOnly = new ProtocolMapperRepresentation
        {
            Name = Marker, Protocol = "openid-connect", ProtocolMapper = HardcodedClaimMapper,
            Config = new() { ["claim.name"] = Marker, ["claim.value"] = "test", ["jsonType.label"] = "String", ["access.token.claim"] = "true" }
        };
        await ExpectForbiddenAsync("DCR: mapper present only in the realm allowlist",
            () => RegisterDefaultAsync(new() { ClientId = "dcr-realm-only", Protocol = "openid-connect", ProtocolMappers = [mapperInRealmOnly] }));

        const string clientName = "dcr-allowed";
        var created = await RegisterDefaultAsync(new()
        {
            ClientId = clientName, Protocol = "openid-connect", FullScopeAllowed = true, ProtocolMappers = [AttributeMapper()]
        });
        string registrationToken = created.Json!.Value.GetProperty("registrationAccessToken").GetString()!;
        string registeredId = await FindClientAsync(admin, realm, clientName, ct);
        var registered = (await admin.Client.GetClientAsync(realm, registeredId, ct)).Body!;
        Check(created.StatusCode == HttpStatusCode.Created && registered.FullScopeAllowed == false
            && registered.ProtocolMappers!.Any(m => m.Name == Marker),
            "DCR: mapper in both allowlists registered with fullScopeAllowed forced off");

        await ExpectForbiddenAsync("DCR: re-enabling fullScopeAllowed",
            () => registration.ReplaceAsync(clientName,
                JsonSerializer.SerializeToElement(new ClientRepresentation { ClientId = clientName, FullScopeAllowed = true },
                    KeycloakJsonContext.Default.ClientRepresentation), registrationToken, ct));
        Check((await admin.Client.GetClientAsync(realm, registeredId, ct)).Body!.FullScopeAllowed == false,
            "DCR: rejected update left fullScopeAllowed disabled");

        const string defaultRole = "dcr-test-role";
        await admin.RoleContainer.CreateRolePOSTAdminRealmsRealmRolesAsync(realm, new() { Name = defaultRole }, ct);
        await ExpectForbiddenAsync("DCR: setting defaultRoles at registration",
            () => RegisterDefaultAsync(new() { ClientId = "dcr-default-role", Protocol = "openid-connect", DefaultRoles = [defaultRole] }));
        string compositeName = (await admin.RealmAdmin.GetRealmAsync(realm, ct)).Body!.DefaultRole!.Name!;
        var defaultRoles = (await admin.RoleContainer.GetRoleCompositesGETAdminRealmsRealmRolesRoleNameCompositesAsync(realm, compositeName, ct)).Body!;
        Check(defaultRoles.All(r => r.Name != defaultRole), "DCR: rejection left the realm default-role composite intact");

        const string offlineRevoke = "backchannel_logout_revoke_offline_tokens";
        var createdOidc = (await oidc.CreateAsync(Element(new JsonObject
        {
            ["client_name"] = "DCR logout options", ["redirect_uris"] = new JsonArray("https://app.invalid/callback"),
            ["backchannel_logout_uri"] = "https://app.invalid/backchannel", [offlineRevoke] = true
        }), await InitialTokenAsync(), ct)).Json!.Value;
        string oidcId = createdOidc.GetProperty("client_id").GetString()!;
        string oidcToken = createdOidc.GetProperty("registration_access_token").GetString()!;
        var read = (await oidc.GetAsync(oidcId, oidcToken, ct)).Json!.Value;
        if (read.TryGetProperty("registration_access_token", out var rotated)) oidcToken = rotated.GetString()!;
        var edit = JsonNode.Parse(read.GetRawText())!.AsObject();
        edit["client_name"] = "DCR logout options updated";
        var updated = (await oidc.ReplaceAsync(oidcId, Element(edit), oidcToken, ct)).Json!.Value;
        if (updated.TryGetProperty("registration_access_token", out rotated)) oidcToken = rotated.GetString()!;
        var persisted = (await oidc.GetAsync(oidcId, oidcToken, ct)).Json!.Value;
        Check(read.GetProperty(offlineRevoke).GetBoolean() && persisted.GetProperty(offlineRevoke).GetBoolean()
            && persisted.GetProperty("client_name").GetString() == "DCR logout options updated",
            "OIDC DCR: read-modify-write preserved offline token revocation on backchannel logout");
    }

    private static async Task VerifyFgapAsync(KeycloakAdminClient admin, KeycloakAdminClient manager, KeycloakAdminClient statsReader,
        ProtocolTransport transport, string realm, string statsUser, CancellationToken ct)
    {
        string permissions = await FindClientAsync(admin, realm, "admin-permissions", ct);
        await ExpectForbiddenAsync("FGAP v2: delegated update of admin-permissions",
            () => manager.Client.UpdateAsync(realm, permissions, new() { Name = "forbidden change" }, ct));
        await ExpectForbiddenAsync("FGAP v2: delegated delete of admin-permissions",
            () => manager.Client.DeleteClientAsync(realm, permissions, ct));
        Check((await admin.Client.GetClientAsync(realm, permissions, ct)).Body!.ClientId == "admin-permissions",
            "FGAP v2: internal permission client survived the rejected requests");

        const string visible = "stats-visible", hidden = "stats-hidden", username = "stats-user";
        string password = NewPassword();
        await admin.Users.CreateUserAsync(realm, new()
        {
            Username = username, FirstName = "Stats", LastName = "Fixture", Email = "stats@example.invalid",
            Enabled = true, EmailVerified = true, Credentials = [new() { Type = "password", Value = password, Temporary = false }]
        }, ct);
        var oidc = new OidcClient(transport);
        foreach (string client in new[] { visible, hidden })
        {
            await admin.Clients.CreateClientAsync(realm, new()
            {
                ClientId = client, Protocol = "openid-connect", Enabled = true, PublicClient = true, DirectAccessGrantsEnabled = true
            }, ct);
            await oidc.PasswordGrantAsync(OAuthClientAuthentication.Public(client), username, password, cancellationToken: ct);
        }
        var control = (await admin.RealmAdmin.GetClientSessionStatsAsync(realm, ct)).Body!;
        Check(control.Any(s => s["clientId"] == visible && s["active"] == "1") &&
            control.Any(s => s["clientId"] == hidden && s["active"] == "1"), "FGAP v2: admin sees both active session fixtures");
        var before = (await statsReader.RealmAdmin.GetClientSessionStatsAsync(realm, ct)).Body!;
        Check(before.Count == 0, "FGAP v2: view-realm alone receives an empty 200 result");

        string visibleId = await FindClientAsync(admin, realm, visible, ct);
        string hiddenId = await FindClientAsync(admin, realm, hidden, ct);
        using var policy = JsonContent(new JsonObject { ["name"] = "stats-reader-policy", ["users"] = new JsonArray(statsUser) });
        var createdPolicy = await admin.Policy.CreatePOSTAdminRealmsRealmClientsClientUuidAuthzResourceServerPolicyTypeAsync(realm, permissions, "user", policy, ct);
        string policyId = createdPolicy.Body.GetProperty("id").GetString()!;
        foreach (var (clientId, scope) in new[] { (visibleId, "view"), (hiddenId, "manage") })
        {
            using var permission = JsonContent(new JsonObject
            {
                ["name"] = "stats-reader-" + scope, ["resourceType"] = "Clients", ["resources"] = new JsonArray(clientId),
                ["scopes"] = new JsonArray(scope), ["policies"] = new JsonArray(policyId)
            });
            await admin.Policy.CreatePOSTAdminRealmsRealmClientsClientUuidAuthzResourceServerPermissionTypeAsync(realm, permissions, "scope", permission, ct);
        }
        await statsReader.Client.UpdateAsync(realm, hiddenId, new() { Name = "managed without view" }, ct);
        var filtered = await statsReader.RealmAdmin.GetClientSessionStatsAsync(realm, ct);
        Check(filtered.StatusCode == HttpStatusCode.OK && filtered.Body is [var row] && row["clientId"] == visible && row["active"] == "1",
            "FGAP v2: 200 statistics include the view client and exclude the manage-only client");
    }

    private static async Task<string> CreateServiceAccountAsync(KeycloakAdminClient admin, string realm, string realmManagement, string scopeId,
        string clientName, string secret, string role, CancellationToken ct)
    {
        var created = await admin.Clients.CreateClientAsync(realm, new()
        {
            ClientId = clientName, Protocol = "openid-connect", Enabled = true, PublicClient = false,
            ServiceAccountsEnabled = true, FullScopeAllowed = true, Secret = secret
        }, ct);
        string client = CreatedId(created);
        await admin.Client.AddDefaultClientScopeAsync(realm, client, scopeId, ct);
        string user = (await admin.Client.GetServiceAccountUserAsync(realm, client, ct)).Body!.Id!;
        var mapping = (await admin.RoleContainer.GetRoleAsync(realm, realmManagement, role, ct)).Body!;
        await admin.ClientRoleMappings.AddClientRoleMappingPOSTAdminRealmsRealmUsersUserIdRoleMappingsClientsClientIdAsync(realm, user, realmManagement, [mapping], ct);
        return user;
    }

    private static ProtocolMapperRepresentation AttributeMapper() => new()
    {
        Name = Marker, Protocol = "openid-connect", ProtocolMapper = UserAttributeMapper,
        Config = new() { ["user.attribute"] = Marker, ["claim.name"] = Marker, ["jsonType.label"] = "String", ["access.token.claim"] = "true" }
    };
    private static async Task<string> FindClientAsync(KeycloakAdminClient admin, string realm, string name, CancellationToken ct)
        => (await admin.Clients.GetClientsAsync(realm, clientId: name, cancellationToken: ct)).Body!.Single(c => c.ClientId == name).Id!;
    private static string CreatedId(AdminResponse response) => Uri.UnescapeDataString(response.Location!.OriginalString.TrimEnd('/').Split('/').Last());
    private static string NewPassword() => Guid.NewGuid().ToString("N") + "aA1!";
    private static StringContent JsonContent(JsonObject body) => new(body.ToJsonString(), Encoding.UTF8, "application/json");
    private static JsonElement Element(JsonObject body)
    {
        using var parsed = JsonDocument.Parse(body.ToJsonString());
        return parsed.RootElement.Clone();
    }

    private static async Task ExpectForbiddenAsync(string scenario, Func<Task> request)
    {
        try { await request(); }
        catch (KeycloakAdminException error) when (error.Stage == KeycloakFailureStage.AdminApi && error.StatusCode == HttpStatusCode.Forbidden)
        { Console.WriteLine("PASS: 403 " + scenario); return; }
        catch (KeycloakProtocolException error) when (error.StatusCode == HttpStatusCode.Forbidden)
        { Console.WriteLine("PASS: 403 " + scenario); return; }
        throw new InvalidOperationException("Expected 403: " + scenario);
    }

    private static void Check(bool condition, string scenario)
    {
        if (!condition) throw new InvalidOperationException(scenario);
        Console.WriteLine("PASS: " + scenario);
    }
}
