using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Keycloak.Admin.Sdk;

if (args is ["--fingerprint"]) { Console.WriteLine(LiveEvidence.Fingerprint(Directory.GetCurrentDirectory())); return 0; }

return await ScriptHost.ExecuteAsync(args, "dotnet run --project tests/Keycloak.Admin.Sdk.IntegrationTests", [], RunAsync);

static async Task RunAsync(CancellationToken cancellationToken)
{
    var server = new Uri(Environment.GetEnvironmentVariable("KC_TEST_URL") ?? throw new InvalidOperationException("KC_TEST_URL is required. Run dotnet run --file tools/Test-Integration.cs."));
    string password = Environment.GetEnvironmentVariable("KC_TEST_PASSWORD") ?? throw new InvalidOperationException("KC_TEST_PASSWORD is required. Run dotnet run --file tools/Test-Integration.cs.");
    using var handler = new RecordingHandler(new SocketsHttpHandler { AllowAutoRedirect = false });
    using var http = new HttpClient(handler);
    using var tokenRequest = new HttpRequestMessage(HttpMethod.Post, new Uri(server, "realms/master/protocol/openid-connect/token"))
    {
        Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["grant_type"] = "password", ["client_id"] = "admin-cli", ["username"] = Environment.GetEnvironmentVariable("KC_TEST_USERNAME") ?? "admin", ["password"] = password })
    };
    using var tokenResponse = await http.SendAsync(tokenRequest, cancellationToken: cancellationToken);
    tokenResponse.EnsureSuccessStatusCode();
    var token = JsonSerializer.Deserialize(await tokenResponse.Content.ReadAsStringAsync(cancellationToken: cancellationToken), KeycloakJsonContext.Default.TokenResponse)!;
    var sdk = new KeycloakAdminClient(http, server, new StaticAccessTokenProvider(token.AccessToken!));
    if (Environment.GetEnvironmentVariable("KC_TEST_PROTOCOLS") == "1")
    {
        using var protocolAdminTokens = new LivePasswordTokens(http, server);
        await ProtocolValidationRunner.RunAsync(http, server, new KeycloakAdminClient(http, server, protocolAdminTokens), protocolAdminTokens, cancellationToken);
        return;
    }
    if (Environment.GetEnvironmentVariable("KC_TEST_FEATURE") is { } feature)
    {
        await FeatureValidationRunner.RunAsync(http, server, new StaticAccessTokenProvider(token.AccessToken!), feature,
            Environment.GetEnvironmentVariable("KC_TEST_FEATURE_GUARDED") == "1", cancellationToken);
        return;
    }
    if (Environment.GetEnvironmentVariable("KC_TEST_FULL_ADMIN") == "1")
    {
        await FullAdminSuite.RunAsync(http, server, cancellationToken);
        return;
    }
    string realm = "sdk-test-" + Guid.NewGuid().ToString("N");
    try
    {
        await sdk.RealmsAdmin.ImportRealmAsync(new StringContent(JsonSerializer.Serialize(new RealmRepresentation { Realm = realm, Enabled = true, OrganizationsEnabled = true }, KeycloakJsonContext.Default.RealmRepresentation), Encoding.UTF8, "application/json"), cancellationToken: cancellationToken);
        Check((await sdk.RealmAdmin.GetRealmAsync(realm, cancellationToken: cancellationToken)).Body!.Realm == realm, "Realm creation");
        await sdk.RealmAdmin.UpdateRealmAsync(realm, new RealmRepresentation { DisplayName = "SDK Native AOT" }, cancellationToken: cancellationToken);
        await sdk.RealmsAdmin.GetRealmsAsync(cancellationToken: cancellationToken);
        await sdk.ServerInfoAdmin.GetInfoAsync(cancellationToken: cancellationToken);
        await sdk.Users.CreateUserAsync(realm, new UserRepresentation { Username = "sdk-user", Enabled = false, Email = "user@example.invalid" }, cancellationToken: cancellationToken);
        var users = (await sdk.Users.GetUsersAsync(realm, username: "sdk-user", exact: true, first: 0, max: 1, cancellationToken: cancellationToken)).Body!;
        Check(users.Count == 1 && users[0].Enabled == false, "User exact query");
        string userId = users[0].Id!;
        Check((await sdk.Users.GetUsersCountAsync(realm, cancellationToken: cancellationToken)).Body == 1, "User count");
        await sdk.User.UpdateUserAsync(realm, userId, new UserRepresentation { Enabled = true, FirstName = "SDK" }, cancellationToken: cancellationToken);
        Check((await sdk.User.GetUserAsync(realm, userId, cancellationToken: cancellationToken)).Body!.FirstName == "SDK", "User update");
        await sdk.User.ResetPasswordAsync(realm, userId, new CredentialRepresentation { Type = "password", Value = Guid.NewGuid().ToString("N") + "aA1!", Temporary = false }, cancellationToken: cancellationToken);
        Check((await sdk.User.CredentialsAsync(realm, userId, cancellationToken: cancellationToken)).Body!.Count == 1, "Password credential");
        await sdk.User.GetSessionsAsync(realm, userId, cancellationToken: cancellationToken);
        await sdk.User.GetConsentsAsync(realm, userId, cancellationToken: cancellationToken);
        await sdk.User.GetConfiguredUserStorageCredentialTypesAsync(realm, userId, cancellationToken: cancellationToken);

        var createdGroup = await sdk.Groups.AddTopLevelGroupAsync(realm, new GroupRepresentation { Name = "group-中" }, cancellationToken: cancellationToken);
        string groupId = LastId(createdGroup);
        await sdk.Group.UpdateGroupAsync(realm, groupId, new GroupRepresentation { Name = "group-updated" }, cancellationToken: cancellationToken);
        Check((await sdk.Group.GetGroupAsync(realm, groupId, cancellationToken: cancellationToken)).Body!.Name == "group-updated", "Group update");
        await sdk.Groups.GetGroupsAsync(realm, first: 0, max: 10, cancellationToken: cancellationToken);
        await sdk.Groups.GetGroupCountAsync(realm, cancellationToken: cancellationToken);
        await sdk.User.JoinGroupAsync(realm, userId, groupId, cancellationToken: cancellationToken);
        Check((await sdk.Group.GetMembersAsync(realm, groupId, cancellationToken: cancellationToken)).Body!.Count == 1, "Membership");
        await sdk.User.GroupMembershipAsync(realm, userId, cancellationToken: cancellationToken);
        await sdk.User.GetGroupMembershipCountAsync(realm, userId, cancellationToken: cancellationToken);
        await sdk.User.RemoveMembershipAsync(realm, userId, groupId, cancellationToken: cancellationToken);

        await sdk.Clients.CreateClientAsync(realm, new ClientRepresentation { ClientId = "sdk-service", Enabled = true, ServiceAccountsEnabled = true, PublicClient = false, Secret = "integration-only-secret", AuthorizationServicesEnabled = true }, cancellationToken: cancellationToken);
        string clientId = (await sdk.Clients.GetClientsAsync(realm, clientId: "sdk-service", cancellationToken: cancellationToken)).Body!.Single().Id!;
        // ClientResource.update disables authorization services when this flag is absent.
        await sdk.Client.UpdateAsync(realm, clientId, new ClientRepresentation { Name = "SDK service", AuthorizationServicesEnabled = true }, cancellationToken: cancellationToken);
        Check((await sdk.Client.GetClientAsync(realm, clientId, cancellationToken: cancellationToken)).Body!.Name == "SDK service", "Client update");
        await sdk.Client.GetClientSecretAsync(realm, clientId, cancellationToken: cancellationToken);
        await sdk.Client.GetServiceAccountUserAsync(realm, clientId, cancellationToken: cancellationToken);
        await sdk.Client.GetDefaultClientScopesAsync(realm, clientId, cancellationToken: cancellationToken);
        await sdk.Client.GetOptionalClientScopesAsync(realm, clientId, cancellationToken: cancellationToken);

        await sdk.RoleContainer.CreateRoleAsync(realm, clientId, new RoleRepresentation { Name = "sdk-role" }, cancellationToken: cancellationToken);
        var role = (await sdk.RoleContainer.GetRoleAsync(realm, clientId, "sdk-role", cancellationToken: cancellationToken)).Body!;
        await sdk.RoleById.GetRoleAsync(realm, role.Id!, cancellationToken: cancellationToken);
        await sdk.RoleById.UpdateRoleAsync(realm, role.Id!, new RoleRepresentation { Name = "sdk-role", Description = "updated" }, cancellationToken: cancellationToken);
        await sdk.RoleContainer.GetRolesAsync(realm, clientId, cancellationToken: cancellationToken);
        await sdk.ClientRoleMappings.AddClientRoleMappingAsync(realm, groupId, clientId, [role], cancellationToken: cancellationToken);
        Check((await sdk.ClientRoleMappings.GetClientRoleMappingsAsync(realm, groupId, clientId, cancellationToken: cancellationToken)).Body!.Count == 1, "Role mapping");
        await sdk.ClientRoleMappings.GetCompositeClientRoleMappingsAsync(realm, groupId, clientId, cancellationToken: cancellationToken);
        await sdk.ClientRoleMappings.GetAvailableClientRoleMappingsAsync(realm, groupId, clientId, cancellationToken: cancellationToken);
        await sdk.ClientRoleMappings.DeleteClientRoleMappingAsync(realm, groupId, clientId, [role], cancellationToken: cancellationToken);

        var scopeCreated = await sdk.ClientScopes.CreateClientScopeAsync(realm, new ClientScopeRepresentation { Name = "sdk-scope", Protocol = "openid-connect" }, cancellationToken: cancellationToken);
        string scopeId = LastId(scopeCreated);
        await sdk.ClientScope.GetClientScopeAsync(realm, scopeId, cancellationToken: cancellationToken);
        await sdk.ClientScope.UpdateAsync(realm, scopeId, new ClientScopeRepresentation { Name = "sdk-scope", Description = "updated" }, cancellationToken: cancellationToken);
        await sdk.ClientScopes.GetClientScopesAsync(realm, cancellationToken: cancellationToken);
        await sdk.Server.FindByIdAsync(realm, clientId, cancellationToken: cancellationToken);
        await sdk.Server.ExportSettingsAsync(realm, clientId, cancellationToken: cancellationToken);
        await sdk.Scope.CreateAsync(realm, clientId, new ScopeRepresentation { Name = "sdk-authz-scope" }, cancellationToken: cancellationToken);
        var authzScope = (await sdk.Scope.FindAllAsync(realm, clientId, name: "sdk-authz-scope", cancellationToken: cancellationToken)).Body!.Single();
        await sdk.Scope.FindByIdAsync(realm, clientId, authzScope.Id!, cancellationToken: cancellationToken);
        Check((await sdk.Scope.FindAsync(realm, clientId, "sdk-authz-scope", cancellationToken: cancellationToken)).Body!.Id == authzScope.Id, "Source-corrected single scope search");
        await sdk.Scope.UpdateAsync(realm, clientId, authzScope.Id!, new ScopeRepresentation { Name = "sdk-authz-scope", DisplayName = "updated" }, cancellationToken: cancellationToken);
        var policy = await sdk.Policy.CreatePOSTAdminRealmsRealmClientsClientUuidAuthzResourceServerPolicyAsync(realm, clientId,
            new PolicyRepresentation { Name = "sdk-user-policy", Type = "user", Logic = "POSITIVE", DecisionStrategy = "UNANIMOUS", Config = new() { ["users"] = "[\"" + userId + "\"]" } }, cancellationToken: cancellationToken);
        Check(policy.Body!.Name == "sdk-user-policy", "Source-corrected raw JSON policy creation and response");
        await AlignmentLive.RunAsync(sdk, realm, clientId, userId, authzScope.Id!, policy.Body.Id!, cancellationToken);
        await sdk.Scope.DeleteAsync(realm, clientId, authzScope.Id!, cancellationToken: cancellationToken);

        await sdk.AuthenticationManagement.GetFlowsAsync(realm, cancellationToken: cancellationToken);
        await sdk.AuthenticationManagement.GetAuthenticatorProvidersAsync(realm, cancellationToken: cancellationToken);
        await sdk.AuthenticationManagement.GetRequiredActionsAsync(realm, cancellationToken: cancellationToken);
        await sdk.UserProfile.GetConfigurationAsync(realm, cancellationToken: cancellationToken);
        await sdk.UserProfile.GetMetadataAsync(realm, cancellationToken: cancellationToken);
        await sdk.RealmAdmin.GetRealmEventsConfigAsync(realm, cancellationToken: cancellationToken);
        await sdk.RealmAdmin.GetEventsAsync(realm, operationTypes: ["CREATE", "UPDATE"], cancellationToken: cancellationToken);
        await sdk.Organizations.CreateAsync(realm, new OrganizationRepresentation { Name = "sdk-org", Alias = "sdk-org", Enabled = true }, cancellationToken: cancellationToken);
        var org = (await sdk.Organizations.SearchAsync(realm, search: "sdk-org", exact: true, cancellationToken: cancellationToken)).Body!.Single();
        await sdk.Organization.GetAsync(realm, org.Id!, cancellationToken: cancellationToken);
        await sdk.Organization.UpdateAsync(realm, org.Id!, new OrganizationRepresentation { Name = "sdk-org", Alias = "sdk-org", Enabled = true, Description = "updated" }, cancellationToken: cancellationToken);
        await sdk.OrganizationMember.AddMemberAsync(realm, org.Id!, userId, cancellationToken: cancellationToken);
        Check((await sdk.OrganizationMember.CountAsync(realm, org.Id!, cancellationToken: cancellationToken)).Body == 1, "Organization member");
        await sdk.OrganizationMember.GetAsync(realm, org.Id!, userId, cancellationToken: cancellationToken);
        await sdk.OrganizationMember.SearchAsync(realm, org.Id!, cancellationToken: cancellationToken);
        await sdk.OrganizationMember.DeleteAsync(realm, org.Id!, userId, cancellationToken: cancellationToken);
        await sdk.Organization.DeleteAsync(realm, org.Id!, cancellationToken: cancellationToken);

        using var provider = new ClientCredentialsTokenProvider(http, server, realm, "sdk-service", _ => ValueTask.FromResult("integration-only-secret"));
        var restricted = new KeycloakAdminClient(http, server, provider);
        try { await restricted.Users.GetUsersAsync(realm, cancellationToken: cancellationToken); throw new Exception("Expected forbidden"); }
        catch (KeycloakAdminException e) { Check(e.StatusCode == HttpStatusCode.Forbidden, "Service-account permission boundary"); }
        try { await sdk.User.GetUserAsync(realm, Guid.NewGuid().ToString(), cancellationToken: cancellationToken); throw new Exception("Expected missing user"); }
        catch (KeycloakAdminException e) { Check(e.StatusCode == HttpStatusCode.NotFound, "Missing user status"); }

        await sdk.ClientScope.DeleteClientScopeAsync(realm, scopeId, cancellationToken: cancellationToken);
        await sdk.RoleContainer.DeleteRoleAsync(realm, clientId, "sdk-role", cancellationToken: cancellationToken);
        await sdk.Client.DeleteClientAsync(realm, clientId, cancellationToken: cancellationToken);
        await sdk.Group.DeleteGroupAsync(realm, groupId, cancellationToken: cancellationToken);
        await sdk.User.DeleteUserAsync(realm, userId, cancellationToken: cancellationToken);
    }
    finally
    {
        using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        try { await sdk.RealmAdmin.DeleteRealmAsync(realm, cancellationToken: cleanup.Token); }
        catch (KeycloakAdminException error) when (error.StatusCode == HttpStatusCode.NotFound) { }
    }
    Directory.CreateDirectory("artifacts");
    await File.WriteAllLinesAsync("artifacts/live-endpoints.tsv", handler.Results.Order(), cancellationToken: cancellationToken);
    Console.WriteLine($"PASS: isolated Keycloak {KeycloakTarget.Version} CRUD, credentials, membership, authorization scopes, organizations and permission boundaries; {handler.Results.Count} HTTP method/path/status observations. Realm cleaned up.");
}

static void Check(bool condition, string message) { if (!condition) throw new Exception(message); }
static string LastId(AdminResponse response) => Uri.UnescapeDataString(response.Location!.OriginalString.TrimEnd('/').Split('/').Last());

sealed class RecordingHandler(HttpMessageHandler inner) : DelegatingHandler(inner)
{
    private static int sent;
    public static int SentCount => Volatile.Read(ref sent);
    public HashSet<string> Results { get; } = [];
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref sent);
        var response = await base.SendAsync(request, cancellationToken);
        if (!response.IsSuccessStatusCode && Environment.GetEnvironmentVariable("KC_TEST_PROTOCOL_COMPONENT") == "wallet" && request.RequestUri!.AbsolutePath.EndsWith("/protocol/oid4vc/credential", StringComparison.Ordinal))
        {
            using var failure = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken));
            if (failure.RootElement.TryGetProperty("error_description", out var description))
            {
                string text = description.GetString() ?? "";
                string[] known = ["JWK algorithm", "Unsupported content encryption algorithm", "Invalid JWK", "Encryption operation failed", "credential_response_encryption requires encrypted", "Encryption is required", "Could not decrypt", "Missing required parameters"];
                Console.WriteLine("Wallet diagnostic classification: " + (known.FirstOrDefault(text.StartsWith) ?? "unclassified"));
            }
        }
        if (!response.IsSuccessStatusCode && Environment.GetEnvironmentVariable("KC_TEST_FULL_ADMIN") == "1")
        {
            string error = await response.Content.ReadAsStringAsync(cancellationToken);
            string? secret = Environment.GetEnvironmentVariable("KC_TEST_PASSWORD");
            if (!string.IsNullOrEmpty(secret)) error = error.Replace(secret, "[redacted]", StringComparison.Ordinal);
            Console.Error.WriteLine($"HTTP {(int)response.StatusCode}: {request.Method} {request.RequestUri!.AbsolutePath}: {error[..Math.Min(error.Length, 1500)]}");
        }
        var endpoint = AdminEndpointCatalog.All.Where(x => x.Method == request.Method.Method)
            .OrderByDescending(x => Regex.Replace(x.Path, @"\{[^}]+\}", "").Length)
            .FirstOrDefault(x => Regex.IsMatch(request.RequestUri!.AbsolutePath, "^" + Regex.Replace(Regex.Escape(x.Path), @"\\\{[^}]+\}", "[^/]+") + "/?$"));
        if (endpoint is not null) Results.Add($"{endpoint.Method}\t{endpoint.Path}\t{(int)response.StatusCode}");
        return response;
    }
}
