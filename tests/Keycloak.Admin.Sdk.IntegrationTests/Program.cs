using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Keycloak.Admin.Sdk;

var server = new Uri(Environment.GetEnvironmentVariable("KC_TEST_URL") ?? throw new InvalidOperationException("KC_TEST_URL is required. Run dotnet run --file tools/Test-Integration.cs."));
string password = Environment.GetEnvironmentVariable("KC_TEST_PASSWORD") ?? throw new InvalidOperationException("KC_TEST_PASSWORD is required. Run dotnet run --file tools/Test-Integration.cs.");
using var handler = new RecordingHandler(new SocketsHttpHandler { AllowAutoRedirect = false });
using var http = new HttpClient(handler);
using var tokenRequest = new HttpRequestMessage(HttpMethod.Post, new Uri(server, "realms/master/protocol/openid-connect/token"))
{
    Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["grant_type"] = "password", ["client_id"] = "admin-cli", ["username"] = Environment.GetEnvironmentVariable("KC_TEST_USERNAME") ?? "admin", ["password"] = password })
};
using var tokenResponse = await http.SendAsync(tokenRequest);
tokenResponse.EnsureSuccessStatusCode();
var token = JsonSerializer.Deserialize(await tokenResponse.Content.ReadAsStringAsync(), KeycloakJsonContext.Default.TokenResponse)!;
var sdk = new KeycloakAdminClient(http, server, new StaticAccessTokenProvider(token.AccessToken!));
if (Environment.GetEnvironmentVariable("KC_TEST_FULL_ADMIN") == "1")
{
    await FullAdminSuite.RunAsync(http, server);
    return;
}
string realm = "sdk-test-" + Guid.NewGuid().ToString("N");
try
{
    await sdk.RealmsAdmin.ImportRealmAsync(new StringContent(JsonSerializer.Serialize(new RealmRepresentation { Realm = realm, Enabled = true, OrganizationsEnabled = true }, KeycloakJsonContext.Default.RealmRepresentation), Encoding.UTF8, "application/json"));
    Check((await sdk.RealmAdmin.GetRealmAsync(realm)).Body!.Realm == realm, "Realm creation");
    await sdk.RealmAdmin.UpdateRealmAsync(realm, new RealmRepresentation { DisplayName = "SDK Native AOT" });
    await sdk.RealmsAdmin.GetRealmsAsync();
    await sdk.ServerInfoAdmin.GetInfoAsync();
    await sdk.Users.CreateUserAsync(realm, new UserRepresentation { Username = "sdk-user", Enabled = false, Email = "user@example.invalid" });
    var users = (await sdk.Users.GetUsersAsync(realm, username: "sdk-user", exact: true, first: 0, max: 1)).Body!;
    Check(users.Count == 1 && users[0].Enabled == false, "User exact query");
    string userId = users[0].Id!;
    Check((await sdk.Users.GetUsersCountAsync(realm)).Body == 1, "User count");
    await sdk.User.UpdateUserAsync(realm, userId, new UserRepresentation { Enabled = true, FirstName = "SDK" });
    Check((await sdk.User.GetUserAsync(realm, userId)).Body!.FirstName == "SDK", "User update");
    await sdk.User.ResetPasswordAsync(realm, userId, new CredentialRepresentation { Type = "password", Value = Guid.NewGuid().ToString("N") + "aA1!", Temporary = false });
    Check((await sdk.User.CredentialsAsync(realm, userId)).Body!.Count == 1, "Password credential");
    await sdk.User.GetSessionsAsync(realm, userId);
    await sdk.User.GetConsentsAsync(realm, userId);
    await sdk.User.GetConfiguredUserStorageCredentialTypesAsync(realm, userId);

    var createdGroup = await sdk.Groups.AddTopLevelGroupAsync(realm, new GroupRepresentation { Name = "group-中" });
    string groupId = LastId(createdGroup);
    await sdk.Group.UpdateGroupAsync(realm, groupId, new GroupRepresentation { Name = "group-updated" });
    Check((await sdk.Group.GetGroupAsync(realm, groupId)).Body!.Name == "group-updated", "Group update");
    await sdk.Groups.GetGroupsAsync(realm, first: 0, max: 10);
    await sdk.Groups.GetGroupCountAsync(realm);
    await sdk.User.JoinGroupAsync(realm, userId, groupId);
    Check((await sdk.Group.GetMembersAsync(realm, groupId)).Body!.Count == 1, "Membership");
    await sdk.User.GroupMembershipAsync(realm, userId);
    await sdk.User.GetGroupMembershipCountAsync(realm, userId);
    await sdk.User.RemoveMembershipAsync(realm, userId, groupId);

    await sdk.Clients.CreateClientAsync(realm, new ClientRepresentation { ClientId = "sdk-service", Enabled = true, ServiceAccountsEnabled = true, PublicClient = false, Secret = "integration-only-secret", AuthorizationServicesEnabled = true });
    string clientId = (await sdk.Clients.GetClientsAsync(realm, clientId: "sdk-service")).Body!.Single().Id!;
    // ClientResource.update disables authorization services when this flag is absent.
    await sdk.Client.UpdateAsync(realm, clientId, new ClientRepresentation { Name = "SDK service", AuthorizationServicesEnabled = true });
    Check((await sdk.Client.GetClientAsync(realm, clientId)).Body!.Name == "SDK service", "Client update");
    await sdk.Client.GetClientSecretAsync(realm, clientId);
    await sdk.Client.GetServiceAccountUserAsync(realm, clientId);
    await sdk.Client.GetDefaultClientScopesAsync(realm, clientId);
    await sdk.Client.GetOptionalClientScopesAsync(realm, clientId);

    await sdk.RoleContainer.CreateRoleAsync(realm, clientId, new RoleRepresentation { Name = "sdk-role" });
    var role = (await sdk.RoleContainer.GetRoleAsync(realm, clientId, "sdk-role")).Body!;
    await sdk.RoleById.GetRoleAsync(realm, role.Id!);
    await sdk.RoleById.UpdateRoleAsync(realm, role.Id!, new RoleRepresentation { Name = "sdk-role", Description = "updated" });
    await sdk.RoleContainer.GetRolesAsync(realm, clientId);
    await sdk.ClientRoleMappings.AddClientRoleMappingAsync(realm, groupId, clientId, [role]);
    Check((await sdk.ClientRoleMappings.GetClientRoleMappingsAsync(realm, groupId, clientId)).Body!.Count == 1, "Role mapping");
    await sdk.ClientRoleMappings.GetCompositeClientRoleMappingsAsync(realm, groupId, clientId);
    await sdk.ClientRoleMappings.GetAvailableClientRoleMappingsAsync(realm, groupId, clientId);
    await sdk.ClientRoleMappings.DeleteClientRoleMappingAsync(realm, groupId, clientId, [role]);

    var scopeCreated = await sdk.ClientScopes.CreateClientScopeAsync(realm, new ClientScopeRepresentation { Name = "sdk-scope", Protocol = "openid-connect" });
    string scopeId = LastId(scopeCreated);
    await sdk.ClientScope.GetClientScopeAsync(realm, scopeId);
    await sdk.ClientScope.UpdateAsync(realm, scopeId, new ClientScopeRepresentation { Name = "sdk-scope", Description = "updated" });
    await sdk.ClientScopes.GetClientScopesAsync(realm);
    await sdk.Server.FindByIdAsync(realm, clientId);
    await sdk.Server.ExportSettingsAsync(realm, clientId);
    await sdk.Scope.CreateAsync(realm, clientId, new ScopeRepresentation { Name = "sdk-authz-scope" });
    var authzScope = (await sdk.Scope.FindAllAsync(realm, clientId, name: "sdk-authz-scope")).Body!.Single();
    await sdk.Scope.FindByIdAsync(realm, clientId, authzScope.Id!);
    Check((await sdk.Scope.FindAsync(realm, clientId, "sdk-authz-scope")).Body!.Id == authzScope.Id, "Source-corrected single scope search");
    await sdk.Scope.UpdateAsync(realm, clientId, authzScope.Id!, new ScopeRepresentation { Name = "sdk-authz-scope", DisplayName = "updated" });
    var policy = await sdk.Policy.CreatePOSTAdminRealmsRealmClientsClientUuidAuthzResourceServerPolicyAsync(realm, clientId,
        new PolicyRepresentation { Name = "sdk-user-policy", Type = "user", Logic = "POSITIVE", DecisionStrategy = "UNANIMOUS", Config = new() { ["users"] = "[\"" + userId + "\"]" } });
    Check(policy.Body!.Name == "sdk-user-policy", "Source-corrected raw JSON policy creation and response");
    await AlignmentLive.RunAsync(sdk, realm, clientId, userId, authzScope.Id!, policy.Body.Id!);
    await sdk.Scope.DeleteAsync(realm, clientId, authzScope.Id!);

    await sdk.AuthenticationManagement.GetFlowsAsync(realm);
    await sdk.AuthenticationManagement.GetAuthenticatorProvidersAsync(realm);
    await sdk.AuthenticationManagement.GetRequiredActionsAsync(realm);
    await sdk.UserProfile.GetConfigurationAsync(realm);
    await sdk.UserProfile.GetMetadataAsync(realm);
    await sdk.RealmAdmin.GetRealmEventsConfigAsync(realm);
    await sdk.RealmAdmin.GetEventsAsync(realm, operationTypes: ["CREATE", "UPDATE"]);
    await sdk.Organizations.CreateAsync(realm, new OrganizationRepresentation { Name = "sdk-org", Alias = "sdk-org", Enabled = true });
    var org = (await sdk.Organizations.SearchAsync(realm, search: "sdk-org", exact: true)).Body!.Single();
    await sdk.Organization.GetAsync(realm, org.Id!);
    await sdk.Organization.UpdateAsync(realm, org.Id!, new OrganizationRepresentation { Name = "sdk-org", Alias = "sdk-org", Enabled = true, Description = "updated" });
    await sdk.OrganizationMember.AddMemberAsync(realm, org.Id!, userId);
    Check((await sdk.OrganizationMember.CountAsync(realm, org.Id!)).Body == 1, "Organization member");
    await sdk.OrganizationMember.GetAsync(realm, org.Id!, userId);
    await sdk.OrganizationMember.SearchAsync(realm, org.Id!);
    await sdk.OrganizationMember.DeleteAsync(realm, org.Id!, userId);
    await sdk.Organization.DeleteAsync(realm, org.Id!);

    using var provider = new ClientCredentialsTokenProvider(http, server, realm, "sdk-service", _ => ValueTask.FromResult("integration-only-secret"));
    var restricted = new KeycloakAdminClient(http, server, provider);
    try { await restricted.Users.GetUsersAsync(realm); throw new Exception("Expected forbidden"); }
    catch (KeycloakAdminException e) { Check(e.StatusCode == HttpStatusCode.Forbidden, "Service-account permission boundary"); }
    try { await sdk.User.GetUserAsync(realm, Guid.NewGuid().ToString()); throw new Exception("Expected missing user"); }
    catch (KeycloakAdminException e) { Check(e.StatusCode == HttpStatusCode.NotFound, "Missing user status"); }

    await sdk.ClientScope.DeleteClientScopeAsync(realm, scopeId);
    await sdk.RoleContainer.DeleteRoleAsync(realm, clientId, "sdk-role");
    await sdk.Client.DeleteClientAsync(realm, clientId);
    await sdk.Group.DeleteGroupAsync(realm, groupId);
    await sdk.User.DeleteUserAsync(realm, userId);
}
finally { await sdk.RealmAdmin.DeleteRealmAsync(realm); }
Directory.CreateDirectory("artifacts");
await File.WriteAllLinesAsync("artifacts/live-endpoints.tsv", handler.Results.Order());
Console.WriteLine($"PASS: isolated Keycloak 26.8.1 CRUD, credentials, membership, authorization scopes, organizations and permission boundaries; {handler.Results.Count} HTTP method/path/status observations. Realm cleaned up.");

static void Check(bool condition, string message) { if (!condition) throw new Exception(message); }
static string LastId(AdminResponse response) => Uri.UnescapeDataString(response.Location!.OriginalString.TrimEnd('/').Split('/').Last());

sealed class RecordingHandler(HttpMessageHandler inner) : DelegatingHandler(inner)
{
    public HashSet<string> Results { get; } = [];
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var response = await base.SendAsync(request, cancellationToken);
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
