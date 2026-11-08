using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Capabilities;
using Keycloak.Admin.Sdk.Platform;
using Keycloak.Admin.Sdk.Protocols;

internal static class ProtocolValidationRunner
{
    public static async Task RunAsync(HttpClient http, Uri server, KeycloakAdminClient admin, IAccessTokenProvider adminTokens, CancellationToken ct)
    {
        string root = Directory.GetCurrentDirectory(), fingerprint = LiveEvidence.ValidationFingerprint(root);
        if (fingerprint != FeatureValidationBuildStamp.InputFingerprint)
            throw new InvalidDataException("Rebuild the protocol validation executable for the current input.");
        var info = await admin.ServerInfoAdmin.GetInfoAsync(ct);
        using var actualInfo = JsonDocument.Parse(info.Content);
        if (actualInfo.RootElement.GetProperty("systemInfo").GetProperty("version").GetString() != KeycloakTarget.Version)
            throw new InvalidDataException("Protocol acceptance requires the exact target server.");
        string realm = "sdk-protocols-" + Guid.NewGuid().ToString("N"), secret = Convert.ToHexString(RandomNumberGenerator.GetBytes(24)) + "aA1!";
        var checks = new JsonArray();
        void Check(bool condition, string proof)
        {
            if (!condition) throw new InvalidDataException("Protocol workflow failed: " + proof);
            checks.Add((JsonNode)JsonValue.Create(proof)!);
            Console.WriteLine("PASS application protocol: " + proof);
        }
        string Token(ProtocolResponse response) => response.Json!.Value.GetProperty("access_token").GetString()!;
        await admin.RealmsAdmin.ImportRealmAsync(Json(new RealmRepresentation { Realm = realm, Enabled = true, ScimApiEnabled = true }), cancellationToken: ct);
        bool legacy = Environment.GetEnvironmentVariable("KC_TEST_PROTOCOL_PROFILE") == "legacy";
        try
        {
            if (Environment.GetEnvironmentVariable("KC_TEST_PROTOCOL_COMPONENT") == "support")
            {
                await ProtocolSupportedWorkflows.RunAsync(admin, http, server, realm, secret, info.Content, legacy, Check, ct);
                Console.WriteLine("PASS supported factory diagnostics; candidate evidence remains unchanged.");
                return;
            }
            if (legacy) await ProtocolLegacyWorkflows.RunAsync(admin, http, server, realm, secret, Check, ct);
            else
            {
            await admin.Clients.CreateClientAsync(realm, new ClientRepresentation
            {
                ClientId = "sdk-protocols", Enabled = true, Protocol = "openid-connect", PublicClient = false,
                Secret = secret, ServiceAccountsEnabled = true, DirectAccessGrantsEnabled = true, FullScopeAllowed = true,
                ProtocolMappers = [new ProtocolMapperRepresentation { Name = "scim-audience", Protocol = "openid-connect", ProtocolMapper = "oidc-audience-mapper",
                    Config = new() { ["included.custom.audience"] = new Uri(server, "realms/" + realm + "/scim/v2").AbsoluteUri,
                        ["access.token.claim"] = "true", ["id.token.claim"] = "false" } },
                    new ProtocolMapperRepresentation { Name = "introspection-audience", Protocol = "openid-connect", ProtocolMapper = "oidc-audience-mapper",
                        Config = new() { ["included.client.audience"] = "sdk-protocols", ["introspection.token.claim"] = "true",
                            ["access.token.claim"] = "true", ["id.token.claim"] = "false" } }]
            }, cancellationToken: ct);
            var app = (await admin.Clients.GetClientsAsync(realm, clientId: "sdk-protocols", cancellationToken: ct)).Body!.Single();
            var serviceUser = (await admin.Client.GetServiceAccountUserAsync(realm, app.Id!, ct)).Body!;
            var management = (await admin.Clients.GetClientsAsync(realm, clientId: "realm-management", cancellationToken: ct)).Body!.Single();
            var role = (await admin.RoleContainer.GetRoleAsync(realm, management.Id!, "manage-users", ct)).Body!;
            await admin.ClientRoleMappings.AddClientRoleMappingPOSTAdminRealmsRealmUsersUserIdRoleMappingsClientsClientIdAsync(realm, serviceUser.Id!, management.Id!, [role], ct);
            var catalog = new KeycloakFeatureFlagCatalog();
            var flags = KeycloakPlatformGate.Create(catalog.All.ToDictionary(id => id, _ => true, StringComparer.Ordinal), catalog);
            var transport = new ProtocolTransport(http, server, realm, flags);
            var oidc = new OidcClient(transport);
            var discovery = await oidc.DiscoverAsync(ct);
            Check(discovery.Json!.Value.GetProperty("issuer").GetString() == new Uri(server, "realms/" + realm).AbsoluteUri, "OIDC discovery returns the exact issuer");
            Check((await oidc.GetSigningKeysAsync(ct)).Json!.Value.GetProperty("keys").GetArrayLength() > 0, "JWKS returns published signing keys");
            var authentication = OAuthClientAuthentication.SecretBasic("sdk-protocols", _ => ValueTask.FromResult(secret));
            string accessToken = Token(await oidc.ClientCredentialsAsync(authentication, cancellationToken: ct));
            var introspection = await oidc.IntrospectAsync(authentication, accessToken, ct);
            Check(introspection.Json!.Value.GetProperty("active").GetBoolean()
                && introspection.Json.Value.GetProperty("sub").GetString() == serviceUser.Id, "Client credentials and introspection identify the expected service account");
            var scim = RealmResourceClient.ScimUsers(transport);
            using var create = JsonDocument.Parse("""{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"scim-test-user","active":true}""");
            var created = await scim.CreateAsync(create.RootElement, accessToken, ct);
            string userId = created.Json!.Value.GetProperty("id").GetString()!;
            Check((await scim.GetAsync(userId, accessToken, ct)).Json!.Value.GetProperty("userName").GetString() == "scim-test-user", "SCIM create persists and can be read through the independent API");
            using var patch = JsonDocument.Parse("""{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false}]}""");
            await scim.PatchAsync(userId, patch.RootElement, accessToken, ct);
            Check(!(await scim.GetAsync(userId, accessToken, ct)).Json!.Value.GetProperty("active").GetBoolean(), "SCIM PATCH disables the persisted user");
            await scim.DeleteAsync(userId, accessToken, ct);
            var remaining = await scim.ListAsync(accessToken, [new("filter", "userName eq \"scim-test-user\"")], ct);
            Check(remaining.Json!.Value.GetProperty("totalResults").GetInt32() == 0, "SCIM delete removes the resource");

            await admin.Users.CreateUserAsync(realm, new UserRepresentation { Username = "account-user", FirstName = "Test", LastName = "User", Email = "protocols@example.invalid",
                EmailVerified = true, Enabled = true, Credentials = [new CredentialRepresentation { Type = "password", Value = secret, Temporary = false }] }, cancellationToken: ct);
            if (Environment.GetEnvironmentVariable("KC_TEST_PROTOCOL_COMPONENT") == "wallet")
            {
                await ProtocolWalletWorkflows.RunAsync(admin, http, transport, realm, secret, Check, ct);
                Console.WriteLine("PASS wallet diagnostics; no acceptance report or capability promotion generated.");
                return;
            }
            if (Environment.GetEnvironmentVariable("KC_TEST_PROTOCOL_COMPONENT") == "authentication")
            {
                await ProtocolAuthenticationWorkflows.RunAsync(admin, http, transport, secret, Check, ct);
                Console.WriteLine("PASS authentication diagnostics; no acceptance report or capability promotion generated.");
                return;
            }
            if (Environment.GetEnvironmentVariable("KC_TEST_PROTOCOL_COMPONENT") == "oidc")
            {
                await ProtocolOidcResponseWorkflows.RunAsync(admin, http, transport, realm, secret, Check, ct);
                Console.WriteLine("PASS OIDC response diagnostics; no acceptance report or capability promotion generated.");
                return;
            }
            if (Environment.GetEnvironmentVariable("KC_TEST_PROTOCOL_COMPONENT") == "assurance")
            {
                await ProtocolOidcAssuranceWorkflows.RunAsync(admin, http, transport, realm, secret, Check, ct);
#if KEYCLOAK_HOSTING
                await ProtocolHostAssuranceWorkflows.RunAsync(admin, http, transport, realm, secret, Check, ct);
#endif
                Console.WriteLine("PASS assurance diagnostics; no acceptance report or capability promotion generated.");
                return;
            }
#if KEYCLOAK_HOSTING
            if (Environment.GetEnvironmentVariable("KC_TEST_PROTOCOL_COMPONENT") == "saml")
            {
                await ProtocolSamlWorkflows.RunAsync(admin, http, transport, realm, secret, Check, ct);
                Console.WriteLine("PASS SAML diagnostics; no acceptance report or capability promotion generated.");
                return;
            }
            if (Environment.GetEnvironmentVariable("KC_TEST_PROTOCOL_COMPONENT") == "hosting")
            {
                await ProtocolHostWorkflows.RunAsync(admin, transport, realm, secret, Check, ct);
                Console.WriteLine("PASS hosting diagnostics; no acceptance report or capability promotion generated.");
                return;
            }
#endif
            using var userGrant = new FormUrlEncodedContent(new Dictionary<string, string> { ["grant_type"] = "password", ["client_id"] = "sdk-protocols", ["client_secret"] = secret,
                ["username"] = "account-user", ["password"] = secret });
            using var userReply = await http.PostAsync(new Uri(server, "realms/" + realm + "/protocol/openid-connect/token"), userGrant, ct);
            userReply.EnsureSuccessStatusCode();
            using var userToken = JsonDocument.Parse(await userReply.Content.ReadAsStringAsync(ct));
            string userAccessToken = userToken.RootElement.GetProperty("access_token").GetString()!;
            var account = new AccountClient(transport);
            var profile = await account.GetProfileAsync(userAccessToken, ct);
            Check(profile.Json!.Value.GetProperty("username").GetString() == "account-user", "Account API reads the actual user's profile without an admin token");
            using var updateProfile = JsonDocument.Parse("""{"firstName":"Updated","lastName":"User","email":"protocols@example.invalid"}""");
            await account.UpdateProfileAsync(userAccessToken, updateProfile.RootElement, ct);
            Check((await account.GetProfileAsync(userAccessToken, ct)).Json!.Value.GetProperty("firstName").GetString() == "Updated", "Account profile update persists for the same user");
            bool denied = false;
            try { await scim.GetAsync(serviceUser.Id!, userAccessToken, ct); }
            catch (KeycloakProtocolException e) when (e.StatusCode is System.Net.HttpStatusCode.Forbidden or System.Net.HttpStatusCode.NotFound) { denied = true; }
            Check(denied, "An ordinary account user cannot read the privileged service account through SCIM");
            await ProtocolScimWorkflows.RunAsync(admin, http, server, transport, realm, accessToken, userAccessToken, Check, ct);

            await ProtocolOidcWorkflows.RunAsync(admin, http, server, transport, realm, secret, Check, ct);
            await ProtocolOidcResponseWorkflows.RunAsync(admin, http, transport, realm, secret, Check, ct);
            await ProtocolOidcAssuranceWorkflows.RunAsync(admin, http, transport, realm, secret, Check, ct);
            await ProtocolResourceWorkflows.RunAsync(admin, transport, realm, secret, Check, ct);
            await ProtocolParameterizedScopeWorkflows.RunAsync(admin, transport, realm, secret, Check, ct);
            await ProtocolJwtGrantWorkflows.RunAsync(admin, transport, realm, secret, Check, ct);
            await ProtocolCimdWorkflows.RunAsync(admin, http, server, realm, secret, Check, ct);
            await ProtocolClientAuthenticationWorkflows.RunAsync(admin, http, server, transport, realm, Check, ct);
            await ProtocolMutualTlsWorkflows.RunAsync(admin, realm, Check, ct);
            await ProtocolFederatedClientWorkflows.RunAsync(admin, transport, realm, Check, ct);
            await ProtocolDeviceWorkflows.RunAsync(admin, transport, realm, secret, Check, ct);
            await ProtocolCibaWorkflows.RunAsync(admin, transport, realm, secret, Check, ct);
            await ProtocolAuthZenWorkflows.RunAsync(admin, transport, realm, secret, userAccessToken, Check, ct);
            await ProtocolUmaWorkflows.RunAsync(admin, http, transport, realm, secret, userAccessToken, Check, ct);

            var initial = await admin.ClientInitialAccess.CreateAsync(realm, new() { Count = 1, Expiration = 120 }, ct);
            using var initialJson = JsonDocument.Parse(initial.Content);
            string initialToken = initialJson.RootElement.GetProperty("token").GetString()!;
            var registration = RealmResourceClient.ClientRegistration(transport);
            using var registrationBody = JsonDocument.Parse("""{"client_name":"protocol-registered","redirect_uris":["https://app.invalid/callback"]}""");
            var registered = await registration.CreateAsync(registrationBody.RootElement, initialToken, ct);
            string registeredId = registered.Json!.Value.GetProperty("client_id").GetString()!;
            string registrationToken = registered.Json.Value.GetProperty("registration_access_token").GetString()!;
            var registrationRead = await registration.GetAsync(registeredId, registrationToken, ct);
            Check(registrationRead.Json!.Value.GetProperty("client_id").GetString() == registeredId, "OIDC dynamic registration persists and uses its registration access token");
            if (registrationRead.Json.Value.TryGetProperty("registration_access_token", out var renewed)) registrationToken = renewed.GetString()!;
            await registration.DeleteAsync(registeredId, registrationToken, ct);
            Check((await admin.Clients.GetClientsAsync(realm, clientId: registeredId, cancellationToken: ct)).Body!.Count == 0, "Dynamic registration delete removes the admin-visible client");
            await ProtocolRegistrationWorkflows.RunAsync(admin, transport, realm, Check, ct);
            var managementTransport = new ProtocolTransport(http, new Uri(Environment.GetEnvironmentVariable("KC_TEST_OPENAPI_URL") ?? throw new InvalidOperationException("KC_TEST_OPENAPI_URL is required for runtime discovery.")), realm, flags);
            Check(!http.DefaultRequestHeaders.Contains("Authorization") && !http.DefaultRequestHeaders.Contains("Cookie"), "Runtime OpenAPI uses a management client without default realm authorization or session cookies");
            await ProtocolClientV2Workflows.RunAsync(transport, managementTransport, await adminTokens.GetAccessTokenAsync(ct), userAccessToken, Check, ct);
            await ProtocolDockerWorkflows.RunAsync(admin, transport, realm, secret, Check, ct);
            await ProtocolDpopWorkflows.RunAsync(admin, http, server, flags, realm, secret, Check, ct);
            await ProtocolBrokerWorkflows.RunAsync(admin, http, server, transport, realm, secret, Check, ct);
            await ProtocolSsfWorkflows.RunAsync(admin, transport, realm, secret, accessToken, Check, ct);
#if KEYCLOAK_HOSTING
            await ProtocolHostWorkflows.RunAsync(admin, transport, realm, secret, Check, ct);
            await ProtocolHostAssuranceWorkflows.RunAsync(admin, http, transport, realm, secret, Check, ct);
            await ProtocolSamlWorkflows.RunAsync(admin, http, transport, realm, secret, Check, ct);
#endif
            // Host verification deliberately retires an actual realm signing key. Do not reuse a
            // resource credential signed by that retired key in the subsequent independent account workflow.
            userAccessToken = Token(await oidc.PasswordGrantAsync(authentication, "account-user", secret, cancellationToken: ct));
            await ProtocolAccountWorkflows.RunAsync(admin, http, server, transport, realm, secret, userAccessToken, Check, ct);
            await ProtocolWalletWorkflows.RunAsync(admin, http, transport, realm, secret, Check, ct);
            await ProtocolAuthenticationWorkflows.RunAsync(admin, http, transport, secret, Check, ct);
            KeycloakPlatformGate.Replace(flags, catalog.All.ToDictionary(id => id, _ => false, StringComparer.Ordinal), catalog);
            int before = RecordingHandler.SentCount;
            try { await oidc.ClientCredentialsAsync(authentication, cancellationToken: ct); throw new InvalidOperationException("Expected local protocol denial."); }
            catch (InvalidOperationException e) when (e.Message.StartsWith("Protocol disabled by host:", StringComparison.Ordinal)) { }
            Check(RecordingHandler.SentCount == before, "Protocol shutdown sends no token or business HTTP request");
            }
        }
        catch (Exception error)
        {
            Console.Error.WriteLine("Protocol workflow call stack: " + error.StackTrace);
            throw;
        }
        finally
        {
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            await admin.RealmAdmin.DeleteRealmAsync(realm, cleanup.Token);
        }
        if (fingerprint != LiveEvidence.ValidationFingerprint(root)) throw new InvalidDataException("Protocol validation inputs changed during acceptance.");
        bool native = !RuntimeFeature.IsDynamicCodeSupported;
        string mode = native ? "native-aot" : "managed";
        string output = Path.Combine(root, "artifacts/application-protocols", mode + (legacy ? "-legacy" : "") + ".json"); Directory.CreateDirectory(Path.GetDirectoryName(output)!);
        var report = new JsonObject { ["schemaVersion"] = 1, ["serverVersion"] = KeycloakTarget.Version, ["sourceCommit"] = KeycloakTarget.SourceCommit,
            ["inputFingerprint"] = fingerprint, ["completed"] = true, ["promoted"] = false, ["scope"] = "selected application workflows; promotion is determined independently",
            ["runtime"] = mode, ["serverProfile"] = legacy ? "legacy" : "standard", ["runtimeIdentifier"] = native ? System.Runtime.InteropServices.RuntimeInformation.RuntimeIdentifier : null,
            ["executableSha256"] = Convert.ToHexStringLower(SHA256.HashData(await File.ReadAllBytesAsync(native ? Environment.ProcessPath! : Path.Combine(AppContext.BaseDirectory, "Keycloak.Admin.Sdk.IntegrationTests.dll"), ct))),
            ["serverInfoSha256"] = Convert.ToHexStringLower(SHA256.HashData(info.Content.Span)),
            ["counterpartImages"] = legacy ? new JsonObject() : new JsonObject { ["kerberos"] = Environment.GetEnvironmentVariable("KC_TEST_KERBEROS_IMAGE_ID") ?? throw new InvalidDataException("Missing Kerberos counterpart image evidence.") },
            ["serverFeatures"] = JsonNode.Parse(actualInfo.RootElement.GetProperty("features").GetRawText()),
            ["checks"] = checks, ["finishedUtc"] = DateTimeOffset.UtcNow.ToString("O") };
        await File.WriteAllTextAsync(output, report.ToJsonString(), ct);
        Console.WriteLine($"PASS application protocol workflows ({mode}): {checks.Count} business checks; no full capability promotion claimed.");
    }

    private static StringContent Json(RealmRepresentation value) => new(JsonSerializer.Serialize(value, KeycloakJsonContext.Default.RealmRepresentation), System.Text.Encoding.UTF8, "application/json");
}
