using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Protocols;
using Microsoft.IdentityModel.Tokens;

internal static class ProtocolCimdWorkflows
{
    internal static async Task RunAsync(KeycloakAdminClient admin, HttpClient http, Uri server, string parentRealm, string secret, Action<bool, string> check, CancellationToken ct)
    {
        using var key = RSA.Create(2048); using var attacker = RSA.Create(2048); using var rotatedKey = RSA.Create(2048);
        await using var publisher = new ProtocolWorkloadIssuer(key, "initial-key"); string realm = parentRealm + "-cimd";
        JsonElement Element(JsonNode node) { using var json = JsonDocument.Parse(node.ToJsonString()); return json.RootElement.Clone(); }
        await admin.RealmsAdmin.ImportRealmAsync(new StringContent(JsonSerializer.Serialize(new RealmRepresentation { Realm = realm, Enabled = true }, KeycloakJsonContext.Default.RealmRepresentation), Encoding.UTF8, "application/json"), ct);
        try
        {
            // The only HTTP exception permits this owned loopback fixture. Production documents and policies use HTTPS.
            await admin.ClientProfiles.UpdateProfilesAsync(realm, new() { Profiles = [new() { Name = "controlled-cimd", Executors = [new() { Executor = "client-id-metadata-document",
                Configuration = Element(new JsonObject { ["cimd-allow-http-scheme"] = true, ["cimd-allow-permitted-domains"] = new JsonArray("127.0.0.1"), ["cimd-restrict-same-domain"] = true }) }] }] }, ct);
            await admin.ClientPolicies.UpdatePoliciesAsync(realm, new() { Policies = [new() { Name = "controlled-cimd", Enabled = true, Conditions = [new() { Condition = "any-client", Configuration = Element(new JsonObject()) }], Profiles = ["controlled-cimd"] }] }, ct);
            await admin.Users.CreateUserAsync(realm, new UserRepresentation { Username = "cimd-user", Enabled = true, FirstName = "CIMD", LastName = "User", Email = "cimd@example.invalid", EmailVerified = true,
                Credentials = [new() { Type = "password", Value = secret, Temporary = false }] }, cancellationToken: ct);
            var actual = (await admin.Users.GetUsersAsync(realm, username: "cimd-user", exact: true, cancellationToken: ct)).Body!.Single();
            var oidc = new OidcClient(new(http, server, realm)); var callback = new Uri(ProtocolWorkloadIssuer.Root + "/callback");
            CimdClientMetadata Metadata(string path, bool confidential = false, string name = "CIMD application") => CimdClientMetadata.Create(new(ProtocolWorkloadIssuer.Root + path), name, [callback],
                confidential ? new Uri(ProtocolWorkloadIssuer.Root + "/jwks") : null, allowLoopbackHttp: true);
            async Task<OidcLoginResult> Login(OAuthClientAuthentication client)
            {
                var transaction = await OidcLoginTransaction.StartAsync(oidc, client, callback, cancellationToken: ct);
                var browser = await ProtocolBrowserFixture.LoginAsync(transaction.AuthorizationUri, callback, "cimd-user", secret, ct);
                return await transaction.CompleteAsync(browser.Callback, client, new(oidc, client.ClientId), ct);
            }
            var publicMetadata = Metadata("/public-metadata.json"); publisher.PublishDocument("/public-metadata.json", publicMetadata.ToJson());
            var publicClient = publicMetadata.CreateAuthentication(); var login = await Login(publicClient);
            var persisted = (await admin.Clients.GetClientsAsync(realm, clientId: publicMetadata.ClientId, cancellationToken: ct)).Body!.Single();
            check(login.Identity.Subject == actual.Id && persisted.PublicClient == true && persisted.RedirectUris!.Contains(callback.AbsoluteUri),
                "CIMD authorization fetches a public metadata document without Admin pre-registration and completes a verified PKCE login for its exact client identity and redirect");
            var refreshed = await oidc.RefreshAsync(publicClient, login.Tokens.Json!.Value.GetProperty("refresh_token").GetString()!, cancellationToken: ct);
            check(refreshed.Json!.Value.TryGetProperty("access_token", out _), "CIMD public-client refresh authenticates the same dynamically registered metadata identity");
            var privateMetadata = Metadata("/private-metadata.json", true); publisher.PublishDocument("/private-metadata.json", privateMetadata.ToJson());
            var signer = new ClientAssertionSigner(privateMetadata.ClientId, oidc, new(new RsaSecurityKey(key) { KeyId = "initial-key" }, "RS256"));
            var privateClient = privateMetadata.CreateAuthentication(signer.CreateAsync); var privateLogin = await Login(privateClient);
            var privatePersisted = (await admin.Clients.GetClientsAsync(realm, clientId: privateMetadata.ClientId, cancellationToken: ct)).Body!.Single();
            check(privateLogin.Identity.Subject == actual.Id && privatePersisted.ClientAuthenticatorType == "client-jwt" && privatePersisted.PublicClient == false,
                "CIMD private_key_jwt uses the public metadata JWKS and returns a verified user identity without publishing a client secret");
            var attackerSigner = new ClientAssertionSigner(privateMetadata.ClientId, oidc, new(new RsaSecurityKey(attacker) { KeyId = "initial-key" }, "RS256")); bool wrongKey = false;
            try { await Login(privateMetadata.CreateAuthentication(attackerSigner.CreateAsync)); } catch (KeycloakProtocolException e) when (e.Error == OAuthError.InvalidClient) { wrongKey = true; }
            check(wrongKey, "CIMD token redemption refuses a private client assertion signed by an unconfigured key");
            publisher.Publish(rotatedKey, "rotated-key"); await admin.ClearKeysCache.ClearKeysCacheAsync(realm, cancellationToken: ct);
            var rotatedSigner = new ClientAssertionSigner(privateMetadata.ClientId, oidc, new(new RsaSecurityKey(rotatedKey) { KeyId = "rotated-key" }, "RS256"));
            check((await Login(privateMetadata.CreateAuthentication(rotatedSigner.CreateAsync))).Identity.Subject == actual.Id, "CIMD private-client signing-key rotation uses the updated pinned metadata JWKS");
            bool retired = false;
            try { await Login(privateClient); } catch (KeycloakProtocolException e) when (e.Error == OAuthError.InvalidClient) { retired = true; }
            check(retired, "CIMD refuses a fresh assertion from a retired metadata signing key");
            async Task<bool> Denied(CimdClientMetadata expected, Uri? redirect = null)
            {
                var transaction = await OidcLoginTransaction.StartAsync(oidc, expected.CreateAuthentication(), redirect ?? callback, cancellationToken: ct);
                using var response = await http.GetAsync(transaction.AuthorizationUri, ct);
                return response.StatusCode == HttpStatusCode.BadRequest || response.StatusCode == HttpStatusCode.Redirect && response.Headers.Location?.Query.Contains("error=", StringComparison.Ordinal) == true;
            }
            check(await Denied(publicMetadata, new(ProtocolWorkloadIssuer.Root + "/unregistered-callback")), "CIMD refuses an authorization redirect absent from the exact published metadata allow-list");
            var mismatched = Metadata("/mismatch.json"); publisher.PublishDocument("/mismatch.json", Metadata("/another-client.json").ToJson());
            check(await Denied(mismatched), "CIMD refuses metadata whose client_id does not exactly match the requested document URL");
            var secretMetadata = Metadata("/secret.json"); var exposed = JsonNode.Parse(secretMetadata.ToJson().GetRawText())!.AsObject(); exposed["client_secret"] = "must-not-publish"; publisher.PublishDocument("/secret.json", Element(exposed));
            check(await Denied(secretMetadata), "CIMD server policy refuses a public metadata document containing client_secret");
            var untrusted = CimdClientMetadata.Create(new("http://localhost:18083/untrusted.json"), "Untrusted domain", [callback], allowLoopbackHttp: true);
            check(await Denied(untrusted), "CIMD server policy refuses document domains outside the explicitly trusted domain list");
        }
        finally { using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(30)); await admin.RealmAdmin.DeleteRealmAsync(realm, cleanup.Token); }
    }
}
