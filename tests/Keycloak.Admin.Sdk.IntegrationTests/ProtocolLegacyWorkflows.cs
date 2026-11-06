using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Capabilities;
using Keycloak.Admin.Sdk.Protocols;

/// <summary>FGAP v1 and deprecated exchange/broker APIs need their own mutually exclusive server profile.</summary>
internal static class ProtocolLegacyWorkflows
{
    internal static async Task RunAsync(KeycloakAdminClient admin, HttpClient http, Uri server, string realm, string secret, Action<bool, string> check, CancellationToken ct)
    {
        var flags = new KeycloakFeatureSnapshotGate(new Dictionary<string, bool> { ["KeycloakSdk.Protocols"] = true, ["KeycloakSdk.Protocols.Oidc"] = true,
            ["KeycloakSdk.Protocols.OidcLegacyExchange"] = true, ["KeycloakSdk.Protocols.IdentityBrokeringLegacy"] = true,
            ["KeycloakSdk.Protocols.IdentityBrokerLogin"] = true });
        var transport = new ProtocolTransport(http, server, realm, flags); var oidc = new OidcClient(transport); var broker = new IdentityBrokerClient(transport);
        var redirect = new Uri("https://app.invalid/legacy-callback");
        async Task<ClientRepresentation> Client(string name, bool browser = false)
        {
            await admin.Clients.CreateClientAsync(realm, new ClientRepresentation { ClientId = name, Enabled = true, Protocol = "openid-connect", Secret = secret,
                PublicClient = false, DirectAccessGrantsEnabled = true, StandardFlowEnabled = browser, RedirectUris = browser ? [redirect.AbsoluteUri] : [], FullScopeAllowed = true,
                Attributes = new() { ["standard.token.exchange.enabled"] = "false" },
                ProtocolMappers = [new() { Name = "own-audience", Protocol = "openid-connect", ProtocolMapper = "oidc-audience-mapper",
                    Config = new() { ["included.client.audience"] = name, ["access.token.claim"] = "true" } }] }, cancellationToken: ct);
            return (await admin.Clients.GetClientsAsync(realm, clientId: name, cancellationToken: ct)).Body!.Single();
        }
        var source = await Client("legacy-source", true); var target = await Client("legacy-target"); var unrelated = await Client("legacy-unrelated");
        var sourceAuth = OAuthClientAuthentication.SecretBasic(source.ClientId!, _ => ValueTask.FromResult(secret));
        var targetAuth = OAuthClientAuthentication.SecretBasic(target.ClientId!, _ => ValueTask.FromResult(secret));
        var unrelatedAuth = OAuthClientAuthentication.SecretBasic(unrelated.ClientId!, _ => ValueTask.FromResult(secret));
        foreach (string name in new[] { "legacy-user", "legacy-victim" })
            await admin.Users.CreateUserAsync(realm, new() { Username = name, Enabled = true, FirstName = "Legacy", LastName = "User", Email = name + "@example.invalid", EmailVerified = true,
                Credentials = [new() { Type = "password", Value = secret, Temporary = false }] }, cancellationToken: ct);
        var user = (await admin.Users.GetUsersAsync(realm, username: "legacy-user", exact: true, cancellationToken: ct)).Body!.Single();
        var victim = (await admin.Users.GetUsersAsync(realm, username: "legacy-victim", exact: true, cancellationToken: ct)).Body!.Single();
        string Token(ProtocolResponse value) => value.Json!.Value.GetProperty("access_token").GetString()!;
        string subject = Token(await oidc.PasswordGrantAsync(sourceAuth, "legacy-user", secret, cancellationToken: ct));
        async Task<bool> Denied(Func<Task<ProtocolResponse>> action)
        {
            try { await action(); return false; }
            catch (KeycloakProtocolException e) when (e.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.BadRequest or HttpStatusCode.Unauthorized) { return true; }
        }
        check(await Denied(() => oidc.ExchangeLegacyAsync(sourceAuth, subject, audience: target.ClientId, cancellationToken: ct)),
            "Legacy internal exchange denies an otherwise authenticated client before FGAP v1 target permission exists");
        var targetPermissions = (await admin.Client.SetManagementPermissionsEnabledAsync(realm, target.Id!, new() { Enabled = true }, ct)).Body!;
        var management = (await admin.Clients.GetClientsAsync(realm, clientId: "realm-management", cancellationToken: ct)).Body!.Single();
        string authz = "/admin/realms/" + realm + "/clients/" + management.Id + "/authz/resource-server";
        async Task<JsonObject> Request(HttpMethod method, string path, JsonObject? body = null)
        {
            var response = await admin.SendAsync(method, path, content: body is null ? null : new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json"), cancellationToken: ct);
            return response.Content.IsEmpty ? new() : JsonNode.Parse(response.Content.Span)!.AsObject();
        }
        var policy = await Request(HttpMethod.Post, authz + "/policy/client", new() { ["name"] = "legacy-approved-client", ["logic"] = "POSITIVE", ["clients"] = new JsonArray(source.Id) });
        string policyId = policy["id"]!.GetValue<string>();
        async Task SetPermission(string permissionId, bool allowed)
        {
            var permission = await Request(HttpMethod.Get, authz + "/permission/scope/" + permissionId);
            permission["policies"] = allowed ? new JsonArray(policyId) : new JsonArray(); permission["decisionStrategy"] = "AFFIRMATIVE";
            await Request(HttpMethod.Put, authz + "/permission/scope/" + permissionId, permission);
        }
        string exchangePermission = targetPermissions.ScopePermissions!["token-exchange"];
        await SetPermission(exchangePermission, true);
        var exchanged = await oidc.ExchangeLegacyAsync(sourceAuth, subject, audience: target.ClientId, cancellationToken: ct, requestedTokenType: TokenExchangeRequestedTokenType.AccessToken);
        check((await new KeycloakAccessTokenValidator(oidc, target.ClientId!).ValidateAsync(Token(exchanged), ct)).Subject == user.Id,
            "FGAP v1 approved internal exchange issues an independently verified token for the exact original subject and target audience");
        var refreshedExchange = await oidc.ExchangeLegacyAsync(sourceAuth, subject, audience: target.ClientId, cancellationToken: ct, requestedTokenType: TokenExchangeRequestedTokenType.RefreshToken);
        string exchangedRefresh = refreshedExchange.Json!.Value.GetProperty("refresh_token").GetString()!;
        check(await Denied(() => oidc.RefreshAsync(targetAuth, exchangedRefresh, cancellationToken: ct))
            && (await new KeycloakAccessTokenValidator(oidc, source.ClientId!).ValidateAsync(Token(await oidc.RefreshAsync(sourceAuth, exchangedRefresh, cancellationToken: ct)), ct)).Subject == user.Id,
            "Legacy refresh-token exchange binds the returned refresh credential to the requesting client and preserves its verified subject");
        string foreignSubject = Token(await oidc.PasswordGrantAsync(unrelatedAuth, "legacy-user", secret, cancellationToken: ct));
        check(await Denied(() => oidc.ExchangeLegacyAsync(unrelatedAuth, foreignSubject, audience: target.ClientId, cancellationToken: ct)),
            "Legacy target permission does not authorize an unrelated confidential client");
        await SetPermission(exchangePermission, false);
        check(await Denied(() => oidc.ExchangeLegacyAsync(sourceAuth, subject, audience: target.ClientId, cancellationToken: ct)),
            "Revoking FGAP v1 target permission denies the next legacy exchange with the original still-valid subject token");
        check(await Denied(() => oidc.ExchangeLegacyAsync(sourceAuth, subject, requestedSubject: victim.Id, cancellationToken: ct))
            && await Denied(() => oidc.ImpersonateLegacyAsync(sourceAuth, victim.Id!, cancellationToken: ct)),
            "Legacy user-token and direct impersonation both deny a client or user without explicit impersonation authority");
        var impersonateRole = (await admin.RoleContainer.GetRoleAsync(realm, management.Id!, "impersonation", ct)).Body!;
        await admin.ClientRoleMappings.AddClientRoleMappingPOSTAdminRealmsRealmUsersUserIdRoleMappingsClientsClientIdAsync(realm, user.Id!, management.Id!, [impersonateRole], ct);
        string impersonator = Token(await oidc.PasswordGrantAsync(sourceAuth, "legacy-user", secret, cancellationToken: ct));
        var impersonated = await oidc.ExchangeLegacyAsync(sourceAuth, impersonator, requestedSubject: victim.Id, cancellationToken: ct);
        check((await new KeycloakAccessTokenValidator(oidc, source.ClientId!).ValidateAsync(Token(impersonated), ct)).Subject == victim.Id,
            "Legacy authorized user impersonation issues a signature-verified token for the explicitly requested target identity");
        await admin.ClientRoleMappings.DeleteClientRoleMappingDELETEAdminRealmsRealmUsersUserIdRoleMappingsClientsClientIdAsync(realm, user.Id!, management.Id!, [impersonateRole], ct);
        string noLongerImpersonator = Token(await oidc.PasswordGrantAsync(sourceAuth, "legacy-user", secret, cancellationToken: ct));
        check(await Denied(() => oidc.ExchangeLegacyAsync(sourceAuth, noLongerImpersonator, requestedSubject: victim.Id, cancellationToken: ct)),
            "Revoking the impersonation role removes authority from the user's next freshly issued access token");
        var userPermissions = (await admin.RealmAdmin.SetUsersManagementPermissionsEnabledAsync(realm, new() { Enabled = true }, ct)).Body!;
        string directPermission = userPermissions.ScopePermissions!["impersonate"];
        await SetPermission(directPermission, true);
        check((await new KeycloakAccessTokenValidator(oidc, source.ClientId!).ValidateAsync(Token(await oidc.ImpersonateLegacyAsync(sourceAuth, victim.Id!, cancellationToken: ct)), ct)).Subject == victim.Id,
            "Direct legacy impersonation requires actual FGAP v1 client permission and verifies the requested target subject");
        await SetPermission(directPermission, false);
        check(await Denied(() => oidc.ImpersonateLegacyAsync(sourceAuth, victim.Id!, cancellationToken: ct)),
            "Revoking FGAP v1 client impersonation permission immediately prevents another direct impersonation");

        string upstreamRealm = realm + "-legacy-upstream", alias = "legacy-upstream";
        var issuer = new Uri(server, "realms/" + upstreamRealm);
        await admin.RealmsAdmin.ImportRealmAsync(new StringContent(JsonSerializer.Serialize(new RealmRepresentation { Realm = upstreamRealm, Enabled = true,
            Attributes = new() { ["frontendUrl"] = server.AbsoluteUri } }, KeycloakJsonContext.Default.RealmRepresentation), Encoding.UTF8, "application/json"), cancellationToken: ct);
        try
        {
            await admin.Clients.CreateClientAsync(upstreamRealm, new() { ClientId = "legacy-provider", Enabled = true, Protocol = "openid-connect", Secret = secret, PublicClient = false,
                StandardFlowEnabled = true, DirectAccessGrantsEnabled = true, RedirectUris = [new Uri(server, "realms/" + realm + "/broker/" + alias + "/endpoint").AbsoluteUri],
                ProtocolMappers = [new() { Name = "own-audience", Protocol = "openid-connect", ProtocolMapper = "oidc-audience-mapper", Config = new() { ["included.client.audience"] = "legacy-provider", ["access.token.claim"] = "true" } }] }, cancellationToken: ct);
            await admin.Users.CreateUserAsync(upstreamRealm, new() { Username = "legacy-external", Enabled = true, FirstName = "External", LastName = "User", Email = "legacy-external@example.invalid", EmailVerified = true,
                Credentials = [new() { Type = "password", Value = secret, Temporary = false }] }, cancellationToken: ct);
            var externalUser = (await admin.Users.GetUsersAsync(upstreamRealm, username: "legacy-external", exact: true, cancellationToken: ct)).Body!.Single();
            var provider = new IdentityProviderRepresentation { Alias = alias, ProviderId = "oidc", Enabled = true, StoreToken = true, TrustEmail = true, AddReadTokenRoleOnCreate = false,
                Config = new() { ["clientId"] = "legacy-provider", ["clientSecret"] = secret, ["authorizationUrl"] = issuer.AbsoluteUri + "/protocol/openid-connect/auth",
                    ["tokenUrl"] = issuer.AbsoluteUri + "/protocol/openid-connect/token", ["userInfoUrl"] = issuer.AbsoluteUri + "/protocol/openid-connect/userinfo",
                    ["jwksUrl"] = issuer.AbsoluteUri + "/protocol/openid-connect/certs", ["useJwksUrl"] = "true", ["validateSignature"] = "true", ["issuer"] = issuer.AbsoluteUri } };
            await admin.IdentityProviders.CreateAsync(realm, provider, ct);
            await admin.User.AddFederatedIdentityAsync(realm, user.Id!, alias, new() { IdentityProvider = alias, UserId = externalUser.Id, UserName = externalUser.Username }, ct);
            var login = await OidcLoginTransaction.StartAsync(oidc, sourceAuth, redirect, options: new() { IdentityProvider = alias }, cancellationToken: ct);
            var callback = await ProtocolBrowserFixture.LoginAsync(login.AuthorizationUri, redirect, "legacy-external", secret, ct);
            var verified = await login.CompleteAsync(callback.Callback, sourceAuth, new(oidc, source.ClientId!), ct);
            string localAccess = Token(verified.Tokens);
            check(verified.Identity.Subject == user.Id && await Denied(() => broker.GetTokenLegacyAsync(alias, localAccess, ct)),
                "Legacy broker login preserves the linked local identity and refuses stored credentials without the user's broker read-token role");
            var brokerClient = (await admin.Clients.GetClientsAsync(realm, clientId: "broker", cancellationToken: ct)).Body!.Single();
            var readRole = (await admin.RoleContainer.GetRoleAsync(realm, brokerClient.Id!, "read-token", ct)).Body!;
            await admin.ClientRoleMappings.AddClientRoleMappingPOSTAdminRealmsRealmUsersUserIdRoleMappingsClientsClientIdAsync(realm, user.Id!, brokerClient.Id!, [readRole], ct);
            localAccess = Token(await oidc.RefreshAsync(sourceAuth, verified.Tokens.Json!.Value.GetProperty("refresh_token").GetString()!, cancellationToken: ct));
            var upstreamValidator = new KeycloakAccessTokenValidator(new OidcClient(new(http, server, upstreamRealm)), "legacy-provider");
            var externalCredentials = await broker.GetTokenLegacyAsync(alias, localAccess, ct); string externalAccess = Token(externalCredentials);
            check((await upstreamValidator.ValidateAsync(externalAccess, ct)).Subject == externalUser.Id,
                "Legacy broker read-token authorization retrieves a stored upstream credential independently verified against its own issuer and audience");
            var providerPermissions = (await admin.IdentityProvider.SetManagementPermissionsEnabledAsync(realm, alias, new() { Enabled = true }, ct)).Body!;
            string providerPermission = providerPermissions.ScopePermissions!["token-exchange"];
            check(await Denied(() => oidc.ExchangeLegacyAsync(sourceAuth, externalAccess, alias, cancellationToken: ct)),
                "Legacy external-to-internal exchange requires provider-specific FGAP v1 permission in addition to a valid external token");
            await SetPermission(providerPermission, true);
            var externalToLocal = await oidc.ExchangeLegacyAsync(sourceAuth, externalAccess, alias, cancellationToken: ct);
            check((await new KeycloakAccessTokenValidator(oidc, source.ClientId!).ValidateAsync(Token(externalToLocal), ct)).Subject == user.Id,
                "Legacy external-to-internal exchange verifies the real provider token and resolves the exact persisted linked local subject");
            string externalId = externalCredentials.Json!.Value.GetProperty("id_token").GetString()!;
            check((await new KeycloakAccessTokenValidator(oidc, source.ClientId!).ValidateAsync(Token(await oidc.ExchangeLegacyAsync(sourceAuth, externalId, alias, cancellationToken: ct, subjectTokenType: TokenExchangeSubjectTokenType.IdToken)), ct)).Subject == user.Id
                && (await new KeycloakAccessTokenValidator(oidc, source.ClientId!).ValidateAsync(Token(await oidc.ExchangeLegacyAsync(sourceAuth, externalAccess, alias, cancellationToken: ct, subjectTokenType: TokenExchangeSubjectTokenType.Jwt)), ct)).Subject == user.Id
                && await Denied(() => oidc.ExchangeLegacyAsync(sourceAuth, externalId[..^2] + "xx", alias, cancellationToken: ct, subjectTokenType: TokenExchangeSubjectTokenType.IdToken)),
                "Legacy external ID-token and JWT exchange verify the configured provider signature and reject a tampered external assertion");
            var localToExternal = await oidc.ExchangeLegacyAsync(sourceAuth, localAccess, requestedIssuer: alias, cancellationToken: ct);
            check((await upstreamValidator.ValidateAsync(Token(localToExternal), ct)).Subject == externalUser.Id,
                "Legacy internal-to-external exchange returns a credential for the independently verified linked upstream subject");
            await SetPermission(providerPermission, false);
            check(await Denied(() => oidc.ExchangeLegacyAsync(sourceAuth, externalAccess, alias, cancellationToken: ct))
                && await Denied(() => oidc.ExchangeLegacyAsync(sourceAuth, localAccess, requestedIssuer: alias, cancellationToken: ct)),
                "Revoking provider exchange permission immediately denies both directions without relying on subject-token expiry");
            await admin.ClientRoleMappings.DeleteClientRoleMappingDELETEAdminRealmsRealmUsersUserIdRoleMappingsClientsClientIdAsync(realm, user.Id!, brokerClient.Id!, [readRole], ct);
            string withoutRead = Token(await oidc.PasswordGrantAsync(sourceAuth, "legacy-user", secret, cancellationToken: ct));
            check(await Denied(() => broker.GetTokenLegacyAsync(alias, withoutRead, ct)),
                "Revoking the broker read-token role prevents stored credential retrieval with the user's next freshly issued token");
            provider.StoreToken = false; await admin.IdentityProvider.UpdateAsync(realm, alias, provider, ct);
            check(await Denied(() => broker.GetTokenLegacyAsync(alias, localAccess, ct)),
                "Disabling provider token storage immediately closes legacy credential retrieval even for a previously authorized access token");
        }
        finally { using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(30)); await admin.RealmAdmin.DeleteRealmAsync(upstreamRealm, cleanup.Token); }
        flags.Replace([]); int before = RecordingHandler.SentCount, reads = 0;
        var deniedAuth = OAuthClientAuthentication.SecretBasic(source.ClientId!, _ => { reads++; return ValueTask.FromResult(secret); });
        foreach (Func<Task> request in new Func<Task>[] { () => oidc.ExchangeLegacyAsync(deniedAuth, subject, cancellationToken: ct), () => oidc.ImpersonateLegacyAsync(deniedAuth, victim.Id!, cancellationToken: ct), () => broker.GetTokenLegacyAsync("upstream", subject, ct) })
        {
            try { await request(); throw new InvalidOperationException("Expected local legacy feature denial."); }
            catch (InvalidOperationException e) when (e.Message.StartsWith("Protocol disabled by host:", StringComparison.Ordinal)) { }
        }
        check(reads == 0 && before == RecordingHandler.SentCount, "Closing legacy host flags prevents every exchange impersonation and broker request before reading credentials or sending HTTP");
    }
}
