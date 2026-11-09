using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Protocols;

internal static class ProtocolOidcWorkflows
{
    internal static async Task RunAsync(KeycloakAdminClient admin, HttpClient http, Uri server, ProtocolTransport transport, string realm, string secret,
        Action<bool, string> check, CancellationToken ct)
    {
        var oidc = new OidcClient(transport); var redirect = new Uri("https://app.invalid/callback");
        await admin.Clients.CreateClientAsync(realm, new ClientRepresentation { ClientId = "browser-app", Protocol = "openid-connect", PublicClient = true,
            Enabled = true, StandardFlowEnabled = true, RedirectUris = [redirect.AbsoluteUri], Attributes = new() { ["pkce.code.challenge.method"] = "S256" } }, cancellationToken: ct);
        var client = OAuthClientAuthentication.Public("browser-app");
        var transaction = new OidcLoginTransaction(oidc, "browser-app", redirect);
        var login = await ProtocolBrowserFixture.LoginAsync(transaction.AuthorizationUri, redirect, "account-user", secret, ct);
        var verified = await transaction.CompleteAsync(login.Callback, client, new(oidc, "browser-app"), ct);
        check(verified.Identity.Subject.Length > 0 && verified.Identity.Claims["preferred_username"].ToString() == "account-user", "Browser authorization code PKCE state nonce and ID token signature validation succeed");
        bool replayDenied = false;
        try { await transaction.CompleteAsync(login.Callback, client, new(oidc, "browser-app"), ct); }
        catch (InvalidDataException) { replayDenied = true; }
        check(replayDenied, "A browser callback transaction cannot be redeemed twice");
        string refresh = verified.Tokens.Json!.Value.GetProperty("refresh_token").GetString()!;
        var refreshed = await oidc.RefreshAsync(client, refresh, cancellationToken: ct);
        string rotated = refreshed.Json!.Value.GetProperty("refresh_token").GetString()!;
        check((await oidc.GetUserInfoAsync(refreshed.Json.Value.GetProperty("access_token").GetString()!, ct)).Json!.Value.GetProperty("sub").GetString() == verified.Identity.Subject,
            "Refresh and userinfo preserve the authenticated subject");
        await oidc.LogoutAsync(client, rotated, ct);
        bool logoutDenied = false;
        try { await oidc.RefreshAsync(client, rotated, cancellationToken: ct); }
        catch (KeycloakProtocolException e) when (e.Error == OAuthError.InvalidGrant) { logoutDenied = true; }
        check(logoutDenied, "Refresh-token logout invalidates the server session");
        var parTransaction = new OidcLoginTransaction(oidc, "browser-app", redirect);
        var pushed = await oidc.PushAuthorizationAsync(client, parTransaction.AuthorizationUri, ct);
        var parLogin = await ProtocolBrowserFixture.LoginAsync(oidc.CreatePushedAuthorizationUri("browser-app", pushed), redirect, "account-user", secret, ct);
        var parResult = await parTransaction.CompleteAsync(parLogin.Callback, client, new(oidc, "browser-app"), ct);
        check(parResult.Identity.Subject == verified.Identity.Subject, "Pushed authorization request completes with the original PKCE state and nonce");
        string revokedRefreshToken = parResult.Tokens.Json!.Value.GetProperty("refresh_token").GetString()!;
        await oidc.RevokeAsync(client, revokedRefreshToken, ct);
        bool refreshRevoked = false;
        try { await oidc.RefreshAsync(client, revokedRefreshToken, cancellationToken: ct); }
        catch (KeycloakProtocolException e) when (e.Error == OAuthError.InvalidGrant) { refreshRevoked = true; }
        check(refreshRevoked, "OIDC revocation invalidates the real refresh credential and prevents a subsequent refresh");

        await admin.RealmAdmin.UpdateRealmAsync(realm, new() { AdminPermissionsEnabled = true }, ct);
        await admin.Clients.CreateClientAsync(realm, new ClientRepresentation { ClientId = "subject-app", Protocol = "openid-connect", PublicClient = true,
            Enabled = true, StandardFlowEnabled = true, ConsentRequired = true, RedirectUris = [redirect.AbsoluteUri], Attributes = new() { ["pkce.code.challenge.method"] = "S256" },
            ProtocolMappers = [new ProtocolMapperRepresentation { Name = "verification-audience", Protocol = "openid-connect", ProtocolMapper = "oidc-audience-mapper",
                Config = new() { ["included.client.audience"] = "sdk-protocols", ["access.token.claim"] = "true", ["introspection.token.claim"] = "true" } },
                new ProtocolMapperRepresentation { Name = "actor-audience", Protocol = "openid-connect", ProtocolMapper = "oidc-audience-mapper",
                Config = new() { ["included.client.audience"] = "actor-app", ["access.token.claim"] = "true" } }] }, cancellationToken: ct);
        await admin.Clients.CreateClientAsync(realm, new ClientRepresentation { ClientId = "actor-app", Protocol = "openid-connect", PublicClient = false,
            Enabled = true, Secret = secret, ServiceAccountsEnabled = true, DirectAccessGrantsEnabled = true, Attributes = new() { ["standard.token.exchange.enabled"] = "true" },
            ProtocolMappers = [new ProtocolMapperRepresentation { Name = "subject-audience", Protocol = "openid-connect", ProtocolMapper = "oidc-audience-mapper",
                Config = new() { ["included.client.audience"] = "subject-app", ["access.token.claim"] = "true", ["introspection.token.claim"] = "true" } },
                new ProtocolMapperRepresentation { Name = "verification-audience", Protocol = "openid-connect", ProtocolMapper = "oidc-audience-mapper",
                Config = new() { ["included.client.audience"] = "sdk-protocols", ["access.token.claim"] = "true", ["introspection.token.claim"] = "true" } }] }, cancellationToken: ct);
        var actor = (await admin.Clients.GetClientsAsync(realm, clientId: "actor-app", cancellationToken: ct)).Body!.Single();
        var actorUser = (await admin.Client.GetServiceAccountUserAsync(realm, actor.Id!, ct)).Body!;
        var authz = (await admin.Clients.GetClientsAsync(realm, clientId: "admin-permissions", cancellationToken: ct)).Body!.Single();
        string policyPath = "/admin/realms/" + realm + "/clients/" + authz.Id + "/authz/resource-server";
        async Task<JsonNode?> Post(string path, JsonNode body)
        {
            var response = await admin.SendAsync(HttpMethod.Post, policyPath + path, content: new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json"), cancellationToken: ct);
            return response.Content.IsEmpty ? null : JsonNode.Parse(response.Content.Span);
        }
        var policy = await Post("/policy/client", new JsonObject { ["name"] = "sdk-actor-policy", ["logic"] = "POSITIVE", ["clients"] = new JsonArray(actor.Id) });
        var permission = await Post("/permission/scope", new JsonObject { ["name"] = "sdk-delegate-users", ["resourceType"] = "Users", ["scopes"] = new JsonArray("delegate"),
            ["policies"] = new JsonArray(policy!["id"]!.GetValue<string>()) });
        var subjectClient = OAuthClientAuthentication.Public("subject-app");
        var delegation = new OidcLoginTransaction(oidc, "subject-app", redirect, "openid delegation:client:actor-app");
        var subjectLogin = await ProtocolBrowserFixture.LoginAsync(delegation.AuthorizationUri, redirect, "account-user", secret, ct);
        var subject = await delegation.CompleteAsync(subjectLogin.Callback, subjectClient, new(oidc, "subject-app"), ct);
        var actorAuth = OAuthClientAuthentication.SecretBasic("actor-app", _ => ValueTask.FromResult(secret));
        string subjectToken = subject.Tokens.Json!.Value.GetProperty("access_token").GetString()!;
        var actorToken = (await oidc.ClientCredentialsAsync(actorAuth, cancellationToken: ct)).Json!.Value.GetProperty("access_token").GetString()!;
        // Introspection verifies the signed token at Keycloak; raw local JWT decoding is never treated as verification.
        var subjectInfo = (await oidc.IntrospectAsync(actorAuth, subjectToken, ct)).Json!.Value;
        check(subjectLogin.Consented && subjectInfo.GetProperty("active").GetBoolean() && subjectInfo.GetProperty("may_act").GetProperty("sub").GetString() == actorUser.Id,
            "Client delegation requires real user consent and issues may_act for the FGAP v2 authorized actor");
        var exchange = await oidc.ExchangeDelegatedAsync(actorAuth, subjectToken, actorToken, cancellationToken: ct);
        string delegatedToken = exchange.Json!.Value.GetProperty("access_token").GetString()!;
        // The actor's explicitly configured verification audience can introspect the signed delegated token.
        var delegated = (await oidc.IntrospectAsync(OAuthClientAuthentication.SecretBasic("sdk-protocols", _ => ValueTask.FromResult(secret)), delegatedToken, ct)).Json!.Value;
        check(!exchange.Json.Value.TryGetProperty("refresh_token", out _) && delegated.GetProperty("sub").GetString() == subject.Identity.Subject
            && delegated.GetProperty("act").GetProperty("client_id").GetString() == "actor-app", "Delegated exchange preserves the subject and records act without a refresh token");
        bool ordinaryDenied = false;
        try { await oidc.ExchangeAsync(actorAuth, subjectToken, cancellationToken: ct); }
        catch (KeycloakProtocolException e) when (e.Error == OAuthError.InvalidRequest) { ordinaryDenied = true; }
        check(ordinaryDenied, "Standard exchange rejects may_act tokens and cannot bypass delegation");
        var delegatedAdmin = new KeycloakAdminClient(http, server, new StaticAccessTokenProvider(delegatedToken));
        bool adminDenied = false;
        try { await delegatedAdmin.Users.GetUsersAsync(realm, cancellationToken: ct); }
        catch (KeycloakAdminException e) when (e.StatusCode == HttpStatusCode.Forbidden) { adminDenied = true; }
        check(adminDenied, "Client delegated tokens cannot call Admin APIs");
        await admin.SendAsync(HttpMethod.Delete, policyPath + "/permission/" + permission!["id"]!.GetValue<string>(), cancellationToken: ct);
        var revokedRefresh = await oidc.RefreshAsync(subjectClient, subject.Tokens.Json.Value.GetProperty("refresh_token").GetString()!, cancellationToken: ct);
        string refreshedSubjectToken = revokedRefresh.Json!.Value.GetProperty("access_token").GetString()!;
        var revokedInfo = (await oidc.IntrospectAsync(OAuthClientAuthentication.SecretBasic("sdk-protocols", _ => ValueTask.FromResult(secret)), refreshedSubjectToken, ct)).Json!.Value;
        check(revokedInfo.GetProperty("active").GetBoolean() && !revokedInfo.TryGetProperty("may_act", out _), "Revoking FGAP v2 delegation strips may_act when the subject token is refreshed");
        bool revokedDenied = false;
        try { await oidc.ExchangeDelegatedAsync(actorAuth, refreshedSubjectToken, actorToken, cancellationToken: ct); }
        catch (KeycloakProtocolException e) when (e.Error is OAuthError.AccessDenied or OAuthError.InvalidRequest) { revokedDenied = true; }
        check(revokedDenied, "The refreshed subject token cannot delegate after FGAP v2 permission revocation");
        var ordinaryTransaction = new OidcLoginTransaction(oidc, "subject-app", redirect);
        var ordinaryBrowser = await ProtocolBrowserFixture.LoginAsync(ordinaryTransaction.AuthorizationUri, redirect, "account-user", secret, ct);
        var ordinary = await ordinaryTransaction.CompleteAsync(ordinaryBrowser.Callback, subjectClient, new(oidc, "subject-app"), ct);
        var standard = await oidc.ExchangeAsync(actorAuth, ordinary.Tokens.Json!.Value.GetProperty("access_token").GetString()!, "sdk-protocols", "openid", ct);
        var standardIdentity = await new KeycloakAccessTokenValidator(oidc, "sdk-protocols").ValidateAsync(standard.Json!.Value.GetProperty("access_token").GetString()!, ct);
        check(standardIdentity.Subject == ordinary.Identity.Subject && standardIdentity.Claims.GetProperty("azp").GetString() == "actor-app" && !standardIdentity.Claims.TryGetProperty("act", out _),
            "Standard exchange issues an independently signature-verified audience-narrowed token for the original subject without inventing an actor");
        string ordinaryAccess = ordinary.Tokens.Json.Value.GetProperty("access_token").GetString()!;
        var idExchange = await oidc.ExchangeAsync(actorAuth, ordinaryAccess, scope: "openid", cancellationToken: ct, requestedTokenType: TokenExchangeRequestedTokenType.IdToken);
        var exchangedId = await new OidcTokenValidator(oidc, "actor-app").ValidateExchangedIdTokenAsync(idExchange.Json!.Value.GetProperty("access_token").GetString()!, ct);
        check(exchangedId.Subject == ordinary.Identity.Subject && idExchange.Json.Value.GetProperty("issued_token_type").GetString() == "urn:ietf:params:oauth:token-type:id_token"
            && idExchange.Json.Value.GetProperty("token_type").GetString() == "N_A",
            "Standard ID-token exchange validates its signed issuer audience lifetime and original subject without treating the exchanged identity as a browser login");
        bool refreshExchangeDenied = false;
        try { await oidc.ExchangeAsync(actorAuth, ordinaryAccess, cancellationToken: ct, requestedTokenType: TokenExchangeRequestedTokenType.RefreshToken); }
        catch (KeycloakProtocolException e) when (e.Error == OAuthError.InvalidRequest) { refreshExchangeDenied = true; }
        check(refreshExchangeDenied, "Standard refresh-token exchange refuses issuance before the requesting client explicitly enables this response type");
        actor.Attributes!["standard.token.exchange.enableRefreshRequestedTokenType"] = "SAME_SESSION"; await admin.Client.UpdateAsync(realm, actor.Id!, actor, ct);
        var refreshExchange = await oidc.ExchangeAsync(actorAuth, ordinaryAccess, "sdk-protocols", cancellationToken: ct, requestedTokenType: TokenExchangeRequestedTokenType.RefreshToken);
        var refreshedExchange = await oidc.RefreshAsync(actorAuth, refreshExchange.Json!.Value.GetProperty("refresh_token").GetString()!, cancellationToken: ct);
        check((await new KeycloakAccessTokenValidator(oidc, "sdk-protocols").ValidateAsync(refreshedExchange.Json!.Value.GetProperty("access_token").GetString()!, ct)).Subject == ordinary.Identity.Subject,
            "Explicitly enabled standard refresh-token exchange issues a usable client-bound refresh credential for the original online user session");
        await admin.Users.CreateUserAsync(realm, new UserRepresentation { Username = "delegate-admin", Enabled = true, FirstName = "Delegate", LastName = "Administrator", Email = "delegate-admin@example.invalid", EmailVerified = true,
            Credentials = [new CredentialRepresentation { Type = "password", Value = secret, Temporary = false }] }, cancellationToken: ct);
        var administrator = (await admin.Users.GetUsersAsync(realm, username: "delegate-admin", exact: true, cancellationToken: ct)).Body!.Single();
        var administratorPolicy = await Post("/policy/user", new JsonObject { ["name"] = "sdk-administrator-delegate-policy", ["logic"] = "POSITIVE", ["users"] = new JsonArray(administrator.Id) });
        var administratorPermission = await Post("/permission/scope", new JsonObject { ["name"] = "sdk-administrator-delegate-users", ["resourceType"] = "Users", ["scopes"] = new JsonArray("delegate"),
            ["policies"] = new JsonArray(administratorPolicy!["id"]!.GetValue<string>()) });
        var administratorSubject = new OidcLoginTransaction(oidc, "subject-app", redirect, "openid delegation:user:delegate-admin");
        var administratorConsent = await ProtocolBrowserFixture.LoginAsync(administratorSubject.AuthorizationUri, redirect, "account-user", secret, ct);
        var consentedSubject = await administratorSubject.CompleteAsync(administratorConsent.Callback, subjectClient, new(oidc, "subject-app"), ct);
        string userActorToken = (await oidc.PasswordGrantAsync(actorAuth, "delegate-admin", secret, scope: "openid", cancellationToken: ct)).Json!.Value.GetProperty("access_token").GetString()!;
        string userSubjectToken = consentedSubject.Tokens.Json!.Value.GetProperty("access_token").GetString()!;
        var userDelegation = await oidc.ExchangeDelegatedAsync(actorAuth, userSubjectToken, userActorToken, cancellationToken: ct);
        var userDelegated = await new KeycloakAccessTokenValidator(oidc, "sdk-protocols").ValidateAsync(userDelegation.Json!.Value.GetProperty("access_token").GetString()!, ct);
        check(administratorConsent.Consented && userDelegated.Subject == subject.Identity.Subject && userDelegated.Claims.GetProperty("act").GetProperty("sub").GetString() == administrator.Id
            && !userDelegation.Json.Value.TryGetProperty("refresh_token", out _), "Administrator delegation enforces real user consent and the FGAP-authorized human actor while preserving the subject");
        bool wrongActor = false;
        try { await oidc.ExchangeDelegatedAsync(actorAuth, userSubjectToken, actorToken, cancellationToken: ct); }
        catch (KeycloakProtocolException e) when (e.Error == OAuthError.InvalidRequest) { wrongActor = true; }
        await admin.SendAsync(HttpMethod.Delete, policyPath + "/permission/" + administratorPermission!["id"]!.GetValue<string>(), cancellationToken: ct);
        var updatedUserSubject = await oidc.RefreshAsync(subjectClient, consentedSubject.Tokens.Json.Value.GetProperty("refresh_token").GetString()!, cancellationToken: ct);
        var updatedIdentity = await new KeycloakAccessTokenValidator(oidc, "sdk-protocols").ValidateAsync(updatedUserSubject.Json!.Value.GetProperty("access_token").GetString()!, ct);
        check(wrongActor && !updatedIdentity.Claims.TryGetProperty("may_act", out _), "Administrator delegation rejects an unrelated actor and removes delegation authority on refresh after permission revocation");
    }
}
