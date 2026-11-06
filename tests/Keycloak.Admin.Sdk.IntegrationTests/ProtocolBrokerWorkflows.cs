using System.Net;
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Protocols;

internal static class ProtocolBrokerWorkflows
{
    internal static async Task RunAsync(KeycloakAdminClient admin, HttpClient http, Uri server, ProtocolTransport transport, string realm, string secret, Action<bool, string> check, CancellationToken ct)
    {
        string upstreamRealm = realm + "-upstream", alias = "upstream";
        var issuer = new Uri(server, "realms/" + upstreamRealm); string internalIssuer = "http://127.0.0.1:8080/realms/" + upstreamRealm;
        await admin.RealmsAdmin.ImportRealmAsync(new StringContent(System.Text.Json.JsonSerializer.Serialize(new RealmRepresentation { Realm = upstreamRealm, Enabled = true,
            Attributes = new() { ["frontendUrl"] = server.AbsoluteUri } }, KeycloakJsonContext.Default.RealmRepresentation), System.Text.Encoding.UTF8, "application/json"), cancellationToken: ct);
        try
        {
            await admin.Clients.CreateClientAsync(upstreamRealm, new ClientRepresentation { ClientId = "broker-upstream", Protocol = "openid-connect", Enabled = true, PublicClient = false,
                Secret = secret, StandardFlowEnabled = true, RedirectUris = [new Uri(server, "realms/" + realm + "/broker/" + alias + "/endpoint").AbsoluteUri],
                ProtocolMappers = [new ProtocolMapperRepresentation { Name = "upstream-audience", Protocol = "openid-connect", ProtocolMapper = "oidc-audience-mapper",
                    Config = new() { ["included.client.audience"] = "broker-upstream", ["access.token.claim"] = "true" } }] }, cancellationToken: ct);
            await admin.Users.CreateUserAsync(upstreamRealm, new UserRepresentation { Username = "upstream-user", FirstName = "Upstream", LastName = "User", Email = "upstream@example.invalid", EmailVerified = true,
                Enabled = true, Credentials = [new CredentialRepresentation { Type = "password", Value = secret, Temporary = false }] }, cancellationToken: ct);
            var upstreamUser = (await admin.Users.GetUsersAsync(upstreamRealm, username: "upstream-user", exact: true, cancellationToken: ct)).Body!.Single();
            var localUser = (await admin.Users.GetUsersAsync(realm, username: "account-user", exact: true, cancellationToken: ct)).Body!.Single();
            await admin.IdentityProviders.CreateAsync(realm, new IdentityProviderRepresentation { Alias = alias, ProviderId = "oidc", Enabled = true, StoreToken = true, TrustEmail = true,
                Config = new() { ["clientId"] = "broker-upstream", ["clientSecret"] = secret, ["authorizationUrl"] = issuer.AbsoluteUri + "/protocol/openid-connect/auth",
                    ["tokenUrl"] = internalIssuer + "/protocol/openid-connect/token", ["userInfoUrl"] = internalIssuer + "/protocol/openid-connect/userinfo",
                    ["jwksUrl"] = internalIssuer + "/protocol/openid-connect/certs", ["useJwksUrl"] = "true", ["issuer"] = issuer.AbsoluteUri } }, ct);
            await admin.User.AddFederatedIdentityAsync(realm, localUser.Id!, alias, new FederatedIdentityRepresentation { IdentityProvider = alias, UserId = upstreamUser.Id, UserName = "upstream-user" }, ct);
            var redirect = new Uri("https://app.invalid/broker-callback");
            await admin.Clients.CreateClientAsync(realm, new ClientRepresentation { ClientId = "broker-reader", Protocol = "openid-connect", Enabled = true, PublicClient = false, Secret = secret,
                StandardFlowEnabled = true, RedirectUris = [redirect.AbsoluteUri], Attributes = new() { ["external.token.enabled"] = "true", ["external.token.idp"] = alias, ["pkce.code.challenge.method"] = "S256" } }, cancellationToken: ct);
            var oidc = new OidcClient(transport); var auth = OAuthClientAuthentication.SecretBasic("broker-reader", _ => ValueTask.FromResult(secret));
            var transaction = new OidcLoginTransaction(oidc, "broker-reader", redirect, options: new() { IdentityProvider = alias });
            var browser = await ProtocolBrowserFixture.LoginAsync(transaction.AuthorizationUri, redirect, "upstream-user", secret, ct);
            var verified = await transaction.CompleteAsync(browser.Callback, auth, new(oidc, "broker-reader"), ct);
            check(verified.Identity.Subject == localUser.Id && (await admin.User.GetFederatedIdentityAsync(realm, localUser.Id!, ct)).Body!.Any(i => i.IdentityProvider == alias && i.UserId == upstreamUser.Id),
                "Broker login validates the downstream ID token and retains the exact upstream linked identity");
            string access = verified.Tokens.Json!.Value.GetProperty("access_token").GetString()!;
            var broker = new IdentityBrokerClient(transport);
            var external = (await broker.GetTokenAsync(alias, auth, access, ct)).Json!.Value;
            var upstreamValidator = new KeycloakAccessTokenValidator(new OidcClient(new(http, server, upstreamRealm)), "broker-upstream");
            var upstreamAccess = await upstreamValidator.ValidateAsync(external.GetProperty("access_token").GetString()!, ct);
            check(upstreamAccess.Subject == upstreamUser.Id && upstreamAccess.Issuer == issuer.AbsoluteUri, "Broker v2 returns an upstream credential independently verified against its own issuer audience and signing keys");
            bool badClient = false, badUser = false, badProvider = false;
            try { await broker.GetTokenAsync(alias, OAuthClientAuthentication.SecretBasic("broker-reader", _ => ValueTask.FromResult("wrong-secret")), access, ct); }
            catch (KeycloakProtocolException e) when (e.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.BadRequest) { badClient = true; }
            try { await broker.GetTokenAsync(alias, auth, "invalid-user-token", ct); }
            catch (KeycloakProtocolException e) when (e.StatusCode == HttpStatusCode.BadRequest) { badUser = true; }
            try { await broker.GetTokenAsync("unapproved-provider", auth, access, ct); }
            catch (KeycloakProtocolException e) when (e.StatusCode == HttpStatusCode.Forbidden) { badProvider = true; }
            check(badClient && badUser && badProvider, "Broker v2 requires independent client authentication a valid user token and an explicitly approved identity provider");
            var reader = (await admin.Clients.GetClientsAsync(realm, clientId: "broker-reader", cancellationToken: ct)).Body!.Single(); reader.Attributes!["external.token.enabled"] = "false";
            await admin.Client.UpdateAsync(realm, reader.Id!, reader, ct);
            bool disabled = false;
            try { await broker.GetTokenAsync(alias, auth, access, ct); }
            catch (KeycloakProtocolException e) when (e.StatusCode == HttpStatusCode.Forbidden) { disabled = true; }
            check(disabled, "Disabling broker external-token access takes effect for the next request even with an existing user token");
            await admin.User.RemoveFederatedIdentityAsync(realm, localUser.Id!, alias, ct);
            check(!(await admin.User.GetFederatedIdentityAsync(realm, localUser.Id!, ct)).Body!.Any(i => i.IdentityProvider == alias), "Broker linked identity cleanup removes the upstream association");
            reader.Attributes!["external.token.enabled"] = "true"; await admin.Client.UpdateAsync(realm, reader.Id!, reader, ct);
            await admin.Users.CreateUserAsync(realm, new UserRepresentation { Username = "link-user", Enabled = true, FirstName = "Link", LastName = "User", Email = "link@example.invalid", EmailVerified = true,
                Credentials = [new() { Type = "password", Value = secret, Temporary = false }] }, cancellationToken: ct);
            var linkUser = (await admin.Users.GetUsersAsync(realm, username: "link-user", exact: true, cancellationToken: ct)).Body!.Single();
            using var linkHandler = new HttpClientHandler { AllowAutoRedirect = false, UseCookies = true }; using var linkBrowser = new HttpClient(linkHandler);
            var initialLogin = await OidcLoginTransaction.StartAsync(oidc, auth, redirect, cancellationToken: ct);
            var localLogin = await ProtocolBrowserFixture.LoginAsync(initialLogin.AuthorizationUri, redirect, "link-user", secret, ct, linkBrowser);
            if ((await initialLogin.CompleteAsync(localLogin.Callback, auth, new(oidc, "broker-reader"), ct)).Identity.Subject != linkUser.Id) throw new InvalidDataException("Wrong initial account-linking identity.");
            var cancelledLink = await OidcLoginTransaction.StartAsync(oidc, auth, redirect, options: new() { Action = "idp_link:" + alias }, cancellationToken: ct);
            var cancelledCallback = await ProtocolBrowserFixture.DenyConsentAsync(cancelledLink.AuthorizationUri, redirect, "link-user", secret, ct, linkBrowser);
            var stillLocal = await cancelledLink.CompleteAsync(cancelledCallback, auth, new(oidc, "broker-reader"), ct);
            check(stillLocal.Identity.Subject == linkUser.Id && !(await admin.User.GetFederatedIdentityAsync(realm, linkUser.Id!, ct)).Body!.Any(i => i.IdentityProvider == alias),
                "Application-initiated broker linking respects explicit user cancellation and leaves the authenticated local identity unlinked");
            var approvedLink = await OidcLoginTransaction.StartAsync(oidc, auth, redirect, options: new() { Action = "idp_link:" + alias }, cancellationToken: ct);
            var approvedCallback = await ProtocolBrowserFixture.LoginAsync(approvedLink.AuthorizationUri, redirect, "upstream-user", secret, ct, linkBrowser);
            var linkedLogin = await approvedLink.CompleteAsync(approvedCallback.Callback, auth, new(oidc, "broker-reader"), ct);
            check(approvedCallback.Consented && linkedLogin.Identity.Subject == linkUser.Id
                && (await admin.User.GetFederatedIdentityAsync(realm, linkUser.Id!, ct)).Body!.Any(i => i.IdentityProvider == alias && i.UserId == upstreamUser.Id),
                "Application-initiated broker linking requires actual confirmation and upstream login while preserving the signed local subject and exact external association");
            string linkedAccess = linkedLogin.Tokens.Json!.Value.GetProperty("access_token").GetString()!;
            var linkedExternal = (await broker.GetTokenAsync(alias, auth, linkedAccess, ct)).Json!.Value;
            check((await upstreamValidator.ValidateAsync(linkedExternal.GetProperty("access_token").GetString()!, ct)).Subject == upstreamUser.Id,
                "A user-linked broker credential belongs to the independently verified upstream identity rather than replacing the local application subject");
            await new AccountClient(transport).UnlinkAccountAsync(alias, linkedAccess, ct); bool unlinked = false;
            try { await broker.GetTokenAsync(alias, auth, linkedAccess, ct); } catch (KeycloakProtocolException e) when (e.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.NotFound or HttpStatusCode.Forbidden) { unlinked = true; }
            check(unlinked && !(await admin.User.GetFederatedIdentityAsync(realm, linkUser.Id!, ct)).Body!.Any(i => i.IdentityProvider == alias),
                "Account self-service unlink removes the persisted external association and immediately prevents retrieval with the existing local access token");
        }
        finally { using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(30)); await admin.RealmAdmin.DeleteRealmAsync(upstreamRealm, cleanup.Token); }
    }
}
