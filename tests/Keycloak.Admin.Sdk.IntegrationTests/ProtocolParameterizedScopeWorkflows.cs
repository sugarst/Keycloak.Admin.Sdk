using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Protocols;

internal static class ProtocolParameterizedScopeWorkflows
{
    internal static async Task RunAsync(KeycloakAdminClient admin, ProtocolTransport transport, string realm, string secret, Action<bool, string> check, CancellationToken ct)
    {
        var oidc = new OidcClient(transport); var callback = new Uri("https://scopes.invalid/callback");
        var created = await admin.ClientScopes.CreateClientScopeAsync(realm, new ClientScopeRepresentation { Name = "sdk-project", Protocol = "openid-connect",
            Attributes = new() { ["is.parameterized.scope"] = "true", ["parameterized.scope.type"] = "custom", ["parameterized.scope.regexp"] = "alpha|beta", ["parameterized.scope.repeatable"] = "false", ["display.on.consent.screen"] = "true", ["include.in.token.scope"] = "true" },
            ProtocolMappers = [new() { Name = "project", Protocol = "openid-connect", ProtocolMapper = "oidc-parameterized-scope-mapper", Config = new() { ["claim.name"] = "project", ["jsonType.label"] = "String", ["access.token.claim"] = "true", ["id.token.claim"] = "true" } }] }, ct);
        string scopeId = created.Location!.Segments.Last().Trim('/');
        await admin.Clients.CreateClientAsync(realm, new ClientRepresentation { ClientId = "scope-client", Protocol = "openid-connect", Enabled = true, PublicClient = false, Secret = secret,
            StandardFlowEnabled = true, ConsentRequired = true, ServiceAccountsEnabled = true, RedirectUris = [callback.AbsoluteUri], ProtocolMappers = [new() { Name = "audience", Protocol = "openid-connect", ProtocolMapper = "oidc-audience-mapper", Config = new() { ["included.client.audience"] = "scope-client", ["access.token.claim"] = "true" } }] }, cancellationToken: ct);
        var client = (await admin.Clients.GetClientsAsync(realm, clientId: "scope-client", cancellationToken: ct)).Body!.Single();
        await admin.Client.AddOptionalClientScopeAsync(realm, client.Id!, scopeId, ct); var auth = OAuthClientAuthentication.SecretBasic("scope-client", _ => ValueTask.FromResult(secret));
        var transaction = await OidcLoginTransaction.StartAsync(oidc, "scope-client", callback, options: new() { ParameterizedScopes = [new("sdk-project", "alpha")] }, cancellationToken: ct);
        var browser = await ProtocolBrowserFixture.LoginAsync(transaction.AuthorizationUri, callback, "account-user", secret, ct);
        var login = await transaction.CompleteAsync(browser.Callback, auth, new(oidc, "scope-client"), ct);
        var token = await new KeycloakAccessTokenValidator(oidc, "scope-client").ValidateAsync(login.Tokens.Json!.Value.GetProperty("access_token").GetString()!, ct);
        check(browser.Consented && token.Claims.GetProperty("project").GetString() == "alpha" && token.Claims.GetProperty("scope").GetString()!.Split(' ').Contains("sdk-project:alpha"),
            "Parameterized browser scopes require actual user consent and preserve the allowed parameter in a verified token claim and scope");
        bool invalid = false, repeated = false;
        try { await oidc.ClientCredentialsWithParameterizedScopesAsync(auth, [new("sdk-project", "forbidden")], cancellationToken: ct); } catch (KeycloakProtocolException e) when (e.Error == OAuthError.InvalidScope) { invalid = true; }
        try { await oidc.ClientCredentialsWithParameterizedScopesAsync(auth, [new("sdk-project", "alpha"), new("sdk-project", "beta")], cancellationToken: ct); } catch (KeycloakProtocolException e) when (e.Error == OAuthError.InvalidScope) { repeated = true; }
        check(invalid && repeated, "Parameterized scopes reject parameters outside the server regex and conflicting values for a non-repeatable scope");
        var configuredScope = (await admin.ClientScope.GetClientScopeAsync(realm, scopeId, ct)).Body!; configuredScope.Attributes!["parameterized.scope.repeatable"] = "true";
        await admin.ClientScope.UpdateAsync(realm, scopeId, configuredScope, ct);
        var repeatable = await oidc.ClientCredentialsWithParameterizedScopesAsync(auth, [new("sdk-project", "alpha"), new("sdk-project", "beta")], cancellationToken: ct);
        var repeatedClaims = (await new KeycloakAccessTokenValidator(oidc, "scope-client").ValidateAsync(repeatable.Json!.Value.GetProperty("access_token").GetString()!, ct)).Claims;
        check(repeatedClaims.GetProperty("project").EnumerateArray().Select(p => p.GetString()).ToHashSet(StringComparer.Ordinal).SetEquals(["alpha", "beta"]),
            "Explicitly repeatable parameterized scopes preserve both authorized values in the verified multivalued claim");
        await admin.Client.RemoveOptionalClientScopeAsync(realm, client.Id!, scopeId, ct); bool removed = false;
        try { await oidc.ClientCredentialsWithParameterizedScopesAsync(auth, [new("sdk-project", "alpha")], cancellationToken: ct); } catch (KeycloakProtocolException e) when (e.Error == OAuthError.InvalidScope) { removed = true; }
        check(removed, "Removing a parameterized client-scope assignment prevents its next use");
    }
}
