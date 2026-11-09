using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Protocols;

internal static class FeatureOid4vcWorkflows
{
    internal static async Task RunAsync(KeycloakAdminClient wire, KeycloakAdminClient sdk, HttpClient http, Uri server, string realm, Action<string, int, string> proof, CancellationToken ct)
    {
        const string scopeName = "feature-credential", clientId = "feature-wallet", username = "credential-user";
        string password = Convert.ToHexString(RandomNumberGenerator.GetBytes(24)) + "aA1!";
        void Require(bool condition, string description) { if (!condition) throw new InvalidDataException("Credential Admin business verification failed: " + description); }
        void Proof(string operation, AdminResponse<JsonElement> response, string description) => proof("UserVerifiableCredential." + operation + "Async", (int)response.StatusCode, description);
        HttpContent Body(JsonObject json) => new StringContent(json.ToJsonString(), Encoding.UTF8, "application/json");
        await using var smtp = new ProtocolSmtpReceiver();
        await wire.RealmAdmin.UpdateRealmAsync(realm, new() { VerifiableCredentialsEnabled = true, SmtpServer = new() { ["host"] = "127.0.0.1", ["port"] = ProtocolSmtpReceiver.Port.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["from"] = "issuer@example.invalid", ["ssl"] = "false", ["starttls"] = "false", ["auth"] = "false" } }, ct);
        var transport = new ProtocolTransport(http, server, realm); var oidc = new OidcClient(transport); var wallet = new Oid4vcIssuerClient(transport);
        await wire.ClientScopes.CreateClientScopeAsync(realm, new() { Name = scopeName, Protocol = "oid4vc", Attributes = new()
            { ["include.in.token.scope"] = "true", ["vc.credential_configuration_id"] = scopeName, ["vc.credential_identifier"] = scopeName, ["vc.format"] = "jwt_vc_json",
                ["vc.issuer_did"] = wallet.Issuer.AbsoluteUri, ["vc.verifiable_credential_type"] = "https://credentials.example.invalid/feature", ["vc.expiry_in_seconds"] = "3600", ["vc.binding_required"] = "false", ["vc.credential_signing_alg"] = "RS256" },
            ProtocolMappers = [new() { Name = "email", Protocol = "oid4vc", ProtocolMapper = "oid4vc-user-attribute-mapper", Config = new() { ["claim.name"] = "email", ["userAttribute"] = "email" } }] }, ct);
        var scope = (await wire.ClientScopes.GetClientScopesAsync(realm, ct)).Body!.Single(s => s.Name == scopeName);
        var callback = new Uri("https://app.invalid/feature-credential");
        await wire.Clients.CreateClientAsync(realm, new() { ClientId = clientId, Enabled = true, PublicClient = true, Protocol = "openid-connect", StandardFlowEnabled = true, DirectAccessGrantsEnabled = true,
            RedirectUris = [callback.AbsoluteUri], Attributes = new() { ["oid4vci.enabled"] = "true", ["pkce.code.challenge.method"] = "S256" } }, cancellationToken: ct);
        var client = (await wire.Clients.GetClientsAsync(realm, clientId: clientId, cancellationToken: ct)).Body!.Single();
        await wire.Client.AddOptionalClientScopeAsync(realm, client.Id!, scope.Id!, ct);
        await wire.Users.CreateUserAsync(realm, new() { Username = username, Enabled = true, Email = "credential-user@example.invalid", EmailVerified = true, FirstName = "Before", LastName = "User",
            Credentials = [new() { Type = "password", Value = password, Temporary = false }] }, cancellationToken: ct);
        string userId = (await wire.Users.GetUsersAsync(realm, username: username, exact: true, cancellationToken: ct)).Body!.Single().Id!;
        var created = await sdk.UserVerifiableCredential.CreateCredentialAsync(realm, userId, Body(new() { ["credentialScopeName"] = scopeName }), ct);
        Require(created.Body.GetProperty("credentialConfigurationId").GetString() == scopeName, "created exact credential entitlement");
        var userToken = await oidc.PasswordGrantAsync(OAuthClientAuthentication.Public(clientId), username, password, cancellationToken: ct);
        string accountAccess = userToken.Json!.Value.GetProperty("access_token").GetString()!; var account = new Oid4vcAccountClient(transport);
        Require((await account.GetEntitlementsAsync(accountAccess, ct)).Json!.Value.EnumerateArray().Single().GetProperty("credentialConfigurationId").GetString() == scopeName, "independent account observes entitlement");
        Proof("CreateCredential", created, "The expected user's credential entitlement is independently visible through the current-user Account API.");
        var listed = await sdk.UserVerifiableCredential.GetCredentialsAsync(realm, userId, ct);
        Require(listed.Body.GetArrayLength() == 1 && listed.Body[0].GetProperty("credentialScopeName").GetString() == scopeName, "Admin list matches account entitlement");
        Proof("GetCredentials", listed, "Admin lists the same exact entitlement observed through the independently authenticated Account API.");
        await wire.User.UpdateUserAsync(realm, userId, new() { FirstName = "After" }, ct);
        var updated = await sdk.UserVerifiableCredential.UpdateCredentialAsync(realm, userId, scopeName, cancellationToken: ct);
        Require(updated.Body.GetProperty("revision").GetString() != created.Body.GetProperty("revision").GetString()
            && updated.Body.GetProperty("userAttributes").GetProperty("firstName")[0].GetString() == "After", "revision and user snapshot update");
        Proof("UpdateCredential", updated, "Refreshing an entitlement increments its revision and snapshots independently changed user attributes.");
        var mailed = await sdk.UserVerifiableCredential.SendCredentialOfferAsync(realm, userId, Body(new() { ["credentialConfigurationId"] = scopeName }), lifespan: 300, cancellationToken: ct);
        var message = await smtp.ReceiveAsync(ct); Require(message.Recipient.Contains("credential-user@example.invalid", StringComparison.Ordinal), "owned SMTP recipient");
        // Action tokens can use Keycloak's internal MAC keys. Keep them opaque and let the server validate the action.
        using var actionBrowser = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false, UseCookies = true });
        actionBrowser.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 AppleWebKit/605.1.15 Version/18.0 Safari/605.1.15");
        Uri current = message.ActionLink(wallet.Issuer); JsonElement? emailedOffer = null;
        for (int step = 0; step < 8; step++)
        {
            Require(current.GetLeftPart(UriPartial.Authority) == wallet.Issuer.GetLeftPart(UriPartial.Authority) && current.AbsolutePath.StartsWith(wallet.Issuer.AbsolutePath + "/login-actions/", StringComparison.Ordinal), "pinned email action navigation");
            using var actionReply = await actionBrowser.GetAsync(current, ct);
            if ((int)actionReply.StatusCode is >= 300 and < 400) { current = new(current, actionReply.Headers.Location!); continue; }
            actionReply.EnsureSuccessStatusCode(); string html = await actionReply.Content.ReadAsStringAsync(ct);
            var links = Regex.Matches(html, "href=[\"']([^\"']+)[\"']", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1)).Select(m => WebUtility.HtmlDecode(m.Groups[1].Value)).ToArray();
            string? offer = links.SingleOrDefault(link => link.StartsWith("openid-credential-offer://?", StringComparison.Ordinal));
            if (offer is not null)
            {
                var parameters = offer[(offer.IndexOf('?') + 1)..].Split('&').Select(p => p.Split('=', 2)).ToDictionary(p => p[0], p => Uri.UnescapeDataString(p[1]));
                emailedOffer = (await wallet.GetOfferAsync(new(parameters["credential_offer_uri"]), ct)).Json!.Value; break;
            }
            string? confirmation = links.SingleOrDefault(link => new Uri(current, link).AbsolutePath == wallet.Issuer.AbsolutePath + "/login-actions/action-token");
            Require(confirmation is not null, "server accepted email action confirmation"); current = new(current, confirmation!);
        }
        Require(emailedOffer is not null && emailedOffer.Value.GetProperty("credential_configuration_ids")[0].GetString() == scopeName, "email action produces exact wallet offer");
        Proof("SendCredentialOffer", mailed, "The owned SMTP recipient confirms an opaque action at Keycloak and independently retrieves its exact credential offer.");
        var transaction = await OidcLoginTransaction.StartAsync(oidc, OAuthClientAuthentication.Public(clientId), callback, "openid " + scopeName,
            options: new() { IssuerState = emailedOffer!.Value.GetProperty("grants").GetProperty("authorization_code").GetProperty("issuer_state").GetString() }, cancellationToken: ct);
        var browser = await ProtocolBrowserFixture.LoginAsync(transaction.AuthorizationUri, callback, username, password, ct);
        var login = await transaction.CompleteAsync(browser.Callback, OAuthClientAuthentication.Public(clientId), new OidcTokenValidator(oidc, clientId), ct);
        var detail = login.Tokens.Json!.Value.GetProperty("authorization_details")[0]; string identifier = detail.GetProperty("credential_identifiers")[0].GetString()!;
        string access = login.Tokens.Json.Value.GetProperty("access_token").GetString()!;
        var configuration = (await wallet.GetIssuerMetadataAsync(ct)).Configurations[scopeName];
        var credential = await wallet.RequestCredentialAsync(configuration, access, credentialIdentifier: identifier, cancellationToken: ct);
        Require((await new Oid4vcCredentialValidator(oidc).ValidateAsync(credential.Json!.Value.GetProperty("credentials")[0].GetProperty("credential").GetString()!, configuration, null, ct))
            .Claims.GetProperty("vc").GetProperty("credentialSubject").GetProperty("email").GetString() == "credential-user@example.invalid", "actual signed credential");
        var issued = await sdk.UserVerifiableCredential.GetIssuedCredentialsAsync(realm, userId, ct);
        string issuedId = issued.Body.EnumerateArray().Single().GetProperty("id").GetString()!;
        Require((await account.GetIssuedCredentialsAsync(accountAccess, ct)).Json!.Value.EnumerateArray().Single().GetProperty("id").GetString() == issuedId, "independent issued credential account list");
        Proof("GetIssuedCredentials", issued, "Admin and the separately authenticated Account API identify the same actually issued and signature-verified credential.");
        var revoked = await sdk.UserVerifiableCredential.RevokeIssuedCredentialAsync(realm, userId, issuedId, ct);
        Require((await account.GetIssuedCredentialsAsync(accountAccess, ct)).Json!.Value.GetArrayLength() == 0, "issued credential no longer visible to account");
        bool refused = false;
        try { await wallet.RequestCredentialAsync(configuration, access, credentialIdentifier: identifier, cancellationToken: ct); }
        catch (KeycloakProtocolException error) when (error.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden) { refused = true; }
        Require(refused, "revocation prevents further issuance through the original credential token");
        Proof("RevokeIssuedCredential", revoked, "Revocation removes the current account's issued credential and its original token can no longer obtain it.");
        var removed = await sdk.UserVerifiableCredential.RevokeCredentialAsync(realm, userId, scopeName, ct);
        Require((await account.GetEntitlementsAsync(accountAccess, ct)).Json!.Value.GetArrayLength() == 0, "entitlement revoked for account");
        Proof("RevokeCredential", removed, "Revoking the entitlement removes it from the independently authenticated user's available credentials.");
    }
}
