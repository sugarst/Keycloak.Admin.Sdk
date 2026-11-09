using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Capabilities;
using Keycloak.Admin.Sdk.Protocols;

internal static class ProtocolWalletPresentationWorkflows
{
    internal static async Task RunAsync(KeycloakAdminClient admin, HttpClient http, ProtocolTransport transport, string realm, string password, string userId,
        string verifierId, VerifiedOid4vcCredential credential, Oid4vcProofKey holder, Action<bool, string> check, CancellationToken ct)
    {
        const string appId = "wallet-presentation-app"; var callback = new Uri("https://app.invalid/presentation"); var oidc = new OidcClient(transport);
        await admin.Clients.CreateClientAsync(realm, new() { ClientId = appId, Enabled = true, PublicClient = true, Protocol = "openid-connect", StandardFlowEnabled = true,
            RedirectUris = [callback.AbsoluteUri], Attributes = new() { ["pkce.code.challenge.method"] = "S256" } }, cancellationToken: ct);
        string trustedKeys = (await oidc.GetSigningKeysAsync(ct)).Json!.Value.GetRawText();
        var query = new JsonObject { ["credentials"] = new JsonArray(new JsonObject { ["id"] = "identity", ["format"] = "dc+sd-jwt",
            ["meta"] = new JsonObject { ["vct_values"] = new JsonArray((JsonNode)JsonValue.Create(credential.Claims.GetProperty("vct").GetString())!) },
            ["claims"] = new JsonArray(new JsonObject { ["path"] = new JsonArray((JsonNode)JsonValue.Create("email")!) }) }) };
        foreach (bool encrypted in new[] { false, true })
        {
            string alias = encrypted ? "wallet-verifier-encrypted" : "wallet-verifier";
            await admin.IdentityProviders.CreateAsync(realm, new() { Alias = alias, ProviderId = "oid4vp", Enabled = true, Config = new()
                { ["trustedIssuerJwks"] = trustedKeys, ["dcqlQuery"] = query.ToJsonString(), ["principalAttribute"] = "email", ["syncMode"] = "FORCE",
                    ["responseMode"] = encrypted ? "direct_post.jwt" : "direct_post" } }, ct);
            await admin.User.AddFederatedIdentityAsync(realm, userId, alias, new() { IdentityProvider = alias, UserId = "protocols@example.invalid", UserName = "protocols@example.invalid" }, ct);
            foreach (bool crossDevice in new[] { false, true })
            {
                string mode = (encrypted ? "encrypted" : "plain") + (crossDevice ? " cross-device" : " same-device");
                using var browser = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false, UseCookies = true });
                browser.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 AppleWebKit/605.1.15 Version/18.0 Safari/605.1.15");
                var login = await OidcLoginTransaction.StartAsync(oidc, OAuthClientAuthentication.Public(appId), callback, options: new() { IdentityProvider = alias }, cancellationToken: ct);
                Uri current = login.AuthorizationUri; string? html = null;
                for (int step = 0; step < 8; step++)
                {
                    using var reply = await browser.GetAsync(current, ct);
                    if ((int)reply.StatusCode is >= 300 and < 400) { current = new(current, reply.Headers.Location!); continue; }
                    reply.EnsureSuccessStatusCode(); html = await reply.Content.ReadAsStringAsync(ct); break;
                }
                if (html is null) throw new InvalidDataException("Wallet verifier did not return its login page.");
                string pattern = crossDevice ? "data-oid4vp-wallet-url=\"([^\"]+)\"" : "id=\"oid4vp-open-wallet\"\\s+href=\"([^\"]+)\"";
                var link = Regex.Match(html, pattern, RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
                if (!link.Success) throw new InvalidDataException("Wallet verifier link missing from the pinned login page.");
                string walletLink = WebUtility.HtmlDecode(link.Groups[1].Value);
                var parameters = walletLink[(walletLink.IndexOf('?') + 1)..].Split('&').Select(p => p.Split('=', 2)).ToDictionary(p => Uri.UnescapeDataString(p[0]), p => Uri.UnescapeDataString(p[1].Replace('+', ' ')));
                check(parameters["client_id"] == verifierId, "The " + mode + " wallet link identifies the independently pinned verifier certificate");
                var client = new Oid4vpClient(transport, alias, verifierId); var requestUri = new Uri(parameters["request_uri"]);
                var request = await client.GetRequestAsync(requestUri, ct); var replay = await client.GetRequestAsync(requestUri, ct);
                check(request.ClientId == verifierId && request.ResponseMode == (encrypted ? "direct_post.jwt" : "direct_post"), "The " + mode + " signed wallet request verifies its certificate signature audience nonce state and response destination");
                int before = RecordingHandler.SentCount; bool partial = false;
                try { await client.PresentAsync(request, credential, [], holder, "identity", ct); } catch (InvalidDataException) { partial = true; }
                check(partial && before == RecordingHandler.SentCount, "The " + mode + " wallet refuses omitted required claims before signing or sending a presentation");
                var posted = await client.PresentAsync(request, credential, credential.Disclosures, holder, "identity", ct);
                bool replayDenied = false;
                try { await client.PresentAsync(replay, credential, credential.Disclosures, holder, "identity", ct); }
                catch (KeycloakProtocolException e) when (e.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.Unauthorized) { replayDenied = true; }
                check(replayDenied, "The " + mode + " verifier atomically consumes the wallet request and rejects a second real presentation");
                string complete;
                if (crossDevice)
                {
                    var server = new Uri(transport.Issuer.AbsoluteUri[..transport.Issuer.AbsoluteUri.IndexOf("/realms/", StringComparison.Ordinal)] + "/");
                    var browserTransport = new ProtocolTransport(browser, server, realm, new KeycloakFeatureSnapshotGate(new Dictionary<string, bool> { ["KeycloakSdk.Protocols"] = true, ["KeycloakSdk.Protocols.WalletPresentation"] = true }));
                    var status = (await new Oid4vpClient(browserTransport, alias, verifierId).GetStatusAsync(request.State, ct)).Json!.Value;
                    if (status.GetProperty("status").GetString() != "complete") throw new InvalidDataException("The bound cross-device browser did not observe its completed presentation.");
                    complete = status.GetProperty("redirectUri").GetString()!;
                }
                else complete = posted.Json!.Value.GetProperty("redirect_uri").GetString()!;
                var completed = await ProtocolBrowserFixture.LoginAsync(new(complete), callback, "account-user", password, ct, browser);
                var result = await login.CompleteAsync(completed.Callback, OAuthClientAuthentication.Public(appId), new OidcTokenValidator(oidc, appId), ct);
                check(result.Identity.Subject == userId, "A real " + mode + " wallet presentation completes only its original browser login and independently mapped user");
            }
        }
    }
}
