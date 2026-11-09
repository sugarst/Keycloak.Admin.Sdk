using System.Net;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Protocols;
using Microsoft.IdentityModel.Tokens;

internal static class ProtocolOidcResponseWorkflows
{
    internal static async Task RunAsync(KeycloakAdminClient admin, HttpClient http, ProtocolTransport transport, string realm, string secret, Action<bool, string> check, CancellationToken ct)
    {
        var oidc = new OidcClient(transport); var callback = new Uri("https://app.invalid/response");
        using var clientKey = RSA.Create(2048); using var attackerKey = RSA.Create(2048);
        const string id = "signed-browser";
        var parameters = clientKey.ExportParameters(false);
        JsonObject Jwk(string use, string? algorithm = null) => new() { ["kty"] = "RSA", ["kid"] = use + "-key", ["use"] = use, ["alg"] = algorithm ?? (use == "sig" ? "RS256" : "RSA-OAEP"),
            ["n"] = Base64UrlEncoder.Encode(parameters.Modulus), ["e"] = Base64UrlEncoder.Encode(parameters.Exponent) };
        await admin.Clients.CreateClientAsync(realm, new ClientRepresentation { ClientId = id, Protocol = "openid-connect", Enabled = true, PublicClient = true,
            StandardFlowEnabled = true, RedirectUris = [callback.AbsoluteUri], Attributes = new() { ["pkce.code.challenge.method"] = "S256",
                ["use.jwks.string"] = "true", ["jwks.string"] = new JsonObject { ["keys"] = new JsonArray(Jwk("sig"), Jwk("enc")) }.ToJsonString(),
                ["request.object.signature.alg"] = "RS256", ["request.object.required"] = "request only", ["authorization.signed.response.alg"] = "RS256" } }, cancellationToken: ct);
        var client = (await admin.Clients.GetClientsAsync(realm, clientId: id, cancellationToken: ct)).Body!.Single();
        var authentication = OAuthClientAuthentication.Public(id);
        var signer = new OidcRequestObjectSigner(id, new(new RsaSecurityKey(clientKey) { KeyId = "sig-key" }, "RS256"));
        var validator = new OidcTokenValidator(oidc, id, decryptionKeys: [new RsaSecurityKey(clientKey) { KeyId = "enc-key" }]);
        string? subject = null;
        foreach (var mode in Enum.GetValues<OidcAuthorizationResponseMode>())
        {
            var transaction = await OidcLoginTransaction.StartSignedAsync(oidc, authentication, callback, signer, options: new() { ResponseMode = mode }, cancellationToken: ct);
            OidcLoginResult result;
            if (mode is OidcAuthorizationResponseMode.FormPost or OidcAuthorizationResponseMode.FormPostJwt)
            {
                var form = await ProtocolBrowserFixture.LoginPostAsync(transaction.AuthorizationUri, callback, "account-user", secret, ct);
                if (mode == OidcAuthorizationResponseMode.FormPostJwt)
                {
                    var corrupt = form.ToDictionary(); string[] parts = corrupt["response"].Split('.');
                    byte[] signature = Base64UrlEncoder.DecodeBytes(parts[2]); signature[0] ^= 1; parts[2] = Base64UrlEncoder.Encode(signature); corrupt["response"] = string.Join('.', parts);
                    bool rejected = false;
                    try { await transaction.CompleteFormPostAsync(callback, corrupt, authentication, validator, ct); }
                    catch (InvalidDataException) { rejected = true; }
                    check(rejected, "A tampered real JARM signature is rejected before the intact original authorization response can redeem its code");
                }
                result = await transaction.CompleteFormPostAsync(callback, form, authentication, validator, ct);
            }
            else
            {
                var browser = await ProtocolBrowserFixture.LoginAsync(transaction.AuthorizationUri, callback, "account-user", secret, ct);
                result = await transaction.CompleteAsync(browser.Callback, authentication, validator, ct);
            }
            subject ??= result.Identity.Subject;
            check(subject == result.Identity.Subject && result.Identity.Claims["preferred_username"].ToString() == "account-user",
                "Signed request objects retain their original PKCE state nonce and verified user across " + mode + " responses");
        }
        using var noRedirect = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false });
        var malicious = await OidcLoginTransaction.StartSignedAsync(oidc, authentication, callback,
            new(id, new(new RsaSecurityKey(attackerKey) { KeyId = "sig-key" }, "RS256")), cancellationToken: ct);
        using var bad = await noRedirect.GetAsync(malicious.AuthorizationUri, ct);
        check(bad.StatusCode == HttpStatusCode.BadRequest || bad.Headers.Location?.Query.Contains("error=", StringComparison.Ordinal) == true,
            "Keycloak refuses a request object signed by a key outside the registered client trust");
        var unsigned = new OidcLoginTransaction(oidc, id, callback);
        using var downgrade = await noRedirect.GetAsync(unsigned.AuthorizationUri, ct);
        check(downgrade.StatusCode == HttpStatusCode.BadRequest || downgrade.Headers.Location?.Query.Contains("error=", StringComparison.Ordinal) == true,
            "A client requiring signed requests refuses an unsigned authorization downgrade");

        foreach (string algorithm in new[] { "RSA-OAEP", "RSA-OAEP-256" })
        {
            client.Attributes!["id.token.encrypted.response.alg"] = algorithm;
            client.Attributes["id.token.encrypted.response.enc"] = "A256CBC-HS512";
            client.Attributes["authorization.encrypted.response.alg"] = algorithm;
            client.Attributes["authorization.encrypted.response.enc"] = "A256CBC-HS512";
            client.Attributes["jwks.string"] = new JsonObject { ["keys"] = new JsonArray(Jwk("sig"), Jwk("enc", algorithm)) }.ToJsonString();
            await admin.Client.UpdateAsync(realm, client.Id!, client, ct);
            await admin.ClearKeysCache.ClearKeysCacheAsync(realm, cancellationToken: ct);
            var transaction = await OidcLoginTransaction.StartSignedAsync(oidc, authentication, callback, signer,
                options: new() { ResponseMode = OidcAuthorizationResponseMode.FormPostJwt }, cancellationToken: ct);
            var fields = await ProtocolBrowserFixture.LoginPostAsync(transaction.AuthorizationUri, callback, "account-user", secret, ct);
            bool unavailableKey = false;
            try { await transaction.CompleteFormPostAsync(callback, fields, authentication, new(oidc, id, decryptionKeys: [new RsaSecurityKey(attackerKey)]), ct); }
            catch (InvalidDataException) { unavailableKey = true; }
            var identity = await transaction.CompleteFormPostAsync(callback, fields, authentication, validator, ct);
            check(unavailableKey && fields["response"].Split('.').Length == 5 && identity.Tokens.Json!.Value.GetProperty("id_token").GetString()!.Split('.').Length == 5 && identity.Identity.Subject == subject,
                "Real " + algorithm + " encrypted JARM and ID tokens require the host decryption key before yielding the original verified subject");
        }
        var realmKeys = (await oidc.GetSigningKeysAsync(ct)).Json!.Value.GetProperty("keys");
        var realmEncryptionKey = realmKeys.EnumerateArray().First(k => k.TryGetProperty("use", out var use) && use.GetString() == "enc" && k.GetProperty("alg").GetString() == "RSA-OAEP");
        var encryptedSigner = new OidcRequestObjectSigner(id, new(new RsaSecurityKey(clientKey) { KeyId = "sig-key" }, "RS256"),
            encryption: new(new JsonWebKey(realmEncryptionKey.GetRawText()), "RSA-OAEP", "A256CBC-HS512"));
        var encryptedTransaction = await OidcLoginTransaction.StartSignedAsync(oidc, authentication, callback, encryptedSigner,
            options: new() { ResponseMode = OidcAuthorizationResponseMode.FormPostJwt }, cancellationToken: ct);
        var encryptedForm = await ProtocolBrowserFixture.LoginPostAsync(encryptedTransaction.AuthorizationUri, callback, "account-user", secret, ct);
        check((await encryptedTransaction.CompleteFormPostAsync(callback, encryptedForm, authentication, validator, ct)).Identity.Subject == subject,
            "Keycloak decrypts a signed request object with its pinned realm key before returning an encrypted and verified browser identity");
        await using (var publisher = new ProtocolWorkloadIssuer(clientKey, "request-publisher"))
        {
            var requestUri = new Uri(ProtocolWorkloadIssuer.Root + "/request.jwt");
            client.Attributes!["request.object.required"] = "request_uri only"; client.Attributes["request.uris"] = requestUri.AbsoluteUri;
            await admin.Client.UpdateAsync(realm, client.Id!, client, ct);
            var referenced = await OidcLoginTransaction.StartReferencedAsync(oidc, authentication, callback, signer, requestUri,
                (credential, token) => { token.ThrowIfCancellationRequested(); publisher.PublishRequestObject("/request.jwt", credential); return ValueTask.CompletedTask; },
                options: new() { ResponseMode = OidcAuthorizationResponseMode.FormPostJwt }, allowLoopbackHttp: true, cancellationToken: ct);
            var referenceForm = await ProtocolBrowserFixture.LoginPostAsync(referenced.AuthorizationUri, callback, "account-user", secret, ct);
            check((await referenced.CompleteFormPostAsync(callback, referenceForm, authentication, validator, ct)).Identity.Subject == subject,
                "A registered request_uri serves the original signed request and retains its bound browser identity through real Keycloak retrieval");
        }

        const string compatibilityId = "browser-compatibility";
        await admin.Clients.CreateClientAsync(realm, new ClientRepresentation { ClientId = compatibilityId, Protocol = "openid-connect", Enabled = true, PublicClient = true,
            StandardFlowEnabled = true, ImplicitFlowEnabled = true, RedirectUris = [callback.AbsoluteUri], Attributes = new() { ["pkce.code.challenge.method"] = "S256" },
            ProtocolMappers = [new() { Name = "own-audience", Protocol = "openid-connect", ProtocolMapper = "oidc-audience-mapper", Config = new() { ["included.client.audience"] = compatibilityId, ["access.token.claim"] = "true" } }] }, cancellationToken: ct);
        var compatibility = OAuthClientAuthentication.Public(compatibilityId);
        foreach (var type in Enum.GetValues<OidcAuthorizationResponseType>().Where(t => t != OidcAuthorizationResponseType.Code))
        foreach (var mode in new[] { OidcAuthorizationResponseMode.Fragment, OidcAuthorizationResponseMode.FormPost, OidcAuthorizationResponseMode.Jwt })
        {
            var transaction = await OidcBrowserTransaction.StartAsync(oidc, compatibility, callback, type, new() { ResponseMode = mode }, cancellationToken: ct);
            Uri? actualCallback = null; IReadOnlyDictionary<string, string>? actualForm = null;
            if (mode == OidcAuthorizationResponseMode.FormPost) actualForm = await ProtocolBrowserFixture.LoginPostAsync(transaction.AuthorizationUri, callback, "account-user", secret, ct);
            else actualCallback = (await ProtocolBrowserFixture.LoginAsync(transaction.AuthorizationUri, callback, "account-user", secret, ct)).Callback;
            Task<OidcBrowserResult> Complete() => actualForm is null ? transaction.CompleteAsync(actualCallback!, compatibility, new(oidc, compatibilityId), new(oidc, compatibilityId), ct)
                : transaction.CompleteFormPostAsync(callback, actualForm, compatibility, new(oidc, compatibilityId), new(oidc, compatibilityId), ct);
            var result = await Complete();
            bool hasIdentity = type is not (OidcAuthorizationResponseType.Token or OidcAuthorizationResponseType.None);
            check((hasIdentity ? result.Identity?.Subject == subject : result.Identity is null) && (type != OidcAuthorizationResponseType.None || result.AccessToken is null && result.Tokens is null),
                "Browser " + type + " via " + mode + " enforces its requested credentials correlation nonce and token or code hashes without inventing an identity");
            bool replay = false;
            try { await Complete(); }
            catch (InvalidDataException) { replay = true; }
            check(replay, "Browser " + type + " via " + mode + " callback cannot be consumed twice");
        }
        foreach (string substituted in new[] { "code", "access_token" })
        {
            var transaction = await OidcBrowserTransaction.StartAsync(oidc, compatibility, callback, OidcAuthorizationResponseType.CodeIdTokenToken, cancellationToken: ct);
            var browser = await ProtocolBrowserFixture.LoginAsync(transaction.AuthorizationUri, callback, "account-user", secret, ct);
            var fields = browser.Callback.Fragment.TrimStart('#').Split('&').Select(p => p.Split('=', 2)).ToDictionary(p => Uri.UnescapeDataString(p[0]), p => Uri.UnescapeDataString(p[1]));
            fields[substituted] = "substituted";
            bool refused = false;
            try { await transaction.CompleteAsync(new(callback + "#" + string.Join('&', fields.Select(p => p.Key + "=" + Uri.EscapeDataString(p.Value)))), compatibility, new(oidc, compatibilityId), new(oidc, compatibilityId), ct); }
            catch (InvalidDataException) { refused = true; }
            check(refused, "A real hybrid ID token rejects substitution of its bound " + substituted + " before code redemption");
        }
    }
}
