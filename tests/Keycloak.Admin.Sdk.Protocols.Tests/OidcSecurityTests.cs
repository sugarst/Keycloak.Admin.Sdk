using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Keycloak.Admin.Sdk.Protocols;
using Keycloak.Admin.Sdk.Capabilities;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualStudio.TestTools.UnitTesting;

[TestClass]
public sealed class OidcSecurityTests
{
    [TestMethod]
    public async Task MandatoryAssuranceChecksVerifiedContextAuthenticationTimeAndMethodsInsteadOfTokenIssueTime()
    {
        using var fixture = new IdentityFixture(); var clock = new ControlledClock(); long now = clock.GetUtcNow().ToUnixTimeSeconds();
        var requirement = new OidcAssuranceRequirement(["urn:high"], TimeSpan.FromMinutes(2), ["pwd", "otp"], clock);
        var validator = new OidcTokenValidator(fixture.Oidc, "app");
        Dictionary<string, object> Claims() => new() { ["acr"] = "urn:high", ["auth_time"] = now - 60, ["amr"] = new[] { "pwd", "otp" } };
        async Task<OidcIdentity> Identity(Dictionary<string, object> values) => await validator.ValidateIdTokenAsync(fixture.Token(mutate: c => { foreach (var pair in values) c[pair.Key] = pair.Value; }), "nonce", "access");
        var identity = await Identity(Claims()); requirement.Validate(identity); Assert.AreEqual("urn:high", identity.VerifiedClaims.GetProperty("acr").GetString());
        foreach (object kind in new object[] { "Bearer", "DPoP", "Refresh", 12 })
            await Assert.ThrowsAsync<InvalidDataException>(() => validator.ValidateIdTokenAsync(fixture.Token(mutate: c => c["typ"] = kind), "nonce", "access"));
        await validator.ValidateIdTokenAsync(fixture.Token(mutate: c => c["typ"] = "ID"), "nonce", "access");
        Assert.AreEqual("urn:high", requirement.RequestedAcrValues); Assert.AreEqual(120, requirement.MaximumAgeSeconds);
        foreach (Action<Dictionary<string, object>> mutate in new Action<Dictionary<string, object>>[] {
            c => c.Remove("acr"), c => c["acr"] = "urn:low", c => c["acr"] = 2,
            c => c.Remove("auth_time"), c => c["auth_time"] = now - 180, c => c["auth_time"] = now + 60, c => c["auth_time"] = -1L,
            c => c["auth_time"] = "123", c => c["auth_time"] = 1.5, c => c["auth_time"] = double.MaxValue,
            c => c.Remove("amr"), c => c["amr"] = "otp", c => c["amr"] = new[] { 1, 2 }, c => c["amr"] = new[] { "pwd" } })
        {
            var claims = Claims(); mutate(claims); var invalid = await Identity(claims); Assert.Throws<InvalidDataException>(() => requirement.Validate(invalid));
        }
        var acrOnly = new OidcAssuranceRequirement(["urn:high"]); acrOnly.Validate(await Identity(new() { ["acr"] = "urn:high" })); Assert.IsNull(acrOnly.MaximumAgeSeconds);
        var ageOnly = new OidcAssuranceRequirement(maximumAuthenticationAge: TimeSpan.Zero, clock: clock); ageOnly.Validate(await Identity(new() { ["auth_time"] = now })); Assert.IsNull(ageOnly.RequestedAcrValues);
        new OidcAssuranceRequirement(requiredMethods: ["otp"]).Validate(await Identity(new() { ["amr"] = new[] { "otp" } }));
        var payload = new JsonObject { ["iss"] = fixture.Oidc.Issuer.AbsoluteUri, ["aud"] = "app", ["sub"] = "user", ["nonce"] = "nonce", ["iat"] = now, ["exp"] = now + 300, ["acr"] = "urn:high" }.ToJsonString()
            .Replace("\"acr\":\"urn:high\"", "\"acr\":\"urn:high\",\"acr\":\"urn:low\"", StringComparison.Ordinal);
        var ambiguous = await validator.ValidateIdTokenAsync(new JsonWebTokenHandler().CreateToken(payload, fixture.Signing), "nonce", "access");
        Assert.Throws<InvalidDataException>(() => acrOnly.Validate(ambiguous));
        clock.Advance(TimeSpan.FromMinutes(3)); Assert.Throws<InvalidDataException>(() => requirement.Validate(identity));
    }

    [TestMethod]
    public void AssurancePoliciesRejectInvalidConfigurationAndUnverifiedJsonShapes()
    {
        var policy = new OidcAssuranceRequirement(["urn:high"]);
        Assert.Throws<ArgumentNullException>(() => policy.Validate(null!));
        foreach (string json in new[] { "null", "[]", "12", "{\"acr\":12}", "{\"acr\":\"urn:low\"}" })
        { using var document = JsonDocument.Parse(json); Assert.Throws<InvalidDataException>(() => policy.ValidateVerifiedClaims(document.RootElement)); }
        Assert.Throws<ArgumentException>(() => new OidcAssuranceRequirement());
        foreach (string[] invalid in new[] { new[] { "" }, new[] { "with space" }, new[] { "\0" }, new[] { new string('a', 257) }, new[] { "duplicate", "duplicate" }, Enumerable.Range(0, 33).Select(i => i.ToString(System.Globalization.CultureInfo.InvariantCulture)).ToArray() })
            Assert.Throws<ArgumentException>(() => new OidcAssuranceRequirement(invalid));
        foreach (var age in new[] { TimeSpan.FromSeconds(-1), TimeSpan.FromSeconds((long)int.MaxValue + 1) }) Assert.Throws<ArgumentOutOfRangeException>(() => new OidcAssuranceRequirement(maximumAuthenticationAge: age));
    }

    [TestMethod]
    public async Task LoginTransactionsCaptureMandatoryAssuranceAndCannotPublishAnUnverifiedLowerContext()
    {
        using var fixture = new IdentityFixture(); var callback = new Uri("https://app.invalid/callback"); var client = OAuthClientAuthentication.Public("app");
        var policy = new OidcAssuranceRequirement(["urn:high"], TimeSpan.FromMinutes(5));
        foreach (int maximumAge in new[] { 30, 600 })
        {
            var request = fixture.Oidc.CreateAuthorizationUri("app", callback, "state", "nonce", OidcClient.CreateVerifier(), options: new() { RequiredAssurance = policy, MaximumAuthenticationAgeSeconds = maximumAge });
            Assert.AreEqual(Math.Min(maximumAge, 300).ToString(System.Globalization.CultureInfo.InvariantCulture), Parse(request.Query)["max_age"]);
        }
        var validator = new OidcTokenValidator(fixture.Oidc, "app");
        foreach (bool attained in new[] { false, true })
        {
            var tx = await OidcLoginTransaction.StartAsync(fixture.Oidc, client, callback, options: new() { RequiredAssurance = policy });
            var query = Parse(tx.AuthorizationUri.Query); Assert.AreEqual("urn:high", query["acr_values"]); Assert.AreEqual("300", query["max_age"]);
            fixture.Handler.Reply = request => request.RequestUri!.AbsolutePath.EndsWith("/certs", StringComparison.Ordinal) ? fixture.Jwks()
                : new JsonObject { ["id_token"] = fixture.Token(nonce: query["nonce"], mutate: c => { c["acr"] = attained ? "urn:high" : "urn:low"; c["auth_time"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(); }), ["access_token"] = "access" }.ToJsonString();
            var response = new Uri(callback + "?state=" + tx.State + "&code=c");
            if (attained) Assert.AreEqual("user", (await tx.CompleteAsync(response, client, validator)).Identity.Subject);
            else await Assert.ThrowsAsync<InvalidDataException>(() => tx.CompleteAsync(response, client, validator));
        }
        foreach (bool attained in new[] { false, true })
        {
            var tx = await OidcBrowserTransaction.StartAsync(fixture.Oidc, client, callback, OidcAuthorizationResponseType.IdToken, new() { RequiredAssurance = policy, ResponseMode = OidcAuthorizationResponseMode.FormPost });
            var query = Parse(tx.AuthorizationUri.Query); fixture.Handler.Reply = _ => fixture.Jwks();
            var fields = new Dictionary<string, string> { ["state"] = tx.State, ["id_token"] = fixture.Token(nonce: query["nonce"], mutate: c => { c["acr"] = attained ? "urn:high" : "urn:low"; c["auth_time"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(); }) };
            if (attained) Assert.AreEqual("user", (await tx.CompleteFormPostAsync(callback, fields, client, validator)).Identity!.Subject);
            else await Assert.ThrowsAsync<InvalidDataException>(() => tx.CompleteFormPostAsync(callback, fields, client, validator));
        }
        foreach (var type in new[] { OidcAuthorizationResponseType.None, OidcAuthorizationResponseType.Token })
            await Assert.ThrowsAsync<ArgumentException>(() => OidcBrowserTransaction.StartAsync(fixture.Oidc, client, callback, type, new() { RequiredAssurance = policy, ResponseMode = OidcAuthorizationResponseMode.Fragment }));
        using var http = new HttpClient(fixture.Handler, false); var flags = new KeycloakFeatureSnapshotGate(new Dictionary<string, bool> { ["KeycloakSdk.Protocols"] = true, ["KeycloakSdk.Protocols.Oidc"] = true });
        var closed = new OidcClient(new(http, new("https://identity.invalid/"), "r", flags)); int before = fixture.Handler.Calls;
        await Assert.ThrowsAsync<InvalidOperationException>(() => OidcLoginTransaction.StartAsync(closed, client, callback, options: new() { RequiredAssurance = policy }));
        Assert.AreEqual(before, fixture.Handler.Calls);
    }
    [TestMethod]
    public async Task EncryptedRequestObjectsRemainSignedAndUseOnlyExplicitAuthenticatedEncryption()
    {
        using var fixture = new IdentityFixture(); using var realmKey = RSA.Create(2048);
        var raw = fixture.Oidc.CreateAuthorizationUri("app", new("https://app.invalid/callback"), "state", "nonce", OidcClient.CreateVerifier());
        foreach (string algorithm in new[] { "RSA-OAEP", "RSA-OAEP-256" })
        foreach (string encryption in new[] { "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512" })
        {
            var signer = new OidcRequestObjectSigner("app", fixture.Signing, encryption: new(new RsaSecurityKey(realmKey), algorithm, encryption));
            var authorization = await signer.CreateAuthorizationUriAsync(fixture.Oidc.Issuer, raw);
            var validation = await new JsonWebTokenHandler().ValidateTokenAsync(Parse(authorization.Query)["request"], new TokenValidationParameters {
                ValidIssuer = "app", ValidAudience = fixture.Oidc.Issuer.AbsoluteUri, IssuerSigningKey = fixture.Signing.Key,
                TokenDecryptionKey = JweCryptoProviderFactory.DecryptionKey(new RsaSecurityKey(realmKey)), CryptoProviderFactory = new JweCryptoProviderFactory() });
            Assert.IsTrue(validation.IsValid); var token = (JsonWebToken)validation.SecurityToken;
            Assert.AreEqual("state", token.InnerToken.GetPayloadValue<string>("state")); Assert.AreEqual("nonce", token.InnerToken.GetPayloadValue<string>("nonce"));
        }
        foreach (var credentials in new[] { new EncryptingCredentials(new RsaSecurityKey(realmKey), "RSA1_5", "A256CBC-HS512"), new(new RsaSecurityKey(realmKey), "RSA-OAEP", "A128GCM") })
            Assert.Throws<ArgumentException>(() => new OidcRequestObjectSigner("app", fixture.Signing, encryption: credentials));
        var httpIssuer = new Uri("http://identity.invalid/realms/r");
        await new OidcRequestObjectSigner("app", fixture.Signing).CreateAuthorizationUriAsync(httpIssuer, new(raw.AbsoluteUri.Replace("https:", "http:", StringComparison.Ordinal)));
    }

    [TestMethod]
    public async Task BrowserTokensCannotSubstituteCodesIdentitiesSubjectsOrResourceAudiences()
    {
        using var fixture = new IdentityFixture(); using var foreignHttp = new HttpClient();
        var foreignOidc = new OidcClient(new(foreignHttp, new("https://attacker.invalid/"), "r"));
        var auth = OAuthClientAuthentication.Public("app"); var callback = new Uri("https://app.invalid/callback");
        var validator = new OidcTokenValidator(fixture.Oidc, "app"); var resource = new KeycloakAccessTokenValidator(fixture.Oidc, "app");
        string access = fixture.Token(mutate: c => c["typ"] = "Bearer");
        foreach (string scenario in new[] { "state", "issuer", "error", "extra", "empty", "missing", "hash", "missing-hash", "nonce", "access-audience", "token-type", "no-token-type", "no-resource", "foreign-resource", "subject", "redeemed-subject", "empty-redeem", "client", "validator", "foreign-validator" })
        {
            var tx = await OidcBrowserTransaction.StartAsync(fixture.Oidc, auth, callback, OidcAuthorizationResponseType.CodeIdTokenToken);
            string nonce = Parse(tx.AuthorizationUri.Query)["nonce"];
            var fields = new Dictionary<string, string> { ["state"] = tx.State, ["iss"] = fixture.Oidc.Issuer.AbsoluteUri, ["code"] = "code", ["access_token"] = access, ["token_type"] = "Bearer" };
            fields["id_token"] = fixture.Token(nonce: nonce, hash: true, access: access, mutate: c => c["c_hash"] = HalfHash("code"));
            switch (scenario)
            {
                case "state": fields["state"] = "other"; break;
                case "issuer": fields["iss"] = foreignOidc.Issuer.AbsoluteUri; break;
                case "error": fields["error"] = "access_denied"; break;
                case "extra": fields["access_token"] = " "; break;
                case "empty": fields["code"] = " "; break;
                case "missing": fields.Remove("id_token"); break;
                case "hash": fields["code"] = "substituted"; break;
                case "missing-hash": fields["id_token"] = fixture.Token(nonce: nonce, hash: true, access: access); break;
                case "nonce": fields["id_token"] = fixture.Token(nonce: "other", hash: true, access: access, mutate: c => c["c_hash"] = HalfHash("code")); break;
                case "access-audience": fields["access_token"] = fixture.Token(audience: "other", mutate: c => c["typ"] = "Bearer");
                    fields["id_token"] = fixture.Token(nonce: nonce, hash: true, access: fields["access_token"], mutate: c => c["c_hash"] = HalfHash("code")); break;
                case "token-type": fields["token_type"] = "DPoP"; break;
                case "no-token-type": fields.Remove("token_type"); break;
                case "subject": fields["access_token"] = fixture.Token(subject: "other", mutate: c => c["typ"] = "Bearer");
                    fields["id_token"] = fixture.Token(nonce: nonce, hash: true, access: fields["access_token"], mutate: c => c["c_hash"] = HalfHash("code")); break;
            }
            fixture.Handler.Reply = request => request.RequestUri!.AbsolutePath.EndsWith("/certs", StringComparison.Ordinal) ? fixture.Jwks()
                : scenario == "empty-redeem" ? "" : new JsonObject { ["id_token"] = fixture.Token(nonce: nonce, subject: scenario == "redeemed-subject" ? "other" : "user"), ["access_token"] = access }.ToJsonString();
            var selectedResource = scenario == "no-resource" ? null : scenario == "foreign-resource" ? new(foreignOidc, "app") : resource;
            var selectedValidator = scenario == "validator" ? new(fixture.Oidc, "other") : scenario == "foreign-validator" ? new(foreignOidc, "app") : validator;
            var selectedClient = scenario == "client" ? OAuthClientAuthentication.Public("other") : auth;
            var actual = new Uri(callback + "#" + string.Join('&', fields.Select(p => p.Key + "=" + Uri.EscapeDataString(p.Value))));
            if (scenario is "client" or "validator" or "foreign-validator") await Assert.ThrowsAsync<ArgumentException>(() => tx.CompleteAsync(actual, selectedClient, selectedValidator, selectedResource));
            else await Assert.ThrowsAsync<InvalidDataException>(() => tx.CompleteAsync(actual, selectedClient, selectedValidator, selectedResource));
        }
        var none = await OidcBrowserTransaction.StartAsync(fixture.Oidc, auth, callback, OidcAuthorizationResponseType.None);
        await Assert.ThrowsAsync<InvalidDataException>(() => none.CompleteAsync(new(callback + "?state=" + none.State + "&code=unsolicited"), auth, validator));
        var clock = new ControlledClock();
        var expired = await OidcBrowserTransaction.StartAsync(fixture.Oidc, auth, callback, OidcAuthorizationResponseType.None, clock: clock);
        clock.Advance(TimeSpan.FromMinutes(6));
        await Assert.ThrowsAsync<InvalidDataException>(() => expired.CompleteAsync(new(callback + "?state=" + expired.State), auth, validator));
        var racing = await OidcBrowserTransaction.StartAsync(fixture.Oidc, auth, callback, OidcAuthorizationResponseType.None, new() { ResponseMode = OidcAuthorizationResponseMode.QueryJwt }, clock: clock);
        fixture.Handler.Reply = _ => { clock.Advance(TimeSpan.FromMinutes(6)); return fixture.Jwks(); };
        await Assert.ThrowsAsync<InvalidDataException>(() => racing.CompleteAsync(new(callback + "?response=" + fixture.AuthorizationResponse(racing.State)), auth, validator));
        fixture.Handler.Reply = _ => fixture.Jwks();
        await Assert.ThrowsAsync<InvalidDataException>(() => validator.ValidateBrowserIdTokenAsync(fixture.Token(), "nonce", "access", null, CancellationToken.None));
        var plain = new OidcLoginTransaction(fixture.Oidc, "app", callback);
        await Assert.ThrowsAsync<InvalidDataException>(() => plain.CompleteAsync(new(callback + "?state=" + plain.State + "&code=code&id_token=unsolicited"), auth, validator));
        static string HalfHash(string value) { byte[] bytes = SHA256.HashData(Encoding.ASCII.GetBytes(value)); return Base64UrlEncoder.Encode(bytes, 0, bytes.Length / 2); }
    }

    [TestMethod]
    public async Task RequestPublicationAndBrowserInitiationObeyIndependentHostGatesBeforeCredentialsOrNetwork()
    {
        using var fixture = new IdentityFixture(); using var http = new HttpClient(fixture.Handler, false);
        var values = new Dictionary<string, bool> { ["KeycloakSdk.Protocols"] = true, ["KeycloakSdk.Protocols.Oidc"] = true,
            ["KeycloakSdk.Protocols.OidcRequestObjects"] = true, ["KeycloakSdk.Protocols.OidcSignedResponses"] = true, ["KeycloakSdk.Protocols.OidcBrowserCompatibility"] = true };
        var gate = new KeycloakFeatureSnapshotGate(values); var oidc = new OidcClient(new(http, new("https://identity.invalid/"), "r", gate));
        var callback = new Uri("https://app.invalid/callback"); int credentials = 0, publications = 0;
        var client = OAuthClientAuthentication.SecretPost("app", _ => { credentials++; return ValueTask.FromResult("secret"); });
        var signer = new OidcRequestObjectSigner("app", fixture.Signing);
        ValueTask Publish(string request, CancellationToken ct) { ct.ThrowIfCancellationRequested(); publications++; Assert.AreEqual(3, request.Split('.').Length); return ValueTask.CompletedTask; }
        foreach (string feature in values.Keys.Where(k => k is not "KeycloakSdk.Protocols" and not "KeycloakSdk.Protocols.Oidc").ToArray())
        {
            values[feature] = false; gate.Replace(values);
            if (feature.EndsWith("OidcBrowserCompatibility", StringComparison.Ordinal))
                await Assert.ThrowsAsync<InvalidOperationException>(() => OidcBrowserTransaction.StartAsync(oidc, client, callback, OidcAuthorizationResponseType.None));
            else await Assert.ThrowsAsync<InvalidOperationException>(() => OidcLoginTransaction.StartReferencedAsync(oidc, client, callback, signer, new("https://app.invalid/request.jwt"), Publish, options: new() { ResponseMode = OidcAuthorizationResponseMode.QueryJwt }));
            Assert.AreEqual(0, credentials); Assert.AreEqual(0, publications); Assert.AreEqual(0, fixture.Handler.Calls); values[feature] = true;
        }
        gate.Replace(values);
        var tx = await OidcLoginTransaction.StartReferencedAsync(oidc, client, callback, signer, new("https://app.invalid/request.jwt"), Publish);
        Assert.AreEqual("https://app.invalid/request.jwt", Parse(tx.AuthorizationUri.Query)["request_uri"]); Assert.AreEqual(1, publications);
        await OidcLoginTransaction.StartReferencedAsync(oidc, client, callback, signer, new("http://127.0.0.1/request.jwt"), Publish, allowLoopbackHttp: true);
        foreach (var invalid in new[] { new Uri("relative", UriKind.Relative), new Uri("http://external.invalid/request"), new Uri("http://127.0.0.1/request"), new Uri("https://user:pass@app.invalid/request"), new Uri("https://app.invalid/request#fragment"), new Uri("https://app.invalid/" + new string('a', 2050)) })
            await Assert.ThrowsAsync<ArgumentException>(() => OidcLoginTransaction.StartReferencedAsync(oidc, client, callback, signer, invalid, Publish));
        await Assert.ThrowsAsync<ArgumentNullException>(() => OidcLoginTransaction.StartReferencedAsync(oidc, client, callback, signer, null!, Publish));
        await Assert.ThrowsAsync<ArgumentNullException>(() => OidcLoginTransaction.StartReferencedAsync(oidc, client, callback, signer, new("https://app.invalid/request.jwt"), null!));
        await Assert.ThrowsAsync<InvalidOperationException>(() => OidcLoginTransaction.StartReferencedAsync(oidc, client, callback, signer, new("https://app.invalid/request.jwt"), (_, _) => { gate.Replace([]); return ValueTask.CompletedTask; }));
        Assert.AreEqual(0, credentials); Assert.AreEqual(0, fixture.Handler.Calls);
    }
    [TestMethod]
    public async Task BrowserCompatibilityResponsesValidateRequestedCredentialsAndRequireHashesBeforeRedeemingCodes()
    {
        using var fixture = new IdentityFixture(); var auth = OAuthClientAuthentication.Public("app"); var callback = new Uri("https://app.invalid/callback");
        var validator = new OidcTokenValidator(fixture.Oidc, "app"); var accessValidator = new KeycloakAccessTokenValidator(fixture.Oidc, "app");
        string access = fixture.Token(mutate: c => c["typ"] = "Bearer");
        foreach (var type in Enum.GetValues<OidcAuthorizationResponseType>().Where(t => t != OidcAuthorizationResponseType.Code))
        foreach (var mode in new[] { OidcAuthorizationResponseMode.Fragment, OidcAuthorizationResponseMode.FormPost, OidcAuthorizationResponseMode.FormPostJwt, OidcAuthorizationResponseMode.Jwt })
        {
            var transaction = await OidcBrowserTransaction.StartAsync(fixture.Oidc, auth, callback, type, new() { ResponseMode = mode });
            string wire = type.Wire(), nonce = Parse(transaction.AuthorizationUri.Query)["nonce"];
            var fields = new Dictionary<string, string> { ["state"] = transaction.State, ["iss"] = fixture.Oidc.Issuer.AbsoluteUri };
            bool hasAccess = wire.Split(' ').Contains("token", StringComparer.Ordinal), hasCode = wire.Split(' ').Contains("code", StringComparer.Ordinal), hasId = wire.Split(' ').Contains("id_token", StringComparer.Ordinal);
            if (hasAccess) { fields["access_token"] = access; fields["token_type"] = "Bearer"; }
            if (hasCode) fields["code"] = "code";
            if (hasId) fields["id_token"] = fixture.Token(nonce: nonce, hash: hasAccess, access: access, mutate: c => { if (hasCode) c["c_hash"] = HalfHash("code"); });
            fixture.Handler.Reply = request => request.RequestUri!.AbsolutePath.EndsWith("/certs", StringComparison.Ordinal) ? fixture.Jwks()
                : new JsonObject { ["id_token"] = fixture.Token(nonce: nonce), ["access_token"] = access }.ToJsonString();
            if (mode.Signed()) fields = new() { ["response"] = fixture.AuthorizationResponse(transaction.State, mutate: c => { c.Clear(); foreach (var pair in fields) c.Add(pair.Key, pair.Value); }) };
            Task<OidcBrowserResult> Complete() => mode.Post() ? transaction.CompleteFormPostAsync(callback, fields, auth, validator, accessValidator)
                : transaction.CompleteAsync(new(callback + (mode == OidcAuthorizationResponseMode.Jwt && type == OidcAuthorizationResponseType.None ? "?" : "#") + string.Join('&', fields.Select(p => Uri.EscapeDataString(p.Key) + "=" + Uri.EscapeDataString(p.Value)))), auth, validator, accessValidator);
            var result = await Complete();
            Assert.AreEqual(hasId || hasCode, result.Identity is not null); Assert.AreEqual(hasCode, result.Tokens is not null); Assert.AreEqual(hasAccess, result.AccessToken is not null);
            await Assert.ThrowsAsync<InvalidDataException>(Complete);
        }
        static string HalfHash(string value) { byte[] bytes = SHA256.HashData(Encoding.ASCII.GetBytes(value)); return Base64UrlEncoder.Encode(bytes, 0, bytes.Length / 2); }
        Assert.AreEqual("code", OidcAuthorizationResponseType.Code.Wire());
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => OidcBrowserTransaction.StartAsync(fixture.Oidc, auth, callback, (OidcAuthorizationResponseType)99));
        await Assert.ThrowsAsync<ArgumentException>(() => OidcBrowserTransaction.StartAsync(fixture.Oidc, auth, callback, OidcAuthorizationResponseType.Code));
        await Assert.ThrowsAsync<ArgumentException>(() => OidcBrowserTransaction.StartAsync(fixture.Oidc, auth, callback, OidcAuthorizationResponseType.IdToken, scope: "profile"));
        await Assert.ThrowsAsync<ArgumentException>(() => OidcBrowserTransaction.StartAsync(fixture.Oidc, auth, callback, OidcAuthorizationResponseType.IdToken, new() { ResponseMode = OidcAuthorizationResponseMode.Query }));
        await Assert.ThrowsAsync<ArgumentException>(() => OidcBrowserTransaction.StartAsync(fixture.Oidc, auth, new(callback + "?fixed=true"), OidcAuthorizationResponseType.None));
        await Assert.ThrowsAsync<ArgumentNullException>(() => OidcBrowserTransaction.StartAsync(null!, auth, callback, OidcAuthorizationResponseType.None));
        await Assert.ThrowsAsync<ArgumentNullException>(() => OidcBrowserTransaction.StartAsync(fixture.Oidc, null!, callback, OidcAuthorizationResponseType.None));
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        await Assert.ThrowsAsync<OperationCanceledException>(() => OidcBrowserTransaction.StartAsync(fixture.Oidc, auth, callback, OidcAuthorizationResponseType.None, cancellationToken: cancelled.Token));
        var none = await OidcBrowserTransaction.StartAsync(fixture.Oidc, auth, callback, OidcAuthorizationResponseType.None);
        Assert.Throws<OperationCanceledException>(() => none.CompleteAsync(callback, auth, validator, cancellationToken: cancelled.Token));
        Assert.Throws<OperationCanceledException>(() => none.CompleteFormPostAsync(callback, [], auth, validator, cancellationToken: cancelled.Token));
    }

    [TestMethod]
    public async Task AmbiguousSignedClaimsCannotExploitThePinnedKeycloakIssuerCompatibility()
    {
        using var fixture = new IdentityFixture(); var validator = new OidcTokenValidator(fixture.Oidc, "app");
        string issuer = fixture.Oidc.Issuer.AbsoluteUri;
        string Prefix(string name, string value) => "{\"iss\":\"" + issuer + "\",\"aud\":\"app\",\"exp\":" + DateTimeOffset.UtcNow.AddMinutes(1).ToUnixTimeSeconds() + ",\"state\":\"s\",\"code\":\"c\",\"" + name + "\":" + value + "}";
        foreach (string payload in new[] { Prefix("state", "\"s\""), Prefix("iss", "\"https://attacker.invalid\""), Prefix("iss", "12"), Prefix("iss", "\"" + issuer + "\",\"iss\":\"" + issuer + "\"") })
            await Assert.ThrowsAsync<InvalidDataException>(() => validator.ValidateAuthorizationResponseAsync(new JsonWebTokenHandler().CreateToken(payload, fixture.Signing), CancellationToken.None));
        await validator.ValidateAuthorizationResponseAsync(new JsonWebTokenHandler().CreateToken(Prefix("iss", "\"" + issuer + "\""), fixture.Signing), CancellationToken.None);
    }
    [TestMethod]
    public async Task RequestObjectsSignTheOriginalTransactionWithoutReplacingCorrelationOrPkce()
    {
        using var fixture = new IdentityFixture(); var auth = OAuthClientAuthentication.Public("app");
        var signer = new OidcRequestObjectSigner("app", fixture.Signing);
        var tx = await OidcLoginTransaction.StartSignedAsync(fixture.Oidc, auth, new("https://app.invalid/callback"), signer,
            options: new() { MaximumAuthenticationAgeSeconds = 0, Claims = JsonDocument.Parse("{\"id_token\":{\"email\":null}}").RootElement });
        var query = Parse(tx.AuthorizationUri.Query); Assert.AreEqual(2, query.Count); Assert.AreEqual("app", query["client_id"]);
        var validation = await new JsonWebTokenHandler().ValidateTokenAsync(query["request"], new TokenValidationParameters { ValidIssuer = "app", ValidAudience = fixture.Oidc.Issuer.AbsoluteUri,
            IssuerSigningKey = fixture.Signing.Key, ValidAlgorithms = ["RS256"], ValidTypes = ["oauth-authz-req+jwt"], ClockSkew = TimeSpan.Zero });
        Assert.IsTrue(validation.IsValid); var request = (JsonWebToken)validation.SecurityToken;
        Assert.AreEqual(tx.State, request.GetPayloadValue<string>("state")); Assert.AreEqual("S256", request.GetPayloadValue<string>("code_challenge_method"));
        Assert.AreEqual(0L, request.GetPayloadValue<long>("max_age")); Assert.IsTrue(request.GetPayloadValue<JsonElement>("claims").TryGetProperty("id_token", out _));
        string nonce = request.GetPayloadValue<string>("nonce");
        fixture.Handler.Reply = call => call.RequestUri!.AbsolutePath.EndsWith("/certs", StringComparison.Ordinal) ? fixture.Jwks()
            : new JsonObject { ["id_token"] = fixture.Token(nonce: nonce), ["access_token"] = "access" }.ToJsonString();
        Assert.AreEqual("user", (await tx.CompleteAsync(new("https://app.invalid/callback?state=" + tx.State + "&code=code"), auth, new(fixture.Oidc, "app"))).Identity.Subject);
        var raw = fixture.Oidc.CreateAuthorizationUri("app", new("https://app.invalid/callback"), "state", "nonce", OidcClient.CreateVerifier());
        var withDetails = new Uri(raw + "&authorization_details=%5B%7B%22type%22%3A%22openid_credential%22%7D%5D");
        await new OidcRequestObjectSigner("app", fixture.Signing, TimeSpan.FromMinutes(2), TimeProvider.System).CreateAuthorizationUriAsync(fixture.Oidc.Issuer, withDetails);
        Assert.Throws<ArgumentException>(() => new OidcRequestObjectSigner(" ", fixture.Signing));
        Assert.Throws<ArgumentNullException>(() => new OidcRequestObjectSigner("app", null!));
        Assert.Throws<ArgumentException>(() => new OidcRequestObjectSigner("app", new(new SymmetricSecurityKey(new byte[32]), "HS256")));
        foreach (var lifetime in new[] { TimeSpan.Zero, TimeSpan.FromMinutes(6) }) Assert.Throws<ArgumentOutOfRangeException>(() => new OidcRequestObjectSigner("app", fixture.Signing, lifetime));
        foreach (string suffix in new[] { "", "?client_id=other", "?client_id=app&iss=override", "?client_id=app&request=existing", "?client_id=app&scope=a&scope=b",
            "?client_id=app&missing", "?client_id=app&=x", "?client_id=app&max_age=-1", "?client_id=app&claims=[]", "?client_id=app&authorization_details={}",
            "?client_id=app&" + string.Join('&', Enumerable.Range(0, 65).Select(i => "p" + i + "=v")), "?client_id=app&x=" + new string('x', 33000) })
            Assert.Throws<ArgumentException>(() => signer.CreateAuthorizationUriAsync(fixture.Oidc.Issuer, new(fixture.Oidc.Issuer + "/protocol/openid-connect/auth" + suffix)));
        foreach (var wrong in new[] { new Uri("relative", UriKind.Relative), new Uri("https://other.invalid/auth"), new Uri(raw + "#fragment") })
            Assert.Throws<ArgumentException>(() => signer.CreateAuthorizationUriAsync(fixture.Oidc.Issuer, wrong));
        foreach (var wrong in new[] { new Uri("relative", UriKind.Relative), new Uri("ftp://host/"), new Uri("https://user:pass@host/"), new Uri("https://host/?q=x"), new Uri("https://host/#fragment") })
            Assert.Throws<ArgumentException>(() => signer.CreateAuthorizationUriAsync(wrong, raw));
        Assert.Throws<ArgumentNullException>(() => signer.CreateAuthorizationUriAsync(null!, raw)); Assert.Throws<ArgumentNullException>(() => signer.CreateAuthorizationUriAsync(fixture.Oidc.Issuer, null!));
        using var cancel = new CancellationTokenSource(); cancel.Cancel();
        Assert.Throws<OperationCanceledException>(() => signer.CreateAuthorizationUriAsync(fixture.Oidc.Issuer, raw, cancel.Token));
        await Assert.ThrowsAsync<OperationCanceledException>(() => OidcLoginTransaction.StartSignedAsync(fixture.Oidc, auth, new("https://app.invalid/callback"), signer, cancellationToken: cancel.Token));
        await Assert.ThrowsAsync<ArgumentNullException>(() => OidcLoginTransaction.StartSignedAsync(fixture.Oidc, null!, new("https://app.invalid/callback"), signer));
        await Assert.ThrowsAsync<ArgumentNullException>(() => OidcLoginTransaction.StartSignedAsync(fixture.Oidc, auth, new("https://app.invalid/callback"), null!));
    }

    [TestMethod]
    public async Task EveryAuthorizationResponseTransportValidatesTheOriginalTransactionBeforeRedemption()
    {
        using var fixture = new IdentityFixture(); var auth = OAuthClientAuthentication.Public("app");
        foreach (var mode in Enum.GetValues<OidcAuthorizationResponseMode>())
        {
            var tx = new OidcLoginTransaction(fixture.Oidc, "app", new("https://app.invalid/callback"), options: new() { ResponseMode = mode });
            string nonce = Parse(tx.AuthorizationUri.Query)["nonce"];
            fixture.Handler.Reply = request => request.RequestUri!.AbsolutePath.EndsWith("/certs", StringComparison.Ordinal) ? fixture.Jwks()
                : new JsonObject { ["id_token"] = fixture.Token(nonce: nonce), ["access_token"] = "access" }.ToJsonString();
            var values = mode.Signed() ? new Dictionary<string, string> { ["response"] = fixture.AuthorizationResponse(tx.State) }
                : new Dictionary<string, string> { ["state"] = tx.State, ["code"] = "code", ["iss"] = fixture.Oidc.Issuer.AbsoluteUri };
            OidcLoginResult result;
            if (mode.Post()) result = await tx.CompleteFormPostAsync(new("https://app.invalid/callback"), values, auth, new(fixture.Oidc, "app"));
            else result = await tx.CompleteAsync(new("https://app.invalid/callback" + (mode.Fragment() ? "#" : "?") + string.Join('&', values.Select(p => Uri.EscapeDataString(p.Key) + "=" + Uri.EscapeDataString(p.Value)))), auth, new(fixture.Oidc, "app"));
            Assert.AreEqual("user", result.Identity.Subject);
        }
        Assert.Throws<ArgumentOutOfRangeException>(() => new OidcLoginTransaction(fixture.Oidc, "app", new("https://app.invalid/callback"), options: new() { ResponseMode = (OidcAuthorizationResponseMode)99 }));
    }

    [TestMethod]
    public async Task SignedAndEncryptedResponsesRejectDowngradeWrongTrustStateAndUnavailableKeys()
    {
        using var fixture = new IdentityFixture(); using var encryptionKey = RSA.Create(2048); using var wrongKey = RSA.Create(2048);
        var auth = OAuthClientAuthentication.Public("app"); var validator = new OidcTokenValidator(fixture.Oidc, "app", decryptionKeys: [new RsaSecurityKey(encryptionKey)]);
        foreach (string algorithm in new[] { "RSA-OAEP", "RSA-OAEP-256" })
        {
            var encrypting = new EncryptingCredentials(new RsaSecurityKey(encryptionKey), algorithm, "A256CBC-HS512") { CryptoProviderFactory = new JweCryptoProviderFactory() };
            await validator.ValidateIdTokenAsync(fixture.Token(encryption: encrypting), "nonce", "access");
            string response = fixture.AuthorizationResponse("state", encryption: encrypting);
            await validator.ValidateAuthorizationResponseAsync(response, CancellationToken.None);
            await Assert.ThrowsAsync<InvalidDataException>(() => new OidcTokenValidator(fixture.Oidc, "app").ValidateAuthorizationResponseAsync(response, CancellationToken.None));
            await Assert.ThrowsAsync<InvalidDataException>(() => new OidcTokenValidator(fixture.Oidc, "app", decryptionKeys: [new RsaSecurityKey(wrongKey)]).ValidateAuthorizationResponseAsync(response, CancellationToken.None));
            string[] parts = response.Split('.'); parts[0] = Base64UrlEncoder.Encode("{\"alg\":\"RSA1_5\",\"enc\":\"A256CBC-HS512\"}");
            await Assert.ThrowsAsync<InvalidDataException>(() => validator.ValidateAuthorizationResponseAsync(string.Join('.', parts), CancellationToken.None));
        }
        foreach (var invalid in new[] { fixture.AuthorizationResponse("state", issuer: "https://other.invalid"), fixture.AuthorizationResponse("state", audience: "other"),
            fixture.AuthorizationResponse("state", expired: true), fixture.AuthorizationResponse("state", type: "Bearer"), "invalid.jwt" })
            await Assert.ThrowsAsync<InvalidDataException>(() => validator.ValidateAuthorizationResponseAsync(invalid, CancellationToken.None));
        await validator.ValidateAuthorizationResponseAsync(fixture.AuthorizationResponse("state", type: "oauth-authz-resp+jwt"), CancellationToken.None);
        foreach (Func<string, Dictionary<string, string>> input in new Func<string, Dictionary<string, string>>[]
        {
            state => new() { ["state"] = state, ["code"] = "plain" }, state => new() { ["response"] = fixture.AuthorizationResponse("other") },
            state => new() { ["response"] = fixture.AuthorizationResponse(state), ["state"] = state },
            state => new() { ["response"] = fixture.AuthorizationResponse(state, mutate: c => c["code"] = 42) },
            state => new() { ["response"] = fixture.AuthorizationResponse(state, mutate: c => c.Remove("state")) }
        })
        {
            var tx = new OidcLoginTransaction(fixture.Oidc, "app", new("https://app.invalid/callback"), options: new() { ResponseMode = OidcAuthorizationResponseMode.FormPostJwt });
            await Assert.ThrowsAsync<InvalidDataException>(() => tx.CompleteFormPostAsync(new("https://app.invalid/callback"), input(tx.State), auth, validator));
        }
        var plain = new OidcLoginTransaction(fixture.Oidc, "app", new("https://app.invalid/callback"));
        await Assert.ThrowsAsync<InvalidDataException>(() => plain.CompleteAsync(new("https://app.invalid/callback?response=" + fixture.AuthorizationResponse(plain.State)), auth, validator));
    }

    [TestMethod]
    public async Task CallbackInputsAreBoundedAndCannotChangeTheirDeclaredResponseTransport()
    {
        using var fixture = new IdentityFixture(); var auth = OAuthClientAuthentication.Public("app"); var validator = new OidcTokenValidator(fixture.Oidc, "app");
        var post = new OidcLoginTransaction(fixture.Oidc, "app", new("https://app.invalid/callback"), options: new() { ResponseMode = OidcAuthorizationResponseMode.FormPost });
        foreach (var invalid in new IEnumerable<KeyValuePair<string, string>>[] { [new("", "x")], [new("state", null!)], [new("a", "1"), new("a", "2")],
            Enumerable.Range(0, 33).Select(i => KeyValuePair.Create("p" + i, "v")), [new("state", new string('x', 131073))] })
            await Assert.ThrowsAsync<InvalidDataException>(() => post.CompleteFormPostAsync(new("https://app.invalid/callback"), invalid, auth, validator));
        await Assert.ThrowsAsync<InvalidDataException>(() => post.CompleteAsync(new("https://app.invalid/callback?state=s&code=c"), auth, validator));
        await Assert.ThrowsAsync<InvalidDataException>(() => post.CompleteFormPostAsync(new("https://other.invalid/callback"), [], auth, validator));
        await Assert.ThrowsAsync<ArgumentNullException>(() => post.CompleteFormPostAsync(null!, [], auth, validator));
        await Assert.ThrowsAsync<ArgumentNullException>(() => post.CompleteFormPostAsync(new("https://app.invalid/callback"), null!, auth, validator));
        var plain = new OidcLoginTransaction(fixture.Oidc, "app", new("https://app.invalid/callback"));
        await Assert.ThrowsAsync<InvalidDataException>(() => plain.CompleteFormPostAsync(new("https://app.invalid/callback"), [], auth, validator));
        await Assert.ThrowsAsync<InvalidDataException>(() => plain.CompleteAsync(new("https://app.invalid/callback?x=" + new string('x', 33000)), auth, validator));
        var fragment = new OidcLoginTransaction(fixture.Oidc, "app", new("https://app.invalid/callback"), options: new() { ResponseMode = OidcAuthorizationResponseMode.Fragment });
        await Assert.ThrowsAsync<InvalidDataException>(() => fragment.CompleteAsync(new("https://app.invalid/callback?state=x#code=y"), auth, validator));
    }

    [TestMethod]
    public async Task IdTokenValidationRejectsUntrustedClaimsSignaturesAndAlgorithms()
    {
        using var fixture = new IdentityFixture();
        var validator = new OidcTokenValidator(fixture.Oidc, "app", ["RS256", "RS384", "RS512"]);
        var identity = await validator.ValidateIdTokenAsync(fixture.Token(), "nonce", "access");
        Assert.AreEqual("user", identity.Subject); Assert.AreEqual(fixture.Oidc.Issuer.AbsoluteUri, identity.Issuer);
        Assert.AreEqual("user", identity.Claims["sub"]);
        foreach (string algorithm in new[] { "RS256", "RS384", "RS512" })
            await validator.ValidateIdTokenAsync(fixture.Token(algorithm: algorithm, hash: true), "nonce", "access");
        foreach (var token in new[]
        {
            fixture.Token(issuer: "https://attacker.invalid"), fixture.Token(audience: "wrong"),
            fixture.Token(expired: true), fixture.Token(nonce: "other"), fixture.Token(nonce: null),
            fixture.Token(subject: ""), fixture.Token(issuedAt: DateTimeOffset.UtcNow.AddHours(1)),
            fixture.Token(issuedAt: DateTimeOffset.MinValue), fixture.Token(azp: "other"), fixture.Token(multipleAudiences: true),
            fixture.Token(hash: true, access: "other"), fixture.Token(algorithm: "RS384"), "not.jwt"
        })
        {
            var strict = new OidcTokenValidator(fixture.Oidc, "app");
            var error = await Assert.ThrowsAsync<InvalidDataException>(() => strict.ValidateIdTokenAsync(token, "nonce", "access"));
            Assert.IsFalse(error.ToString().Contains(token, StringComparison.Ordinal));
        }
        await validator.ValidateIdTokenAsync(fixture.Token(azp: "app", multipleAudiences: true), "nonce", "access");
        Assert.AreEqual("user", (await validator.ValidateExchangedIdTokenAsync(fixture.Token(nonce: null))).Subject);
        await Assert.ThrowsAsync<InvalidDataException>(() => validator.ValidateExchangedIdTokenAsync(fixture.Token(hash: true)));
        await Assert.ThrowsAsync<InvalidDataException>(() => validator.ValidateExchangedIdTokenAsync(fixture.Token(type: "Bearer")));
        using var other = RSA.Create(2048);
        await Assert.ThrowsAsync<InvalidDataException>(() => validator.ValidateIdTokenAsync(fixture.Token(signingKey: other), "nonce", "access"));
        // A new signing key with the same issuer is accepted only once its public key is served by the pinned realm.
        fixture.Key = other;
        await validator.ValidateIdTokenAsync(fixture.Token(), "nonce", "access");
        using var ct = new CancellationTokenSource(); ct.Cancel(); int calls = fixture.Handler.Calls;
        await Assert.ThrowsAsync<OperationCanceledException>(() => validator.ValidateIdTokenAsync(fixture.Token(), "nonce", "access", ct.Token));
        Assert.AreEqual(calls, fixture.Handler.Calls);
        Assert.Throws<ArgumentException>(() => new OidcTokenValidator(fixture.Oidc, "app", ["none"]));
        Assert.Throws<ArgumentException>(() => new OidcTokenValidator(fixture.Oidc, "app", ["HS256"]));
        Assert.Throws<ArgumentException>(() => new OidcTokenValidator(fixture.Oidc, "app", []));
    }

    [TestMethod]
    public async Task LoginRequiresBoundStateNonceDestinationAndOneTimeRedemption()
    {
        using var fixture = new IdentityFixture();
        var validator = new OidcTokenValidator(fixture.Oidc, "app");
        var auth = OAuthClientAuthentication.Public("app");
        var transaction = new OidcLoginTransaction(fixture.Oidc, "app", new("https://app.invalid/callback"));
        var query = Parse(transaction.AuthorizationUri.Query);
        Assert.AreEqual("S256", query["code_challenge_method"]);
        Assert.AreEqual(transaction.State, query["state"]);
        fixture.Handler.Reply = request => request.RequestUri!.AbsolutePath.EndsWith("/certs", StringComparison.Ordinal)
            ? fixture.Jwks() : new JsonObject { ["id_token"] = fixture.Token(nonce: query["nonce"]), ["access_token"] = "access" }.ToJsonString();
        var callback = new Uri("https://app.invalid/callback?state=" + transaction.State + "&code=one-time&iss=" + Uri.EscapeDataString(fixture.Oidc.Issuer.AbsoluteUri));
        await Assert.ThrowsAsync<InvalidDataException>(() => transaction.CompleteAsync(new("https://other.invalid/callback?state=" + transaction.State + "&code=c"), auth, validator));
        await Assert.ThrowsAsync<InvalidDataException>(() => transaction.CompleteAsync(new("https://app.invalid/callback?state=wrong&code=c"), auth, validator));
        await Assert.ThrowsAsync<InvalidDataException>(() => transaction.CompleteAsync(new(callback + "&state=duplicate"), auth, validator));
        Assert.AreEqual(0, fixture.Handler.Calls);
        var result = await transaction.CompleteAsync(callback, auth, validator);
        Assert.AreEqual("user", result.Identity.Subject);
        Assert.AreEqual(2, fixture.Handler.Calls);
        await Assert.ThrowsAsync<InvalidDataException>(() => transaction.CompleteAsync(callback, auth, validator));
        Assert.AreEqual(2, fixture.Handler.Calls);
        var clock = new ControlledClock();
        var expired = new OidcLoginTransaction(fixture.Oidc, "app", new("https://app.invalid/callback"), clock: clock);
        clock.Advance(TimeSpan.FromMinutes(6));
        await Assert.ThrowsAsync<InvalidDataException>(() => expired.CompleteAsync(new("https://app.invalid/callback?state=" + expired.State + "&code=c"), auth, validator));
        foreach (string suffix in new[] { "&error=access_denied", "", "&code=c&iss=https://wrong.invalid" })
        {
            var tx = new OidcLoginTransaction(fixture.Oidc, "app", new("https://app.invalid/callback"));
            await Assert.ThrowsAsync<InvalidDataException>(() => tx.CompleteAsync(new("https://app.invalid/callback?state=" + tx.State + suffix), auth, validator));
        }
        Assert.Throws<ArgumentException>(() => new OidcLoginTransaction(fixture.Oidc, "app", new("https://app.invalid/callback"), "email"));
        Assert.Throws<ArgumentOutOfRangeException>(() => new OidcLoginTransaction(fixture.Oidc, "app", new("https://app.invalid/callback"), lifetime: TimeSpan.Zero));
        Assert.Throws<ArgumentOutOfRangeException>(() => new OidcLoginTransaction(fixture.Oidc, "app", new("https://app.invalid/callback"), lifetime: TimeSpan.FromHours(1)));
        Assert.Throws<ArgumentException>(() => new OidcLoginTransaction(fixture.Oidc, "app", new("https://app.invalid/callback?fixed=1")));
    }

    [TestMethod]
    public async Task PollingHonorsPendingSlowDownDenialExpiryAndCancellation()
    {
        using var handler = new ReplyHandler(); using var http = new HttpClient(handler);
        var oidc = new OidcClient(new(http, new("https://identity.invalid"), "r")); var auth = OAuthClientAuthentication.Public("app");
        var clock = new ControlledClock();
        var lease = OAuthPollingLease.FromDeviceResponse(Response("""{"device_code":"secret","expires_in":60,"interval":1}"""), clock);
        handler.Status = HttpStatusCode.BadRequest;
        handler.Reply = _ => handler.Calls switch { 1 => """{"error":"authorization_pending"}""", 2 => """{"error":"slow_down"}""", _ => "{}" };
        var polling = oidc.PollDeviceAsync(auth, lease, clock);
        Assert.AreEqual(0, handler.Calls);
        clock.Advance(TimeSpan.FromSeconds(1)); await SpinUntil(() => handler.Calls == 1 && clock.HasTimer);
        clock.Advance(TimeSpan.FromSeconds(1)); await SpinUntil(() => handler.Calls == 2 && clock.HasTimer);
        clock.Advance(TimeSpan.FromSeconds(5)); Assert.AreEqual(2, handler.Calls);
        handler.Status = HttpStatusCode.OK;
        clock.Advance(TimeSpan.FromSeconds(1)); await polling;
        Assert.AreEqual(3, handler.Calls);
        var ciba = OAuthPollingLease.FromCibaResponse(Response("""{"auth_req_id":"secret","expires_in":6}"""), clock);
        handler.Status = HttpStatusCode.BadRequest; handler.Reply = _ => """{"error":"access_denied","error_description":"secret"}""";
        var denied = oidc.PollBackchannelAsync(auth, ciba, clock); clock.Advance(TimeSpan.FromSeconds(5));
        var error = await Assert.ThrowsAsync<KeycloakProtocolException>(() => denied);
        Assert.AreEqual(OAuthError.AccessDenied, error.Error); Assert.IsFalse(error.ToString().Contains("secret", StringComparison.Ordinal));
        clock.Advance(TimeSpan.FromSeconds(1)); int before = handler.Calls;
        Assert.AreEqual(OAuthError.ExpiredToken, (await Assert.ThrowsAsync<KeycloakProtocolException>(() => oidc.PollBackchannelAsync(auth, ciba, clock))).Error);
        Assert.AreEqual(before, handler.Calls);
        using var cancellation = new CancellationTokenSource();
        var fresh = OAuthPollingLease.FromCibaResponse(Response("""{"auth_req_id":"secret","expires_in":60}"""), clock);
        var cancelled = oidc.PollBackchannelAsync(auth, fresh, clock, cancellation.Token); cancellation.Cancel();
        await Assert.ThrowsAsync<TaskCanceledException>(() => cancelled); Assert.AreEqual(before, handler.Calls);
        foreach (string json in new[] { """{"device_code":"","expires_in":60}""", """{"device_code":"c","expires_in":0}""", """{"device_code":"c","expires_in":86401}""", """{"device_code":"c","expires_in":60,"interval":0}""", """{"device_code":"c","expires_in":60,"interval":86401}""" })
            Assert.Throws<InvalidDataException>(() => OAuthPollingLease.FromDeviceResponse(Response(json), clock));
    }

    [TestMethod]
    public async Task CibaRequestedLifetimeCanOnlyShortenTheServerLeaseAndNeverSendsAfterTheLocalDeadline()
    {
        var clock = new ControlledClock(); var response = Response("""{"auth_req_id":"credential","expires_in":120,"interval":5}""");
        var limited = OAuthPollingLease.FromCibaResponse(response, clock, TimeSpan.FromSeconds(3));
        Assert.AreEqual(clock.GetUtcNow().AddSeconds(3), limited.ExpiresAt);
        Assert.AreEqual(clock.GetUtcNow().AddSeconds(120), OAuthPollingLease.FromCibaResponse(response, clock, TimeSpan.FromMinutes(5)).ExpiresAt);
        Assert.AreEqual(clock.GetUtcNow().AddSeconds(120), OAuthPollingLease.FromCibaResponse(response, clock, TimeSpan.FromSeconds(120)).ExpiresAt);
        foreach (var invalid in new[] { TimeSpan.Zero, TimeSpan.FromTicks(-1), TimeSpan.FromDays(1).Add(TimeSpan.FromTicks(1)) })
            Assert.Throws<ArgumentOutOfRangeException>(() => OAuthPollingLease.FromCibaResponse(response, clock, invalid));
        using var handler = new ReplyHandler(); using var http = new HttpClient(handler);
        var oidc = new OidcClient(new(http, new("https://identity.invalid"), "r"));
        Assert.AreEqual(OAuthError.ExpiredToken, (await Assert.ThrowsAsync<KeycloakProtocolException>(() => oidc.PollBackchannelAsync(OAuthClientAuthentication.Public("app"), limited, clock))).Error);
        Assert.AreEqual(0, handler.Calls);
    }

    [TestMethod]
    public async Task OAuthErrorsAreBoundedAndAllowlistedWithoutExposingBodies()
    {
        using var handler = new ReplyHandler { Status = HttpStatusCode.BadRequest }; using var http = new HttpClient(handler);
        var client = new OidcClient(new(http, new("https://identity.invalid"), "r"));
        foreach (var (wire, expected) in new[] { ("expired_token", OAuthError.ExpiredToken), ("invalid_target", OAuthError.InvalidTarget), ("invalid_grant", OAuthError.InvalidGrant), ("invalid_client", OAuthError.InvalidClient), ("invalid_request", OAuthError.InvalidRequest), ("invalid_scope", OAuthError.InvalidScope), ("use_dpop_nonce", OAuthError.UseDpopNonce), ("unknown-secret", OAuthError.Unknown) })
        {
            handler.Reply = _ => new JsonObject { ["error"] = wire }.ToJsonString();
            Assert.AreEqual(expected, (await Assert.ThrowsAsync<KeycloakProtocolException>(() => client.DiscoverAsync())).Error);
        }
        foreach (string body in new[] { new string('x', 8192), "not-json", "[]", "{}", """{"error":23}""" })
        {
            handler.Reply = _ => body;
            Assert.AreEqual(OAuthError.Unknown, (await Assert.ThrowsAsync<KeycloakProtocolException>(() => client.DiscoverAsync())).Error);
        }
        foreach (var (wire, expected) in new[] { ("invalidFilter", ScimError.InvalidFilter), ("tooMany", ScimError.TooMany), ("uniqueness", ScimError.Uniqueness),
            ("mutability", ScimError.Mutability), ("invalidSyntax", ScimError.InvalidSyntax), ("invalidPath", ScimError.InvalidPath), ("noTarget", ScimError.NoTarget),
            ("invalidValue", ScimError.InvalidValue), ("sensitive", ScimError.Sensitive), ("unknown-secret", ScimError.Unknown) })
        {
            handler.Reply = _ => new JsonObject { ["scimType"] = wire, ["detail"] = "secret-value" }.ToJsonString();
            var error = await Assert.ThrowsAsync<KeycloakProtocolException>(() => client.DiscoverAsync());
            Assert.AreEqual(expected, error.ScimError); Assert.IsFalse(error.ToString().Contains("secret-value", StringComparison.Ordinal));
        }
        handler.Reply = _ => """{"error":"invalid_request","scimType":42}""";
        Assert.AreEqual(ScimError.None, (await Assert.ThrowsAsync<KeycloakProtocolException>(() => client.DiscoverAsync())).ScimError);
    }

    [TestMethod]
    public async Task SecurityTransactionsRejectMissingTokensClientsAndExpiredSchedulers()
    {
        using var fixture = new IdentityFixture();
        var validator = new OidcTokenValidator(fixture.Oidc, "app"); var auth = OAuthClientAuthentication.Public("app");
        Assert.Throws<ArgumentNullException>(() => new OidcTokenValidator(null!, "app"));
        Assert.Throws<ArgumentNullException>(() => new OidcLoginTransaction(null!, "app", new("https://app.invalid/callback")));
        Assert.Throws<ArgumentException>(() => new OidcTokenValidator(fixture.Oidc, " "));
        fixture.Handler.Reply = _ => "";
        await Assert.ThrowsAsync<InvalidDataException>(() => validator.ValidateIdTokenAsync(fixture.Token(), "nonce", "access"));
        foreach (string response in new[] { "", """{"id_token":null,"access_token":"a"}""", """{"id_token":"i","access_token":null}""" })
        {
            var tx = new OidcLoginTransaction(fixture.Oidc, "app", new("https://app.invalid/callback"));
            fixture.Handler.Reply = _ => response;
            await Assert.ThrowsAsync<InvalidDataException>(() => tx.CompleteAsync(new("https://app.invalid/callback?state=" + tx.State + "&code=c"), auth, validator));
        }
        foreach (string suffix in new[] { "?code=c", "?state=", "?state=STATE&code=", "?state=STATE&code=c#fragment" })
        {
            var tx = new OidcLoginTransaction(fixture.Oidc, "app", new("https://app.invalid/callback"));
            await Assert.ThrowsAsync<InvalidDataException>(() => tx.CompleteAsync(new("https://app.invalid/callback" + suffix.Replace("STATE", tx.State, StringComparison.Ordinal)), auth, validator));
        }
        var pending = new OidcLoginTransaction(fixture.Oidc, "app", new("https://app.invalid/callback"));
        var cb = new Uri("https://app.invalid/callback?state=" + pending.State + "&code=c");
        await Assert.ThrowsAsync<ArgumentException>(() => pending.CompleteAsync(cb, OAuthClientAuthentication.Public("other"), validator));
        await Assert.ThrowsAsync<ArgumentException>(() => pending.CompleteAsync(cb, auth, new(fixture.Oidc, "other")));
        using var otherHttp = new HttpClient(); var other = new OidcClient(new(otherHttp, new("https://other.invalid/"), "r"));
        await Assert.ThrowsAsync<ArgumentException>(() => pending.CompleteAsync(cb, auth, new(other, "app")));
        await Assert.ThrowsAsync<InvalidDataException>(() => pending.CompleteAsync(new("relative", UriKind.Relative), auth, validator));
        // Missing '=' and unknown extension parameters cannot make a mismatching/empty code valid.
        var extension = new OidcLoginTransaction(fixture.Oidc, "app", new("https://app.invalid/callback")); fixture.Handler.Reply = _ => "";
        await Assert.ThrowsAsync<InvalidDataException>(() => extension.CompleteAsync(new("https://app.invalid/callback?state=" + extension.State + "&code=c&extension"), auth, validator));
        var clock = new ControlledClock();
        var lease = OAuthPollingLease.FromDeviceResponse(Response("""{"device_code":"c","expires_in":60}"""));
        OAuthPollingLease.FromCibaResponse(Response("""{"auth_req_id":"c","expires_in":60}"""));
        Assert.Throws<InvalidDataException>(() => OAuthPollingLease.FromDeviceResponse(new(HttpStatusCode.OK, null)));
        Assert.Throws<InvalidDataException>(() => OAuthPollingLease.FromDeviceResponse(Response("""{"device_code":null,"expires_in":60}""")));
        var poll = fixture.Oidc.PollDeviceAsync(auth, lease, clock); clock.Advance(TimeSpan.FromSeconds(61));
        Assert.AreEqual(OAuthError.ExpiredToken, (await Assert.ThrowsAsync<KeycloakProtocolException>(() => poll)).Error);
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        await Assert.ThrowsAsync<OperationCanceledException>(() => fixture.Oidc.PollDeviceAsync(auth, lease, cancellationToken: cancelled.Token));
        await Assert.ThrowsAsync<OperationCanceledException>(() => fixture.Oidc.PollBackchannelAsync(auth, lease, cancellationToken: cancelled.Token));
    }

    private static async Task SpinUntil(Func<bool> check)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while (!check()) await Task.Delay(1, timeout.Token);
    }
    private static ProtocolResponse Response(string json) { using var document = JsonDocument.Parse(json); return new(HttpStatusCode.OK, document.RootElement.Clone()); }
    private static Dictionary<string, string> Parse(string query) => query.TrimStart('?').Split('&').Select(p => p.Split('=', 2)).ToDictionary(p => Uri.UnescapeDataString(p[0]), p => Uri.UnescapeDataString(p[1]));
    private sealed class ReplyHandler : HttpMessageHandler
    {
        public int Calls; public HttpStatusCode Status = HttpStatusCode.OK;
        public Func<HttpRequestMessage, string> Reply = _ => "{}";
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        { cancellationToken.ThrowIfCancellationRequested(); Interlocked.Increment(ref Calls); return Task.FromResult(new HttpResponseMessage(Status) { Content = new StringContent(Reply(request)) }); }
    }
    private sealed class IdentityFixture : IDisposable
    {
        private readonly RSA initialKey = RSA.Create(2048);
        public RSA Key;
        public readonly ReplyHandler Handler = new(); private readonly HttpClient http;
        public readonly OidcClient Oidc;
        public SigningCredentials Signing => new(new RsaSecurityKey(Key) { KeyId = "signer" }, "RS256");
        public IdentityFixture() { Key = initialKey; http = new(Handler); Oidc = new(new(http, new("https://identity.invalid/"), "r")); Handler.Reply = _ => Jwks(); }
        public string Jwks()
        {
            var parameters = Key.ExportParameters(false);
            return new JsonObject { ["keys"] = new JsonArray(new JsonObject { ["kty"] = "RSA", ["kid"] = "signer", ["use"] = "sig", ["n"] = Base64UrlEncoder.Encode(parameters.Modulus), ["e"] = Base64UrlEncoder.Encode(parameters.Exponent) }) }.ToJsonString();
        }
        public string AuthorizationResponse(string state, string? issuer = null, string audience = "app", string type = "JWT", bool expired = false,
            EncryptingCredentials? encryption = null, Action<Dictionary<string, object>>? mutate = null)
        {
            var claims = new Dictionary<string, object> { ["state"] = state, ["code"] = "code" }; mutate?.Invoke(claims);
            return new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(new SecurityTokenDescriptor {
                Issuer = issuer ?? Oidc.Issuer.AbsoluteUri, Audience = audience, TokenType = type, SigningCredentials = Signing, EncryptingCredentials = encryption,
                Expires = DateTime.UtcNow.AddMinutes(expired ? -5 : 5), Claims = claims });
        }
        public string Token(string? issuer = null, string audience = "app", string? nonce = "nonce", string subject = "user", bool expired = false,
            DateTimeOffset? issuedAt = default, string? azp = null, bool multipleAudiences = false, bool hash = false, string access = "access", string algorithm = "RS256", RSA? signingKey = null, string type = "JWT", EncryptingCredentials? encryption = null, Action<Dictionary<string, object>>? mutate = null)
        {
            var now = DateTimeOffset.UtcNow; var claims = new Dictionary<string, object> { ["sub"] = subject };
            if (nonce is not null) claims["nonce"] = nonce;
            if (issuedAt != DateTimeOffset.MinValue) claims["iat"] = (issuedAt ?? now).ToUnixTimeSeconds();
            if (azp is not null) claims["azp"] = azp;
            if (multipleAudiences) claims["aud"] = new[] { audience, "other" };
            if (hash)
            {
                byte[] bytes = Encoding.ASCII.GetBytes(access); byte[] digest = algorithm.EndsWith("256", StringComparison.Ordinal) ? SHA256.HashData(bytes) : algorithm.EndsWith("384", StringComparison.Ordinal) ? SHA384.HashData(bytes) : SHA512.HashData(bytes);
                claims["at_hash"] = Base64UrlEncoder.Encode(digest, 0, digest.Length / 2);
            }
            mutate?.Invoke(claims);
            return new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(new SecurityTokenDescriptor
            {
                Issuer = issuer ?? Oidc.Issuer.AbsoluteUri, Audience = multipleAudiences ? null : audience, TokenType = type, EncryptingCredentials = encryption,
                Claims = claims, NotBefore = now.AddMinutes(-10).UtcDateTime, Expires = (expired ? now.AddMinutes(-5) : now.AddMinutes(5)).UtcDateTime,
                SigningCredentials = new(new RsaSecurityKey(signingKey ?? Key) { KeyId = "signer" }, algorithm)
            });
        }
        public void Dispose() { http.Dispose(); initialKey.Dispose(); }
    }
    private sealed class ControlledClock : TimeProvider
    {
        private DateTimeOffset now = DateTimeOffset.UtcNow; private readonly List<ClockTimer> timers = [];
        public override DateTimeOffset GetUtcNow() => now;
        public bool HasTimer { get { lock (timers) return timers.Any(t => !t.Disposed); } }
        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        { var timer = new ClockTimer(this, callback, state, now + dueTime); lock (timers) timers.Add(timer); return timer; }
        public void Advance(TimeSpan duration)
        { now += duration; ClockTimer[] ready; lock (timers) { ready = timers.Where(t => !t.Disposed && t.Due <= now).ToArray(); foreach (var timer in ready) timer.Disposed = true; } foreach (var timer in ready) timer.Callback(timer.State); }
        private sealed class ClockTimer(ControlledClock owner, TimerCallback callback, object? state, DateTimeOffset due) : ITimer
        {
            internal readonly TimerCallback Callback = callback; internal readonly object? State = state;
            internal DateTimeOffset Due = due; internal bool Disposed;
            public bool Change(TimeSpan dueTime, TimeSpan period) { Due = owner.now + dueTime; return true; }
            public void Dispose() { lock (owner.timers) Disposed = true; }
            public ValueTask DisposeAsync() { Dispose(); return ValueTask.CompletedTask; }
        }
    }
}
