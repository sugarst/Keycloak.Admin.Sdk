using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using static LiveContext;

internal static class FullCaches
{
    public static async Task RunAsync(LiveContext c, LiveFacts f, HttpClient http, Uri server)
    {
        await using (var pg = await PostgresFixture.Connect(c.Cancellation))
        {
            var version = await pg.Query("SELECT current_setting('server_version'),current_setting('server_version_num'),current_database()", c.Cancellation);
            c.Prove(version.Count == 1 && version[0][1] == "180000", "Real backing database reports PostgreSQL 18.0");
            c.Evidence("postgres", new JsonObject { ["version"] = version[0][0], ["versionNumber"] = version[0][1], ["database"] = version[0][2] });
            var realm = await c.Get(""); string previous = S(realm.J, "displayName");
            // Generated realm ID is escaped as a SQL literal; this touches only our isolated realm.
            string id = c.RealmId.Replace("'", "''", StringComparison.Ordinal);
            var rows = await pg.Query("UPDATE realm SET display_name='External PostgreSQL cache mutation' WHERE id='" + id + "' RETURNING id", c.Cancellation);
            c.Prove(rows.Count == 1 && rows[0][0] == c.RealmId, "Actual PostgreSQL out-of-band mutation affects only isolated realm");
            var warm = await c.Get("");
            c.Prove(S(warm.J, "displayName") == previous, "Realm cache still holds old configuration before explicit eviction");
            var clear = await c.Post("clear-realm-cache"); var fresh = await c.Get("");
            c.Prove(S(fresh.J, "displayName") == "External PostgreSQL cache mutation", "Clearing realm cache exposes actual out-of-band PostgreSQL mutation", clear, fresh);
        }
        await Keys(c, http, server);
        await Crl(c, f, http, server);
        Console.WriteLine("PASS full caches: PostgreSQL stale/fresh realm state, changed remote RSA JWKS and actual X509 CRL revocation.");
    }
    private static string B64(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    private static string Jwt(RSA rsa, JsonObject payload, string kid)
    {
        string data = B64(Encoding.UTF8.GetBytes(LiveJson.String(new JsonObject { ["alg"] = "RS256", ["typ"] = "JWT", ["kid"] = kid }))) + "." + B64(Encoding.UTF8.GetBytes(LiveJson.String(payload)));
        return data + "." + B64(rsa.SignData(Encoding.ASCII.GetBytes(data), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }
    private static async Task Keys(LiveContext c, HttpClient http, Uri server)
    {
        await using var callback = new CallbackFixture(c.Cancellation); using var first = RSA.Create(2048); using var second = RSA.Create(2048);
        RSA active = first;
        callback.Responder = (_, _, _) => { var key = active.ExportParameters(false); return (200, "application/json", LiveJson.String(new JsonObject { ["keys"] = new JsonArray(new JsonObject { ["kid"] = "full-cache-key", ["kty"] = "RSA", ["use"] = "sig", ["alg"] = "RS256", ["n"] = B64(key.Modulus!), ["e"] = B64(key.Exponent!) }) })); };
        var client = await c.Post("clients", new JsonObject { ["clientId"] = "full-jwt-cache", ["enabled"] = true, ["publicClient"] = false, ["protocol"] = "openid-connect", ["clientAuthenticatorType"] = "client-jwt", ["serviceAccountsEnabled"] = true, ["attributes"] = new JsonObject { ["use.jwks.url"] = "true", ["jwks.url"] = callback.WebUrl + "/jwks" } });
        async Task<bool> Authenticate(RSA signing)
        {
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            string assertion = Jwt(signing, new JsonObject { ["iss"] = "full-jwt-cache", ["sub"] = "full-jwt-cache", ["aud"] = new Uri(server, "realms/" + c.Realm + "/protocol/openid-connect/token").AbsoluteUri, ["iat"] = now, ["exp"] = now + 60, ["jti"] = Guid.NewGuid().ToString("N") }, "full-cache-key");
            using var form = new FormUrlEncodedContent(new Dictionary<string, string> { ["grant_type"] = "client_credentials", ["client_id"] = "full-jwt-cache", ["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", ["client_assertion"] = assertion });
            using var reply = await http.PostAsync(new Uri(server, "realms/" + c.Realm + "/protocol/openid-connect/token"), form, cancellationToken: c.Cancellation);
            string body = await reply.Content.ReadAsStringAsync(cancellationToken: c.Cancellation);
            return reply.IsSuccessStatusCode && S(JsonNode.Parse(body), "access_token").Length > 100;
        }
        c.Prove(await Authenticate(first) && callback.Requests.Count == 1, "Real signed client assertion authenticates and warms remote public-key cache");
        active = second;
        c.Prove(await Authenticate(first) && callback.Requests.Count == 1, "Changed remote key remains invisible while old key is cached");
        var clear = await c.Post("clear-keys-cache");
        c.Prove(await Authenticate(second) && callback.Requests.Count >= 2, "Clear keys cache refetches changed JWKS and accepts assertion signed with new RSA key", clear);
        await c.Delete("clients/{client-uuid}", ("client-uuid", client.Id));
    }
    private static async Task Crl(LiveContext c, LiveFacts f, HttpClient http, Uri server)
    {
        await using var callback = new CallbackFixture(c.Cancellation); using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=full-user", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyCertSign, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));
        var crl = new CertificateRevocationListBuilder();
        string CrlBody(int number) => PemEncoding.WriteString("X509 CRL", crl.Build(cert, number, DateTimeOffset.UtcNow.AddHours(1), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1, DateTimeOffset.UtcNow.AddSeconds(-30)));
        string body = CrlBody(1);
        callback.Responder = (_, _, _) => (200, "application/pkix-crl", body);
        var flow = await c.Post("authentication/flows", O("""{"alias":"full-x509-cache","providerId":"basic-flow","topLevel":true,"builtIn":false}"""));
        await c.Post("authentication/flows/{flowAlias}/executions/execution", O("""{"provider":"direct-grant-auth-x509-username"}"""), paths: [("flowAlias", "full-x509-cache")]);
        var executions = await c.Get("authentication/flows/{flowAlias}/executions", null, ("flowAlias", "full-x509-cache"));
        var execution = executions.J!.AsArray().Single()!.DeepClone(); execution["requirement"] = "REQUIRED";
        await c.Put("authentication/flows/{flowAlias}/executions", execution, ("flowAlias", "full-x509-cache"));
        var config = new JsonObject { ["alias"] = "full-x509-crl", ["config"] = new JsonObject
        {
            ["x509-cert-auth.mapping-source-selection"] = "Subject's Common Name", ["x509-cert-auth.mapper-selection"] = "Username or Email",
            ["x509-cert-auth.crl-checking-enabled"] = "true", ["x509-cert-auth.crldp-checking-enabled"] = "false",
            ["x509-cert-auth.crl-relative-path"] = callback.WebUrl + "/full.crl", ["x509-cert-auth.timestamp-validation-enabled"] = "true",
            ["x509-cert-auth.revalidate-certificate-enabled"] = "false"
        } };
        await c.Post("authentication/executions/{executionId}/config", config, paths: [("executionId", S(execution, "id"))]);
        await c.Put("clients/{client-uuid}", new JsonObject { ["authorizationServicesEnabled"] = true, ["authenticationFlowBindingOverrides"] = new JsonObject { ["direct_grant"] = flow.Id } }, ("client-uuid", f.Client));
        async Task<(bool Success, string Error)> Authenticate()
        {
            using var message = new HttpRequestMessage(HttpMethod.Post, new Uri(server, "realms/" + c.Realm + "/protocol/openid-connect/token"));
            message.Headers.TryAddWithoutValidation("Client-Cert", Convert.ToBase64String(cert.RawData));
            message.Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["grant_type"] = "password", ["client_id"] = "full-client", ["client_secret"] = "full-client-secret" });
            using var reply = await http.SendAsync(message, cancellationToken: c.Cancellation); return (reply.IsSuccessStatusCode, await reply.Content.ReadAsStringAsync(cancellationToken: c.Cancellation));
        }
        var accepted = await Authenticate();
        c.Prove(accepted.Success && callback.Requests.Count == 1, "Actual X509 direct grant succeeds with downloaded unrevoked CRL: " + (accepted.Success ? "verified" : accepted.Error));
        crl.AddEntry(cert, DateTimeOffset.UtcNow.AddSeconds(-10), X509RevocationReason.KeyCompromise); body = CrlBody(2);
        accepted = await Authenticate();
        c.Prove(accepted.Success && callback.Requests.Count == 1, "Old CRL remains cached after remote certificate revocation");
        var clear = await c.Post("clear-crl-cache"); var denied = await Authenticate();
        c.Prove(!denied.Success && denied.Error.Contains("revoked", StringComparison.OrdinalIgnoreCase) && callback.Requests.Count >= 2, "Clearing CRL cache refetches changed signed CRL and rejects revoked certificate authentication", clear);
    }
}
