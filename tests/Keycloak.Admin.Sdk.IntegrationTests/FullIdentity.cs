using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using static LiveContext;

internal static class FullIdentity
{
    public static async Task RunAsync(LiveContext c, LiveFacts f, Uri server)
    {
        await using var callback = new CallbackFixture();
        using var rsa = RSA.Create(2048);
        var publicKey = rsa.ExportParameters(false);
        string kid = "full-jwk-one";
        callback.Responder = (method, path, _) => path == "/jwks" ? (200, "application/json", LiveJson.String(new JsonObject
        {
            ["keys"] = new JsonArray(new JsonObject { ["kid"] = kid, ["kty"] = "RSA", ["alg"] = "RS256", ["use"] = "sig", ["n"] = B64(publicKey.Modulus!), ["e"] = B64(publicKey.Exponent!) })
        })) : path == "/metadata" ? (200, "application/samlmetadata+xml", CallbackFixture.Metadata) : (404, "text/plain", "Not found");
        var factory = await c.Get("identity-provider/providers/{provider_id}", null, ("provider_id", "oidc"));
        c.Prove(S(factory.J, "id") == "oidc", "Provider discovery returns installed OIDC implementation", factory);
        var upload = new MultipartFormDataContent(); upload.Add(new StringContent("saml"), "providerId"); upload.Add(new StringContent(CallbackFixture.Metadata, Encoding.UTF8, "application/xml"), "file", "metadata.xml");
        var imported = await c.Call("POST", "identity-provider/import-config", raw: upload);
        c.Prove(S(imported.J, "singleSignOnServiceUrl") == "https://idp.example.invalid/sso", "Multipart SAML metadata is parsed by actual Keycloak importer", imported);
        var fetched = await c.Post("identity-provider/import-config", new JsonObject { ["providerId"] = "saml", ["fromUrl"] = callback.MetadataUrl });
        c.Prove(S(fetched.J, "singleSignOnServiceUrl") == "https://idp.example.invalid/sso" && callback.MetadataRequests == 1, "JSON metadata import performs a real HTTP fetch and parses metadata", fetched);
        var saml = new JsonObject { ["alias"] = "full-saml-idp", ["providerId"] = "saml", ["enabled"] = true, ["config"] = imported.J!.DeepClone() };
        var createdSaml = await c.Post("identity-provider/instances", saml);
        var oidcConfig = new JsonObject
        {
            ["authorizationUrl"] = new Uri(server, "realms/" + c.Realm + "/protocol/openid-connect/auth").AbsoluteUri,
            ["tokenUrl"] = new Uri(server, "realms/" + c.Realm + "/protocol/openid-connect/token").AbsoluteUri,
            ["clientId"] = "full-client", ["clientSecret"] = "full-client-secret", ["useJwksUrl"] = "true", ["jwksUrl"] = callback.WebUrl + "/jwks", ["validateSignature"] = "true"
        };
        var oidc = new JsonObject { ["alias"] = "full-oidc-idp", ["providerId"] = "oidc", ["enabled"] = true, ["config"] = oidcConfig };
        var create = await c.Post("identity-provider/instances", oidc);
        var idp = await c.Get("identity-provider/instances/{alias}", null, ("alias", "full-oidc-idp"));
        var list = await c.Get("identity-provider/instances");
        c.Prove(S(idp.J, "alias") == "full-oidc-idp" && Has(list.J, "alias", "full-oidc-idp") && Has(list.J, "alias", "full-saml-idp"), "Identity-provider creation persists real provider configurations", create, createdSaml, idp, list);
        var edit = oidc.DeepClone(); edit["displayName"] = "Full provider updated";
        var update = await c.Put("identity-provider/instances/{alias}", edit, ("alias", "full-oidc-idp")); idp = await c.Get("identity-provider/instances/{alias}", null, ("alias", "full-oidc-idp"));
        c.Prove(S(idp.J, "displayName") == "Full provider updated", "Provider update persists display name", update, idp);
        var reload = await c.Get("identity-provider/instances/{alias}/reload-keys", null, ("alias", "full-oidc-idp"));
        c.Prove(reload.J!.GetValue<bool>() && callback.Requests.Any(r => r.Path == "/jwks"), "Reload keys fetches a real RSA JWKS over HTTP", reload);
        kid = "full-jwk-two";
        // The real storage provider enforces a 10-second minimum JWKS refresh interval.
        await Task.Delay(TimeSpan.FromSeconds(11));
        var reloadAgain = await c.Get("identity-provider/instances/{alias}/reload-keys", null, ("alias", "full-oidc-idp"));
        c.Prove(reloadAgain.J!.GetValue<bool>() && callback.Requests.Count(r => r.Path == "/jwks") >= 2, "Reload refetches changed remote key set", reloadAgain);
        var types = await c.Get("identity-provider/instances/{alias}/mapper-types", null, ("alias", "full-saml-idp"));
        c.Prove(types.J?["saml-user-attribute-idp-mapper"] is not null, "Mapper-type discovery exposes installed SAML attribute mapper", types);
        var mapper = O("""{"name":"full-idp-mapper","identityProviderAlias":"full-saml-idp","identityProviderMapper":"saml-user-attribute-idp-mapper","config":{"attribute.name":"mail","user.attribute":"email","syncMode":"INHERIT"}}""");
        var addMapper = await c.Post("identity-provider/instances/{alias}/mappers", mapper, null, ("alias", "full-saml-idp"));
        string mapperId = addMapper.Id;
        var mapperGet = await c.Get("identity-provider/instances/{alias}/mappers/{id}", null, ("alias", "full-saml-idp"), ("id", mapperId));
        var mappers = await c.Get("identity-provider/instances/{alias}/mappers", null, ("alias", "full-saml-idp"));
        c.Prove(S(mapperGet.J, "name") == "full-idp-mapper" && Has(mappers.J, "id", mapperId), "Identity-provider mapper persists config and provider association", addMapper, mapperGet, mappers);
        mapper["id"] = mapperId; mapper["config"]!["user.attribute"] = "firstName";
        var changeMapper = await c.Put("identity-provider/instances/{alias}/mappers/{id}", mapper, ("alias", "full-saml-idp"), ("id", mapperId));
        mapperGet = await c.Get("identity-provider/instances/{alias}/mappers/{id}", null, ("alias", "full-saml-idp"), ("id", mapperId));
        c.Prove(S(mapperGet.J?["config"], "user.attribute") == "firstName", "Identity-provider mapper update changes stored attribute target", changeMapper, mapperGet);
        var exported = await c.Get("identity-provider/instances/{alias}/export", null, ("alias", "full-saml-idp"));
        string xml = Encoding.UTF8.GetString(exported.Response.Content.Span);
        c.Prove(xml.Contains("EntityDescriptor", StringComparison.Ordinal) && xml.Contains("full-saml-idp", StringComparison.Ordinal), "Provider export generates broker-specific SAML metadata", exported);
        using var cert = new CertificateRequest("CN=full-certificate", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(2));
        var certificate = new MultipartFormDataContent(); certificate.Add(new StringContent("Certificate PEM"), "keystoreFormat"); certificate.Add(new StringContent(cert.ExportCertificatePem()), "file", "certificate.pem");
        var uploaded = await c.Call("POST", "identity-provider/upload-certificate", raw: certificate);
        string encoded = S(uploaded.J, "certificate");
        using var returned = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(encoded));
        c.Prove(returned.Thumbprint == cert.Thumbprint && S(uploaded.J, "publicKey").Length > 0, "Certificate upload parses actual X509 certificate and extracts its public key", uploaded);
        if (c.Route.FgapVersion == 1) await FullRoles.Permissions(c, "identity-provider/instances/{alias}/management/permissions", [("alias", "full-oidc-idp")]);
        var federate = await c.Post("users/{user-id}/federated-identity/{provider}", O("""{"userId":"external-full-user","userName":"external-full-name"}"""), null, ("user-id", f.User), ("provider", "full-oidc-idp"));
        var identities = await c.Get("users/{user-id}/federated-identity", null, ("user-id", f.User));
        c.Prove(Has(identities.J, "identityProvider", "full-oidc-idp") && Has(identities.J, "userId", "external-full-user"), "Federated identity link persists provider and external subject", federate, identities);
        await FullOrganizations.RunAsync(c, f);
        var unfederate = await c.Delete("users/{user-id}/federated-identity/{provider}", ("user-id", f.User), ("provider", "full-oidc-idp")); identities = await c.Get("users/{user-id}/federated-identity", null, ("user-id", f.User));
        c.Prove(!Has(identities.J, "identityProvider", "full-oidc-idp"), "Federated identity removal persists", unfederate, identities);
        var dm = await c.Delete("identity-provider/instances/{alias}/mappers/{id}", ("alias", "full-saml-idp"), ("id", mapperId));
        mappers = await c.Get("identity-provider/instances/{alias}/mappers", null, ("alias", "full-saml-idp"));
        c.Prove(!Has(mappers.J, "id", mapperId), "Provider mapper deletion removes stored model", dm, mappers);
        var di = await c.Delete("identity-provider/instances/{alias}", ("alias", "full-saml-idp"));
        c.Prove(await c.Missing("identity-provider/instances/{alias}", ("alias", "full-saml-idp")), "Identity provider deletion removes its configuration", di);
        Console.WriteLine("PASS full identity: imported metadata, provider/mapper CRUD, real JWKS refetch, certificate parsing and federated subjects.");
    }
    private static string B64(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
