using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Capabilities;
using Keycloak.Admin.Sdk.Protocols;
using Microsoft.IdentityModel.Tokens;

internal static class ProtocolWalletWorkflows
{
    internal static async Task RunAsync(KeycloakAdminClient admin, HttpClient http, ProtocolTransport parent, string realm, string password, Action<bool, string> check, CancellationToken ct)
    {
        await admin.RealmAdmin.UpdateRealmAsync(realm, new() { VerifiableCredentialsEnabled = true }, ct);
        // 26.8.1 creates these SSF scopes without a protocol; OID4VC offer lookup dereferences it.
        // This explicit owned-realm setup is required when the two features coexist, not an SDK transport retry or hidden server mutation.
        foreach (var scope in (await admin.ClientScopes.GetClientScopesAsync(realm, ct)).Body!.Where(s => s.Protocol is null && s.Name is "ssf.read" or "ssf.manage"))
        { scope.Protocol = "openid-connect"; await admin.ClientScope.UpdateAsync(realm, scope.Id!, scope, ct); }
        check((await admin.ClientScopes.GetClientScopesAsync(realm, ct)).Body!.All(s => s.Protocol is not null),
            "Explicit realm scope configuration removes protocol-less SSF scopes before Keycloak 26.8.1 wallet offer lookup");
        var server = new Uri(parent.Issuer.AbsoluteUri[..parent.Issuer.AbsoluteUri.IndexOf("/realms/", StringComparison.Ordinal)] + "/");
        var enabled = new Dictionary<string, bool> { ["KeycloakSdk.Protocols"] = true, ["KeycloakSdk.Protocols.Oidc"] = true, ["KeycloakSdk.Protocols.Account"] = true,
            ["KeycloakSdk.Protocols.Wallet"] = true, ["KeycloakSdk.Protocols.WalletOffers"] = true, ["KeycloakSdk.Protocols.WalletPreAuthorized"] = true,
            ["KeycloakSdk.Protocols.WalletAttestation"] = true, ["KeycloakSdk.Protocols.WalletMdoc"] = true, ["KeycloakSdk.Protocols.WalletPresentation"] = true,
            ["KeycloakSdk.Protocols.IdentityBrokerLogin"] = true };
        var gate = new KeycloakFeatureSnapshotGate(enabled); var transport = new ProtocolTransport(http, server, realm, gate);
        var wallet = new Oid4vcIssuerClient(transport); var oidc = new OidcClient(transport); var verifier = new Oid4vcCredentialValidator(oidc, allowedAlgorithms: ["RS256", "ES256"]);
        var account = new Oid4vcAccountClient(transport); var tokens = new Oid4vcTokenClient(transport);
        using var issuerKey = RSA.Create(2048); using var caKey = RSA.Create(2048);
        var caRequest = new CertificateRequest("CN=SDK Wallet Test CA", caKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true)); caRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(caRequest.PublicKey, false));
        using var caCertificate = caRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(2));
        var signingRequest = new CertificateRequest("CN=SDK Wallet Issuer", issuerKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        signingRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        using var issuerCertificate = signingRequest.Create(caCertificate, DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1), RandomNumberGenerator.GetBytes(16));
        await admin.Component.CreateAsync(realm, new() { Name = "wallet-ca-issued-signature", ProviderType = "org.keycloak.keys.KeyProvider", ProviderId = "rsa", Config = new()
        { ["privateKey"] = [issuerKey.ExportPkcs8PrivateKeyPem()], ["certificate"] = [issuerCertificate.ExportCertificatePem()], ["active"] = ["true"], ["enabled"] = ["true"],
            ["algorithm"] = ["RS256"], ["keyUse"] = ["SIG"], ["priority"] = ["200"] } }, ct);
        var callback = new Uri("https://app.invalid/wallet"); const string clientId = "sdk-wallet";
        await admin.Clients.CreateClientAsync(realm, new() { ClientId = clientId, Enabled = true, PublicClient = true, Protocol = "openid-connect", StandardFlowEnabled = true,
            RedirectUris = [callback.AbsoluteUri], Attributes = new() { ["oid4vci.enabled"] = "true", ["pkce.code.challenge.method"] = "S256" } }, cancellationToken: ct);
        var app = (await admin.Clients.GetClientsAsync(realm, clientId: clientId, cancellationToken: ct)).Body!.Single(); var authentication = OAuthClientAuthentication.Public(clientId);
        string userId = (await admin.Users.GetUsersAsync(realm, username: "account-user", exact: true, cancellationToken: ct)).Body!.Single().Id!;
        string accountAccess = (await oidc.PasswordGrantAsync(OAuthClientAuthentication.SecretPost("sdk-protocols", _ => ValueTask.FromResult(password)), "account-user", password, cancellationToken: ct))
            .Json!.Value.GetProperty("access_token").GetString()!;
        using var holderPrivateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256); var holder = Oid4vcProofKey.FromEcdsa(holderPrivateKey);
        async Task<(OidcLoginResult Login, Oid4vcCredentialConfiguration Configuration, string Identifier)> AuthorizeAsync(string id, string? issuerState = null, string? purpose = null)
        {
            var metadata = await wallet.GetIssuerMetadataAsync(ct);
            using var details = JsonDocument.Parse(new JsonArray(new JsonObject { ["type"] = "openid_credential", ["credential_configuration_id"] = id,
                ["locations"] = new JsonArray((JsonNode)JsonValue.Create(wallet.Issuer.AbsoluteUri)!) }).ToJsonString());
            var transaction = await OidcLoginTransaction.StartAsync(oidc, authentication, callback, "openid " + id, options: new() { AuthorizationDetails = details.RootElement, IssuerState = issuerState }, cancellationToken: ct);
            var browser = await ProtocolBrowserFixture.LoginAsync(transaction.AuthorizationUri, callback, "account-user", password, ct);
            var login = await transaction.CompleteAsync(browser.Callback, authentication, new OidcTokenValidator(oidc, clientId), ct);
            var detail = login.Tokens.Json!.Value.GetProperty("authorization_details")[0];
            check(login.Identity.Subject == userId && detail.GetProperty("credential_configuration_id").GetString() == id,
                "Credential authorization code and PKCE bind the expected user and exact " + id + " configuration" + (purpose is null ? "" : " for " + purpose));
            return (login, metadata.Configurations[id], detail.GetProperty("credential_identifiers")[0].GetString()!);
        }
        async Task<string[]> ProofsAsync(int count = 1)
        {
            string nonce = (await wallet.RequestNonceAsync(ct)).Json!.Value.GetProperty("c_nonce").GetString()!;
            return Enumerable.Range(0, count).Select(_ => holder.CreateIssuanceProof(wallet.Issuer, nonce, clientId)).ToArray();
        }
        string Access(ProtocolResponse response) => response.Json!.Value.GetProperty("access_token").GetString()!;
        string Credential(ProtocolResponse response) => response.Json!.Value.GetProperty("credentials")[0].GetProperty("credential").GetString()!;
        var sessions = new Dictionary<string, (OidcLoginResult Login, Oid4vcCredentialConfiguration Configuration, string Identifier)>();
        var verifiedCredentials = new Dictionary<string, VerifiedOid4vcCredential>();
        foreach (string format in new[] { "jwt_vc_json", "dc+sd-jwt" })
        {
            string id = format == "jwt_vc_json" ? "sdk-jwt" : "sdk-sd";
            await admin.ClientScopes.CreateClientScopeAsync(realm, new() { Name = id, Protocol = "oid4vc", Attributes = new()
            {
                ["include.in.token.scope"] = "true", ["vc.credential_configuration_id"] = id, ["vc.credential_identifier"] = id,
                ["vc.format"] = format, ["vc.issuer_did"] = wallet.Issuer.AbsoluteUri, ["vc.verifiable_credential_type"] = "https://credentials.example.invalid/" + id,
                ["vc.expiry_in_seconds"] = "3600", ["vc.binding_required"] = "true", ["vc.cryptographic_binding_methods_supported"] = "jwk", ["vc.binding_required_proof_types"] = "jwt",
                ["vc.credential_signing_alg"] = "RS256", ["vc.credential_build_config.sd_jwt.visible_claims"] = "id,iat,nbf,exp,jti"
            }, ProtocolMappers = [
                new() { Name = "subject", Protocol = "oid4vc", ProtocolMapper = "oid4vc-subject-id-mapper", Config = new() { ["claim.name"] = "id", ["userAttribute"] = "username" } },
                new() { Name = "email", Protocol = "oid4vc", ProtocolMapper = "oid4vc-user-attribute-mapper", Config = new() { ["claim.name"] = "email", ["userAttribute"] = "email" } },
                new() { Name = "firstName", Protocol = "oid4vc", ProtocolMapper = "oid4vc-user-attribute-mapper", Config = new() { ["claim.name"] = "firstName", ["userAttribute"] = "firstName" } },
                new() { Name = "jti", Protocol = "oid4vc", ProtocolMapper = "oid4vc-generated-id-mapper", Config = new() { ["claim.name"] = "jti" } } ] }, ct);
            var scope = (await admin.ClientScopes.GetClientScopesAsync(realm, ct)).Body!.Single(s => s.Name == id);
            await admin.Client.AddOptionalClientScopeAsync(realm, app.Id!, scope.Id!, ct);
            using var entitlement = new StringContent(new JsonObject { ["credentialScopeName"] = id }.ToJsonString(), Encoding.UTF8, "application/json");
            var grant = await admin.UserVerifiableCredential.CreateCredentialAsync(realm, userId, entitlement, ct);
            check(grant.Body.GetProperty("credentialConfigurationId").GetString() == id
                && (await admin.UserVerifiableCredential.GetCredentialsAsync(realm, userId, ct)).Body.EnumerateArray().Any(c => c.GetProperty("credentialScopeName").GetString() == id),
                "Admin credential entitlement creation persists the expected " + id + " configuration for the independent account user");
            var session = await AuthorizeAsync(id); string access = Access(session.Login.Tokens);
            var issued = await wallet.RequestCredentialAsync(session.Configuration, access, await ProofsAsync(), session.Identifier, cancellationToken: ct);
            var verified = await verifier.ValidateAsync(Credential(issued), session.Configuration, holder.Thumbprint, ct);
            sessions[id] = session; verifiedCredentials[id] = verified;
            var subject = format == "jwt_vc_json" ? verified.Claims.GetProperty("vc").GetProperty("credentialSubject") : verified.Claims;
            check(subject.GetProperty("email").GetString() == "protocols@example.invalid" && verified.HolderThumbprint == holder.Thumbprint,
                "Real " + format + " issuance verifies the pinned issuer signature disclosed user claims and exact wallet holder key");
            string corrupted = Credential(issued); int signature = corrupted.IndexOf('.', corrupted.IndexOf('.') + 1) + 1;
            corrupted = corrupted[..signature] + (corrupted[signature] == 'A' ? 'B' : 'A') + corrupted[(signature + 1)..]; bool tampered = false;
            try { await verifier.ValidateAsync(corrupted, session.Configuration, holder.Thumbprint, ct); } catch (InvalidDataException) { tampered = true; }
            check(tampered, "A modified real " + format + " issuer signature cannot produce a verified credential");
            bool wrongHolder = false;
            try { await verifier.ValidateAsync(Credential(issued), session.Configuration, "another-wallet", ct); } catch (InvalidDataException) { wrongHolder = true; }
            check(wrongHolder, "A valid " + format + " credential bound to one wallet is refused for another holder");
            bool noProof = false;
            try { await wallet.RequestCredentialAsync(session.Configuration, access, credentialIdentifier: session.Identifier, cancellationToken: ct); } catch (KeycloakProtocolException e) when (e.StatusCode == HttpStatusCode.BadRequest) { noProof = true; }
            check(noProof, "Keycloak refuses " + format + " issuance without the configured holder proof");
            string[] batchProofs = await ProofsAsync(2);
            var batch = await wallet.RequestCredentialAsync(session.Configuration, access, batchProofs, session.Identifier, cancellationToken: ct);
            var batchCredentials = batch.Json!.Value.GetProperty("credentials");
            foreach (var item in batchCredentials.EnumerateArray()) await verifier.ValidateAsync(item.GetProperty("credential").GetString()!, session.Configuration, holder.Thumbprint, ct);
            check(batchCredentials.GetArrayLength() == 2, "A real " + format + " proof batch returns two independently verified holder-bound credentials");
            bool nonceReplay = false;
            try { await wallet.RequestCredentialAsync(session.Configuration, access, batchProofs, session.Identifier, cancellationToken: ct); }
            catch (KeycloakProtocolException e) when (e.StatusCode == HttpStatusCode.BadRequest) { nonceReplay = true; }
            check(nonceReplay, "A consumed " + format + " issuance nonce cannot be replayed even with a previously valid wallet proof");
            if (format == "dc+sd-jwt")
            {
                string presentation = verified.CreateSdJwtPresentation([], "https://verifier.example.invalid", "fresh-presentation-nonce", holder);
                check(!presentation.Contains(verified.Disclosures[0], StringComparison.Ordinal) && presentation.Split('~').Length == 2,
                    "An SD-JWT wallet discloses no optional claims unless selected and binds its presentation to the verifier and fresh nonce");
            }
            var refreshed = await tokens.RefreshCredentialTokenAsync(authentication, session.Login.Tokens.Json!.Value.GetProperty("refresh_token").GetString()!, ct);
            var refreshedCredential = await wallet.RequestCredentialAsync(session.Configuration, Access(refreshed), await ProofsAsync(), session.Identifier, cancellationToken: ct);
            check((await verifier.ValidateAsync(Credential(refreshedCredential), session.Configuration, holder.Thumbprint, ct)).Format == format,
                "OID4VCI refresh preserves " + format + " credential authorization and remains usable for holder-bound issuance");
            check((await account.GetEntitlementsAsync(accountAccess, ct)).Json!.Value.EnumerateArray().Any(c => c.GetProperty("credentialScopeName").GetString() == id),
                "The current account independently observes its own " + id + " credential entitlement");
        }
        var metadataJson = await wallet.GetIssuerMetadataAsync(ct);
        check(metadataJson.Configurations.Count >= 2 && (await wallet.GetJwtIssuerMetadataAsync(ct)).Json!.Value.GetProperty("issuer").GetString() == wallet.Issuer.AbsoluteUri,
            "Both canonical credential and JWT issuer metadata endpoints describe the pinned realm");
        var signedMetadata = await verifier.ValidateSignedMetadataAsync(await wallet.GetSignedIssuerMetadataAsync(ct), ct);
        check(signedMetadata.Configurations.ContainsKey("sdk-sd"), "Signed credential metadata verifies its type issuer subject lifetime and independently fetched realm signature");

        using var encryptionPrivate = RSA.Create(2048); var encKey = new RsaSecurityKey(encryptionPrivate); var encParameters = encryptionPrivate.ExportParameters(false);
        string responseAlgorithm = metadataJson.Document.GetProperty("credential_response_encryption").GetProperty("alg_values_supported").EnumerateArray().Select(a => a.GetString()!).First(a => a is "RSA-OAEP" or "RSA-OAEP-256");
        using var publicEncryptionJwk = JsonDocument.Parse(new JsonObject { ["kty"] = "RSA", ["alg"] = responseAlgorithm, ["n"] = Base64UrlEncoder.Encode(encParameters.Modulus), ["e"] = Base64UrlEncoder.Encode(encParameters.Exponent) }.ToJsonString());
        var issuerEncryptionKey = new JsonWebKey(metadataJson.Document.GetProperty("credential_request_encryption").GetProperty("jwks").GetProperty("keys")[0].GetRawText());
        foreach (var pair in sessions)
        {
            var session = pair.Value;
            foreach (string mode in new[] { "request", "both" })
            {
                var encryption = new Oid4vcCredentialEncryption(new(issuerEncryptionKey, issuerEncryptionKey.Alg, "A256GCM"),
                    mode == "request" ? null : encKey, mode == "request" ? null : publicEncryptionJwk.RootElement);
                var encrypted = await wallet.RequestCredentialAsync(session.Configuration, Access(session.Login.Tokens), await ProofsAsync(), session.Identifier, encryption: encryption, cancellationToken: ct);
                var payload = mode == "request" ? encrypted.Json!.Value : encryption.DecryptResponse(encrypted);
                string credential = payload.GetProperty("credentials")[0].GetProperty("credential").GetString()!;
                check((await verifier.ValidateAsync(credential, session.Configuration, holder.Thumbprint, ct)).HolderThumbprint == holder.Thumbprint,
                    "Real " + pair.Key + " " + mode + " encryption authenticates its content and still independently verifies issuer and holder binding");
            }
            bool invalidNonce = false;
            try { await wallet.RequestCredentialAsync(session.Configuration, Access(session.Login.Tokens), [holder.CreateIssuanceProof(wallet.Issuer, "not-a-valid-c-nonce", clientId)], session.Identifier, cancellationToken: ct); }
            catch (KeycloakProtocolException e) when (e.StatusCode == HttpStatusCode.BadRequest) { invalidNonce = true; }
            check(invalidNonce, "A signed " + pair.Key + " proof with an invalid issuer nonce cannot obtain a credential");
        }
        using var mdocKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var mdocCertificateRequest = new CertificateRequest("CN=SDK Wallet EC Issuer", mdocKey, HashAlgorithmName.SHA256);
        mdocCertificateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        mdocCertificateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        using var mdocCertificate = mdocCertificateRequest.Create(caCertificate.SubjectName, X509SignatureGenerator.CreateForRSA(caKey, RSASignaturePadding.Pkcs1),
            DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1), RandomNumberGenerator.GetBytes(16));
        await admin.Component.CreateAsync(realm, new() { Name = "wallet-ec-ca-issued-signature", ProviderType = "org.keycloak.keys.KeyProvider", ProviderId = "ecdsa-generated", Config = new()
        { ["ecdsaPrivateKey"] = [Convert.ToBase64String(mdocKey.ExportPkcs8PrivateKey())], ["ecdsaPublicKey"] = [Convert.ToBase64String(mdocKey.ExportSubjectPublicKeyInfo())],
            ["certificate"] = [mdocCertificate.ExportCertificatePem()], ["ecdsaEllipticCurveKey"] = ["P-256"], ["active"] = ["true"], ["enabled"] = ["true"], ["priority"] = ["300"] } }, ct);
        const string mdocType = "org.sdk.identity";
        await admin.ClientScopes.CreateClientScopeAsync(realm, new() { Name = "sdk-mdoc", Protocol = "oid4vc", Attributes = new()
        { ["include.in.token.scope"] = "true", ["vc.credential_configuration_id"] = "sdk-mdoc", ["vc.credential_identifier"] = "sdk-mdoc", ["vc.format"] = "mso_mdoc",
            ["vc.verifiable_credential_type"] = mdocType, ["vc.expiry_in_seconds"] = "3600", ["vc.binding_required"] = "true", ["vc.binding_required_proof_types"] = "jwt",
            ["vc.cryptographic_binding_methods_supported"] = "cose_key", ["vc.credential_signing_alg"] = "ES256" },
            ProtocolMappers = [new() { Name = "email", Protocol = "oid4vc", ProtocolMapper = "oid4vc-user-attribute-mapper",
                Config = new() { ["claim.name"] = "email", ["userAttribute"] = "email", ["mdoc.namespace"] = mdocType } }] }, ct);
        var mdocScope = (await admin.ClientScopes.GetClientScopesAsync(realm, ct)).Body!.Single(s => s.Name == "sdk-mdoc");
        await admin.Client.AddOptionalClientScopeAsync(realm, app.Id!, mdocScope.Id!, ct);
        using var mdocEntitlement = new StringContent("{\"credentialScopeName\":\"sdk-mdoc\"}", Encoding.UTF8, "application/json");
        await admin.UserVerifiableCredential.CreateCredentialAsync(realm, userId, mdocEntitlement, ct);
        var mdocSession = await AuthorizeAsync("sdk-mdoc");
        var mdocResponse = await wallet.RequestCredentialAsync(mdocSession.Configuration, Access(mdocSession.Login.Tokens), await ProofsAsync(), mdocSession.Identifier, cancellationToken: ct);
        string mdocCredential = Credential(mdocResponse);
        var mdocVerifier = new MdocCredentialValidator(transport, [caCertificate], X509RevocationMode.NoCheck);
        var mdoc = await mdocVerifier.ValidateAsync(mdocCredential, mdocSession.Configuration, holder.Thumbprint, ct);
        check(mdoc.DocumentType == mdocType && mdoc.Namespaces.GetProperty(mdocType).GetProperty("email").GetString() == "protocols@example.invalid" && mdoc.HolderThumbprint == holder.Thumbprint,
            "Real mdoc issuance verifies the trusted CA chain COSE issuer signature signed data digests validity and exact P-256 device key");
        bool mdocWrongHolder = false;
        try { await mdocVerifier.ValidateAsync(mdocCredential, mdocSession.Configuration, "other-wallet", ct); } catch (InvalidDataException) { mdocWrongHolder = true; }
        check(mdocWrongHolder, "A real mdoc credential cannot be accepted for another device key");
        bool untrustedMdoc = false;
        using var otherCaKey = RSA.Create(2048); using var otherCa = new CertificateRequest("CN=Untrusted CA", otherCaKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        try { await new MdocCredentialValidator(transport, [otherCa], X509RevocationMode.NoCheck).ValidateAsync(mdocCredential, mdocSession.Configuration, holder.Thumbprint, ct); } catch (InvalidDataException) { untrustedMdoc = true; }
        check(untrustedMdoc, "An embedded mdoc issuer certificate never establishes trust without the application's configured CA");
        var presentationScope = (await admin.ClientScopes.GetClientScopesAsync(realm, ct)).Body!.Single(s => s.Name == "sdk-sd");
        presentationScope.Attributes!["vc.credential_signing_alg"] = "ES256";
        await admin.ClientScope.UpdateAsync(realm, presentationScope.Id!, presentationScope, ct);
        var presentationSession = await AuthorizeAsync("sdk-sd", purpose: "presentation");
        var presentationCredential = await wallet.RequestCredentialAsync(presentationSession.Configuration, Access(presentationSession.Login.Tokens), await ProofsAsync(), presentationSession.Identifier, cancellationToken: ct);
        var presentationVerified = await new Oid4vcCredentialValidator(oidc, allowedAlgorithms: ["ES256"]).ValidateAsync(Credential(presentationCredential), presentationSession.Configuration, holder.Thumbprint, ct);
        await ProtocolWalletPresentationWorkflows.RunAsync(admin, http, transport, realm, password, userId,
            "x509_hash:" + Base64UrlEncoder.Encode(SHA256.HashData(mdocCertificate.RawData)), presentationVerified, holder, check, ct);
        await ProtocolWalletAttestationWorkflows.RunAsync(admin, http, transport, realm, check, ct);
        var offerLogin = await OidcLoginTransaction.StartAsync(oidc, authentication, callback, cancellationToken: ct);
        var offerBrowser = await ProtocolBrowserFixture.LoginAsync(offerLogin.AuthorizationUri, callback, "account-user", password, ct);
        string offerAccess = Access((await offerLogin.CompleteAsync(offerBrowser.Callback, authentication, new OidcTokenValidator(oidc, clientId), ct)).Tokens);
        async Task<JsonElement> OfferAsync(bool preAuthorized, DateTimeOffset? expires = null)
        {
            var link = (await wallet.CreateOfferAsync("sdk-sd", offerAccess, preAuthorized, expires: expires, cancellationToken: ct)).Json!.Value;
            return (await wallet.GetOfferAsync(new(link.GetProperty("issuer").GetString()! + "/" + Uri.EscapeDataString(link.GetProperty("nonce").GetString()!)), ct)).Json!.Value;
        }
        var authOffer = await OfferAsync(false);
        var offered = await AuthorizeAsync("sdk-sd", authOffer.GetProperty("grants").GetProperty("authorization_code").GetProperty("issuer_state").GetString(), "credential offer");
        check((await verifier.ValidateAsync(Credential(await wallet.RequestCredentialAsync(offered.Configuration, Access(offered.Login.Tokens), await ProofsAsync(), offered.Identifier, cancellationToken: ct)), offered.Configuration, holder.Thumbprint, ct)).Format == "dc+sd-jwt",
            "An authorization-code credential offer preserves issuer_state through PKCE and delivers only its authorized configuration");
        foreach (var type in new[] { Oid4vcOfferResponseType.Qr, Oid4vcOfferResponseType.UriWithQr })
        {
            var reply = await wallet.CreateOfferAsync("sdk-sd", offerAccess, responseType: type, cancellationToken: ct);
            byte[] png = type == Oid4vcOfferResponseType.Qr ? reply.RawBody.ToArray() : Convert.FromBase64String(reply.Json!.Value.GetProperty("qr_code").GetString()!["data:image/png;base64,".Length..]);
            check(png.AsSpan(0, 8).SequenceEqual(new byte[] { 137, 80, 78, 71, 13, 10, 26, 10 }), "Real credential offers return a bounded PNG QR representation through " + type);
        }
        bool unauthorizedTarget = false;
        await admin.Users.CreateUserAsync(realm, new() { Username = "wallet-other", Enabled = true, VerifiableCredentials = [new() { CredentialScopeName = "sdk-sd" }] }, cancellationToken: ct);
        try { await wallet.CreateOfferAsync("sdk-sd", offerAccess, targetUser: "wallet-other", cancellationToken: ct); }
        catch (KeycloakProtocolException e) when (e.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.Forbidden) { unauthorizedTarget = true; }
        check(unauthorizedTarget, "An ordinary wallet user cannot create a targeted credential offer for another account");
        var preOffer = await OfferAsync(true); const string preGrant = "urn:ietf:params:oauth:grant-type:pre-authorized_code";
        string preCode = preOffer.GetProperty("grants").GetProperty(preGrant).GetProperty("pre-authorized_code").GetString()!;
        var preTokens = await tokens.RedeemPreAuthorizedCodeAsync(authentication, preCode, cancellationToken: ct);
        string preIdentifier = preTokens.Json!.Value.GetProperty("authorization_details")[0].GetProperty("credential_identifiers")[0].GetString()!;
        var preCredential = await wallet.RequestCredentialAsync(metadataJson.Configurations["sdk-sd"], Access(preTokens), await ProofsAsync(), preIdentifier, cancellationToken: ct);
        check((await verifier.ValidateAsync(Credential(preCredential), metadataJson.Configurations["sdk-sd"], holder.Thumbprint, ct)).Claims.GetProperty("email").GetString() == "protocols@example.invalid",
            "A real pre-authorized offer issues a holder-bound credential for the original independently observed user");
        bool preReplay = false;
        try { await tokens.RedeemPreAuthorizedCodeAsync(authentication, preCode, cancellationToken: ct); } catch (KeycloakProtocolException e) when (e.StatusCode == HttpStatusCode.BadRequest) { preReplay = true; }
        check(preReplay, "A pre-authorized credential code is consumed atomically and cannot be redeemed twice");
        var expiringOffer = await OfferAsync(true, DateTimeOffset.UtcNow.AddSeconds(3));
        string expiredCode = expiringOffer.GetProperty("grants").GetProperty(preGrant).GetProperty("pre-authorized_code").GetString()!;
        await Task.Delay(TimeSpan.FromSeconds(4), ct); bool expired = false; int beforeExpiry = RecordingHandler.SentCount;
        try { await tokens.RedeemPreAuthorizedCodeAsync(authentication, expiredCode, cancellationToken: ct); }
        catch (KeycloakProtocolException e) when (e.StatusCode == HttpStatusCode.BadRequest) { expired = true; }
        check(expired && RecordingHandler.SentCount == beforeExpiry + 1, "An expired pre-authorized offer cannot issue a credential and is never retried");
        var issuedForAccount = (await account.GetIssuedCredentialsAsync(accountAccess, ct)).Json!.Value;
        string issuedJwtId = issuedForAccount.EnumerateArray().Single(c => c.GetProperty("credentialType").GetString() == "sdk-jwt").GetProperty("id").GetString()!;
        await account.RevokeIssuedCredentialAsync(issuedJwtId, accountAccess, ct);
        check(!(await admin.UserVerifiableCredential.GetIssuedCredentialsAsync(realm, userId, ct)).Body.EnumerateArray().Any(c => c.GetProperty("id").GetString() == issuedJwtId),
            "Account-issued credential revocation independently removes the exact persisted Admin record");
        bool revokedToken = false;
        try { await wallet.RequestCredentialAsync(sessions["sdk-jwt"].Configuration, Access(sessions["sdk-jwt"].Login.Tokens), await ProofsAsync(), sessions["sdk-jwt"].Identifier, cancellationToken: ct); }
        catch (KeycloakProtocolException e) when (e.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden) { revokedToken = true; }
        check(revokedToken, "An account-revoked issued credential cannot be obtained again with its original issuance token");
        await account.RevokeEntitlementAsync("sdk-jwt", accountAccess, ct);
        check(!(await admin.UserVerifiableCredential.GetCredentialsAsync(realm, userId, ct)).Body.EnumerateArray().Any(c => c.GetProperty("credentialScopeName").GetString() == "sdk-jwt"),
            "Account entitlement revocation independently removes the user's persisted credential grant");
        var revocationOffer = await OfferAsync(true);
        string revokedPreCode = revocationOffer.GetProperty("grants").GetProperty(preGrant).GetProperty("pre-authorized_code").GetString()!;
        await account.RevokeEntitlementAsync("sdk-sd", accountAccess, ct);
        var beforeRevokedOffer = (await admin.UserVerifiableCredential.GetIssuedCredentialsAsync(realm, userId, ct)).Body.EnumerateArray().Select(c => c.GetProperty("id").GetString()!).Order().ToArray();
        bool revokedOffer = false; int revokedRequestCount = RecordingHandler.SentCount;
        try { await tokens.RedeemPreAuthorizedCodeAsync(authentication, revokedPreCode, cancellationToken: ct); }
        // Pinned upstream createIssuedVerifiableCredential throws ModelException for the removed entitlement, yielding 500.
        // Preserve that terminal error; do not translate it into success or retry a consumed grant.
        catch (KeycloakProtocolException e) when (e.StatusCode == HttpStatusCode.InternalServerError) { revokedOffer = true; }
        bool oneAttempt = RecordingHandler.SentCount == revokedRequestCount + 1;
        var afterRevokedOffer = (await admin.UserVerifiableCredential.GetIssuedCredentialsAsync(realm, userId, ct)).Body.EnumerateArray().Select(c => c.GetProperty("id").GetString()!).Order().ToArray();
        check(revokedOffer && oneAttempt && beforeRevokedOffer.SequenceEqual(afterRevokedOffer, StringComparer.Ordinal),
            "A revoked pre-authorized offer preserves the pinned server's terminal 500 without issuing any credential or retrying the consumed grant");
        foreach (string feature in new[] { "Wallet", "WalletOffers", "WalletPreAuthorized", "WalletMdoc", "WalletPresentation" })
        {
            enabled["KeycloakSdk.Protocols." + feature] = false; gate.Replace(enabled); int before = RecordingHandler.SentCount, credentialsRead = 0; bool denied = false;
            try
            {
                switch (feature)
                {
                    case "Wallet": await wallet.RequestNonceAsync(ct); break;
                    case "WalletOffers": await wallet.CreateOfferAsync("sdk-sd", offerAccess, cancellationToken: ct); break;
                    case "WalletPreAuthorized": await tokens.RedeemPreAuthorizedCodeAsync(OAuthClientAuthentication.SecretPost(clientId, _ => { credentialsRead++; return ValueTask.FromResult("unused"); }), "unused", cancellationToken: ct); break;
                    case "WalletMdoc": await wallet.RequestCredentialAsync(mdocSession.Configuration, "unused", cancellationToken: ct); break;
                    case "WalletPresentation": await new Oid4vpClient(transport, "wallet-verifier", "x509_hash:" + Base64UrlEncoder.Encode(SHA256.HashData(mdocCertificate.RawData)))
                        .GetRequestAsync(new(wallet.Issuer.AbsoluteUri + "/broker/wallet-verifier/endpoint/request-object/unused"), ct); break;
                }
            }
            catch (InvalidOperationException) { denied = true; }
            check(denied && before == RecordingHandler.SentCount && credentialsRead == 0, "Closing the independent " + feature + " host flag stops its workflow before credentials or HTTP");
            enabled["KeycloakSdk.Protocols." + feature] = true; gate.Replace(enabled);
        }
        using var cancellation = new CancellationTokenSource(); cancellation.Cancel(); bool canceled = false; int beforeCancellation = RecordingHandler.SentCount;
        try { await wallet.RequestNonceAsync(cancellation.Token); } catch (OperationCanceledException) { canceled = true; }
        check(canceled && beforeCancellation == RecordingHandler.SentCount, "Canceled wallet operations terminate before contacting the issuer");
    }
}
