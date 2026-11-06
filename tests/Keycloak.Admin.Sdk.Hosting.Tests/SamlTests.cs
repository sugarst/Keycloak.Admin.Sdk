using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml.Linq;
using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Schemas;
using Keycloak.Admin.Sdk.Capabilities;
using Keycloak.Admin.Sdk.Hosting;
using Keycloak.Admin.Sdk.Protocols;
using Microsoft.IdentityModel.Tokens.Saml2;
using Microsoft.VisualStudio.TestTools.UnitTesting;

[TestClass]
public sealed class SamlTests
{
    private static readonly Uri Callback = new("https://app.invalid/saml/callback");
    private const string Issuer = "https://identity.invalid/realms/r", Entity = "urn:app:saml";
    [TestMethod]
    public async Task IncomingLogoutMustVerifyThePinnedSignedSessionBeforeAnAtomicRetryableRevocation()
    {
        using var fixture = new Fixture(); var provider = fixture.Provider(sign: true); var store = new LogoutStore();
        var notification = fixture.LogoutRequest();
        store.Fail = true;
        await Assert.ThrowsAsync<IOException>(() => provider.HandleLogoutPostAsync(Callback, notification.Encoded, "state", store)); Assert.AreEqual(0, store.Effects);
        store.Fail = false;
        var reply = await provider.HandleLogoutPostAsync(Callback, notification.Encoded, "state", store);
        await provider.HandleLogoutPostAsync(Callback, notification.Encoded, "state", store);
        var redirect = await provider.HandleLogoutRedirectAsync(notification.Uri, store);
        await provider.HandleLogoutSoapAsync(Callback, notification.Soap, store);
        await provider.HandleLogoutPostAsync(Callback, fixture.LogoutRequest(mutate: r => r.NotOnOrAfter = null).Encoded, null, store);
        Assert.AreEqual(1, store.Effects); Assert.AreEqual("state", reply.FormFields!["RelayState"]); Assert.IsNotNull(redirect.Destination);
        Assert.AreEqual(Issuer, store.Last!.Issuer); Assert.AreEqual(Entity, store.Last.ServiceProvider); Assert.AreEqual("session", store.Last.SessionIndex); Assert.AreEqual("user", store.Last.NameId);
        var response = new Saml2LogoutResponse(new() { AllowedIssuer = Entity, SignatureValidationCertificates = [fixture.Certificate], CertificateValidationMode = System.ServiceModel.Security.X509CertificateValidationMode.None });
        new Saml2PostBinding().Unbind(new ITfoxtec.Identity.Saml2.Http.HttpRequest { Method = "POST", Form = new System.Collections.Specialized.NameValueCollection { ["SAMLResponse"] = reply.FormFields["SAMLResponse"] } }, response);
        Assert.AreEqual("_idp-logout", response.InResponseTo.Value); Assert.AreEqual(Saml2StatusCodes.Success, response.Status);
        int mutation = 0;
        foreach (Action<Saml2LogoutRequest> mutate in new Action<Saml2LogoutRequest>[] { r => r.Issuer = "https://attacker.invalid", r => r.Destination = new("https://attacker.invalid/logout"),
            r => r.SessionIndex = null, r => r.NotOnOrAfter = DateTimeOffset.UtcNow.AddMinutes(-1), r => r.NotOnOrAfter = DateTimeOffset.UtcNow.AddHours(1), r => r.IssueInstant = DateTimeOffset.UtcNow.AddMinutes(-10),
            r => { r.NotOnOrAfter = null; r.IssueInstant = DateTimeOffset.UtcNow.AddMinutes(-10); } })
            await Assert.ThrowsAsync<InvalidDataException>(() => provider.HandleLogoutPostAsync(Callback, fixture.LogoutRequest(mutate: mutate).Encoded, null, store), "Invalid logout mutation " + mutation++);
        await Assert.ThrowsAsync<InvalidDataException>(() => provider.HandleLogoutPostAsync(Callback, fixture.LogoutRequest(wrongKey: true).Encoded, null, store));
        Assert.AreEqual(1, store.Effects);
        await Assert.ThrowsAsync<InvalidDataException>(() => provider.HandleLogoutRedirectAsync(new(notification.Uri + "&RelayState=duplicate"), store));
        var closed = fixture.Provider(sign: true, gate: new KeycloakFeatureSnapshotGate([]));
        await Assert.ThrowsAsync<InvalidOperationException>(() => closed.HandleLogoutPostAsync(Callback, notification.Encoded, null, store));
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        await Assert.ThrowsAsync<OperationCanceledException>(() => provider.HandleLogoutPostAsync(Callback, notification.Encoded, null, store, cancelled.Token));
    }
    [TestMethod]
    public async Task BindingSelectionAndIdpInitiatedLoginCannotAcceptUnsolicitedOrSubstitutedTransactions()
    {
        using var fixture = new Fixture(); var provider = fixture.Provider(sign: true);
        var post = await provider.StartLoginAsync(new SamlLoginOptions { RequestBinding = SamlBrowserBinding.Post });
        var xml = XDocument.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(post.FormFields!["SAMLRequest"])));
        Assert.AreEqual(Entity, xml.Root!.Element(XName.Get("Issuer", "urn:oasis:names:tc:SAML:2.0:assertion"))!.Value);
        Assert.IsTrue(xml.Descendants(XName.Get("Signature", "http://www.w3.org/2000/09/xmldsig#")).Any());
        Assert.AreEqual("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", (string?)xml.Root.Attribute("ProtocolBinding"));
        await Assert.ThrowsAsync<InvalidDataException>(() => post.CompleteRedirectAsync(Callback));
        await Assert.ThrowsAsync<InvalidDataException>(() => post.CompleteArtifactAsync(Callback, "artifact", "state", fixture.Http));
        var redirect = await provider.StartLoginAsync(new SamlLoginOptions { ResponseBinding = SamlBrowserBinding.Redirect });
        await Assert.ThrowsAsync<InvalidDataException>(() => redirect.CompleteAsync(Callback, fixture.Response(), "state"));
        await Assert.ThrowsAsync<InvalidDataException>(() => redirect.CompleteRedirectAsync(new("https://attacker.invalid/callback?SAMLResponse=x")));
        foreach (var invalid in new SamlLoginOptions[] { new() { RequestBinding = SamlBrowserBinding.Artifact }, new() { ResponseBinding = (SamlBrowserBinding)99 } })
            await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => provider.StartLoginAsync(invalid));
        await Assert.ThrowsAsync<ArgumentException>(() => provider.StartLoginAsync(new SamlLoginOptions { Passive = true, ForceAuthentication = true }));
        await Assert.ThrowsAsync<ArgumentNullException>(() => provider.StartLoginAsync((SamlLoginOptions)null!));
        foreach (string invalid in new[] { "", "../other", "id?redirect", "a/b" }) await Assert.ThrowsAsync<ArgumentException>(() => provider.StartIdpInitiatedLoginAsync(invalid));
        var initiated = await provider.StartIdpInitiatedLoginAsync("app-url");
        string state = Uri.UnescapeDataString(initiated.AuthorizationUri.Query.Split('=', 2)[1]);
        string unsolicited = fixture.Response(mutate: r => { r.InResponseTo = null; r.Saml2SecurityToken.Assertion.Subject.SubjectConfirmations.First().SubjectConfirmationData.InResponseTo = null; });
        await Assert.ThrowsAsync<InvalidDataException>(() => fixture.Transaction(provider).CompleteAsync(Callback, unsolicited, "state"));
        var identity = await initiated.CompleteAsync(Callback, unsolicited, state);
        Assert.AreEqual("user", identity.NameId);
        await Assert.ThrowsAsync<InvalidDataException>(() => initiated.CompleteAsync(Callback, unsolicited, state));
    }

    [TestMethod]
    public async Task ArtifactAndEcpRejectForeignSourcesEndpointsUnboundedXmlAndClosedHostGates()
    {
        using var fixture = new Fixture(); var provider = fixture.Provider(sign: true);
        SamlLoginTransaction Artifact() => new(provider, "_request", "state", new("https://identity.invalid"), responseBinding: SamlBrowserBinding.Artifact);
        foreach (string invalid in new[] { "not-base64", Convert.ToBase64String(new byte[43]), Convert.ToBase64String(new byte[44]), new string('a', 129) })
            await Assert.ThrowsAsync<InvalidDataException>(() => Artifact().CompleteArtifactAsync(Callback, invalid, "state", fixture.Http));
        var bytes = new byte[44]; bytes[1] = 4; Array.Copy(SHA1.HashData(Encoding.UTF8.GetBytes(Issuer)), 0, bytes, 4, 20); RandomNumberGenerator.Fill(bytes.AsSpan(24));
        string artifact = Convert.ToBase64String(bytes);
        await Assert.ThrowsAsync<InvalidDataException>(() => Artifact().CompleteArtifactAsync(new("https://attacker.invalid/"), artifact, "state", fixture.Http));
        await Assert.ThrowsAsync<InvalidDataException>(() => Artifact().CompleteArtifactAsync(Callback, artifact, "other", fixture.Http));
        Assert.AreEqual(0, fixture.Handler.Calls);
        foreach (string invalidXml in new[] { "<invalid/>", new string('a', 262145), "<!DOCTYPE Envelope [<!ENTITY x SYSTEM 'file:///secret'>]><Envelope>&x;</Envelope>" })
        {
            fixture.Handler.Response = invalidXml;
            await Assert.ThrowsAsync<InvalidDataException>(() => Artifact().CompleteArtifactAsync(Callback, artifact, "state", fixture.Http));
        }
        Assert.AreEqual(Issuer + "/protocol/saml/resolve", fixture.Handler.Url);
        int credentialReads = 0; ValueTask<NetworkCredential> Read(CancellationToken ct) { ct.ThrowIfCancellationRequested(); credentialReads++; return ValueTask.FromResult(new NetworkCredential("user", "password")); }
        var closed = fixture.Provider(sign: true, gate: new KeycloakFeatureSnapshotGate([]));
        await Assert.ThrowsAsync<InvalidOperationException>(() => closed.AuthenticateEcpAsync(fixture.Http, Read)); Assert.AreEqual(0, credentialReads);
        using var cancel = new CancellationTokenSource(); cancel.Cancel();
        await Assert.ThrowsAsync<OperationCanceledException>(() => provider.AuthenticateEcpAsync(fixture.Http, Read, cancellationToken: cancel.Token)); Assert.AreEqual(0, credentialReads);
        fixture.Handler.Response = "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Header><ecp:Response xmlns:ecp=\"urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp\" AssertionConsumerServiceURL=\"https://attacker.invalid/\"/></soap:Header><soap:Body/></soap:Envelope>";
        await Assert.ThrowsAsync<InvalidDataException>(() => provider.AuthenticateEcpAsync(fixture.Http, Read)); Assert.AreEqual(1, credentialReads);
        fixture.Http.DefaultRequestHeaders.Authorization = new("Bearer", "must-not-leak");
        await Assert.ThrowsAsync<ArgumentException>(() => provider.AuthenticateEcpAsync(fixture.Http, Read)); Assert.AreEqual(1, credentialReads);
    }
    [TestMethod]
    public async Task SignedSamlResponsesRequireBrowserCorrelationIssuerAudienceRecipientLifetimeAndReplayProtection()
    {
        using var fixture = new Fixture(); var provider = fixture.Provider();
        var transaction = fixture.Transaction(provider); string encoded = fixture.Response();
        var session = await transaction.CompleteAsync(Callback, encoded, "state");
        Assert.AreEqual("user", session.NameId); Assert.IsTrue(session.Principal.Identity!.IsAuthenticated);
        Assert.IsFalse(session.ToString()!.Contains(encoded, StringComparison.Ordinal));
        await Assert.ThrowsAsync<InvalidDataException>(() => transaction.CompleteAsync(Callback, encoded, "state"));
        await Assert.ThrowsAsync<InvalidDataException>(() => fixture.Transaction(provider).CompleteAsync(Callback, encoded, "state"));
        foreach (Action<Saml2AuthnResponse> mutate in new Action<Saml2AuthnResponse>[]
        { r => r.InResponseTo = new("_wrong"), r => r.Destination = new("https://attacker.invalid/callback"),
          r => r.Saml2SecurityToken.Assertion.Subject.SubjectConfirmations.First().SubjectConfirmationData.InResponseTo = new("_wrong"),
          r => r.Saml2SecurityToken.Assertion.Subject.SubjectConfirmations.First().SubjectConfirmationData.Recipient = new("https://attacker.invalid/"),
          r => r.Saml2SecurityToken.Assertion.Subject.SubjectConfirmations.First().SubjectConfirmationData.NotOnOrAfter = DateTime.UtcNow.AddMinutes(-1),
          r => r.Saml2SecurityToken.Assertion.Conditions.NotOnOrAfter = DateTime.UtcNow.AddMinutes(-1),
          r => r.Saml2SecurityToken.Assertion.Conditions.NotOnOrAfter = null,
          r => r.Saml2SecurityToken.Assertion.Conditions.NotOnOrAfter = DateTime.UtcNow.AddDays(2),
          r => { r.Saml2SecurityToken.Assertion.Conditions.NotOnOrAfter = DateTime.UtcNow.AddHours(2); r.Saml2SecurityToken.Assertion.Conditions.NotBefore = DateTime.UtcNow.AddHours(1); },
          r => r.Saml2SecurityToken.Assertion.Subject.NameId = null!,
          r => r.Saml2SecurityToken.Assertion.Issuer = new("https://attacker.invalid/") })
            await Assert.ThrowsAsync<InvalidDataException>(() => fixture.Transaction(fixture.Provider()).CompleteAsync(Callback, fixture.Response(mutate: mutate), "state"));
        await Assert.ThrowsAsync<InvalidDataException>(() => fixture.Transaction(fixture.Provider()).CompleteAsync(Callback, fixture.Response(audience: "other"), "state"));
        await Assert.ThrowsAsync<InvalidDataException>(() => fixture.Transaction(fixture.Provider()).CompleteAsync(Callback, fixture.Response(wrongKey: true), "state"));
        string tampered = Encoding.UTF8.GetString(Convert.FromBase64String(fixture.Response())).Replace(">user<", ">attacker<", StringComparison.Ordinal);
        await Assert.ThrowsAsync<InvalidDataException>(() => fixture.Transaction(fixture.Provider()).CompleteAsync(Callback, Convert.ToBase64String(Encoding.UTF8.GetBytes(tampered)), "state"));
        await Assert.ThrowsAsync<InvalidDataException>(() => fixture.Transaction(fixture.Provider()).CompleteAsync(new("https://app.invalid/wrong"), fixture.Response(), "state"));
        await Assert.ThrowsAsync<InvalidDataException>(() => fixture.Transaction(fixture.Provider()).CompleteAsync(Callback, fixture.Response(), "wrong-state"));
        foreach (string invalid in new[] { "invalid-base64", new string('a', 350001), Convert.ToBase64String(Encoding.UTF8.GetBytes("<!DOCTYPE Response [<!ENTITY secret SYSTEM 'file:///sensitive'>]><Response>&secret;</Response>")) })
            await Assert.ThrowsAsync<InvalidDataException>(() => fixture.Transaction(fixture.Provider()).CompleteAsync(Callback, invalid, "state"));
    }

    [TestMethod]
    public async Task EncryptedAssertionsAndAssuranceRequirementsCannotBypassSignedIdentityValidation()
    {
        using var fixture = new Fixture();
        string encrypted = fixture.Response(encrypt: true);
        await Assert.ThrowsAsync<InvalidDataException>(() => fixture.Transaction(fixture.Provider()).CompleteAsync(Callback, encrypted, "state"));
        var verified = await fixture.Transaction(fixture.Provider(decrypt: true)).CompleteAsync(Callback, encrypted, "state"); Assert.AreEqual("user", verified.NameId);
        var provider = fixture.Provider();
        var required = new SamlLoginTransaction(provider, "_request", "state", new("https://identity.invalid/"), ["urn:auth:strong"]);
        await Assert.ThrowsAsync<InvalidDataException>(() => required.CompleteAsync(Callback, fixture.Response(), "state"));
        var expected = new SamlLoginTransaction(provider, "_request", "state", new("https://identity.invalid/"), ["urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"]);
        Assert.IsNotNull((await expected.CompleteAsync(Callback, fixture.Response(), "state")).AuthenticationContext);
        await Assert.ThrowsAsync<InvalidDataException>(() => fixture.Transaction(fixture.Provider()).CompleteAsync(Callback, fixture.Response(audience: Entity + "/"), "state"));
        await Assert.ThrowsAsync<InvalidDataException>(() => fixture.Transaction(fixture.Provider()).CompleteAsync(Callback, fixture.Response(mutate: r => r.Saml2SecurityToken.Assertion.Statements.Clear()), "state"));
    }

    [TestMethod]
    public async Task SignedSingleLogoutVerifiesBothBindingsAndRejectsTamperingExpiredMessagesAndSessionSubstitution()
    {
        using var fixture = new Fixture(); var provider = fixture.Provider(sign: true);
        var session = await fixture.Transaction(provider).CompleteAsync(Callback, fixture.Response(), "state");
        var started = await provider.StartLogoutAsync(session); StringAssert.Contains(started.AuthorizationUri.Query, "Signature=");
        var redirect = fixture.Logout(); var tx = new SamlLogoutTransaction(provider, "_logout", "state", new("https://identity.invalid/"));
        await tx.CompleteRedirectAsync(redirect.Uri);
        await Assert.ThrowsAsync<InvalidDataException>(() => tx.CompleteRedirectAsync(redirect.Uri));
        await Assert.ThrowsAsync<InvalidDataException>(() => new SamlLogoutTransaction(provider, "_logout", "state", new("https://identity.invalid/")).CompleteRedirectAsync(redirect.Uri));
        var post = fixture.Logout(); await new SamlLogoutTransaction(provider, "_logout", "state", new("https://identity.invalid/")).CompletePostAsync(Callback, post.Encoded, "state");
        foreach (Action<Saml2LogoutResponse> mutate in new Action<Saml2LogoutResponse>[] { r => r.InResponseTo = new("_other"), r => r.Destination = new("https://app.invalid/other"), r => r.Issuer = "https://attacker.invalid",
            r => r.IssueInstant = DateTimeOffset.UtcNow.AddHours(-1), r => r.IssueInstant = DateTimeOffset.UtcNow.AddHours(1) })
        {
            var bad = fixture.Logout(mutate); await Assert.ThrowsAsync<InvalidDataException>(() => new SamlLogoutTransaction(provider, "_logout", "state", new("https://identity.invalid/")).CompleteRedirectAsync(bad.Uri));
        }
        foreach (var invalid in new[] { new Uri(redirect.Uri.AbsoluteUri + "&RelayState=other"), new Uri(redirect.Uri.AbsoluteUri.Replace("RelayState=state", "RelayState=wrong", StringComparison.Ordinal)),
            new Uri(redirect.Uri.AbsoluteUri.Replace("Signature=", "Signature=X", StringComparison.Ordinal)), new Uri("https://app.invalid/other"), new Uri("https://app.invalid/saml/callback#fragment") })
            await Assert.ThrowsAsync<InvalidDataException>(() => new SamlLogoutTransaction(provider, "_logout", "state", new("https://identity.invalid/")).CompleteRedirectAsync(invalid));
        await Assert.ThrowsAsync<InvalidDataException>(() => new SamlLogoutTransaction(provider, "_logout", "state", new("https://identity.invalid/")).CompletePostAsync(Callback, post.Encoded, "wrong"));
        await Assert.ThrowsAsync<InvalidDataException>(() => new SamlLogoutTransaction(provider, "_logout", "state", new("https://identity.invalid/")).CompletePostAsync(Callback, "invalid", "state"));
        await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Provider().StartLogoutAsync(session));
        await Assert.ThrowsAsync<ArgumentException>(() => provider.StartLogoutAsync(new VerifiedSamlSession(new(), new("user"), "s", "https://attacker.invalid", Entity)));
        await Assert.ThrowsAsync<ArgumentException>(() => provider.StartLogoutAsync(new VerifiedSamlSession(new(), new("user"), null, Issuer, Entity)));
        await Assert.ThrowsAsync<ArgumentNullException>(() => provider.StartLogoutAsync(null!));
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel(); await Assert.ThrowsAsync<OperationCanceledException>(() => provider.StartLogoutAsync(session, cancelled.Token));
    }

    [TestMethod]
    public async Task SamlRequestAndMetadataUseTheFixedRealmAndKeepPrivateCertificatesOutOfMetadata()
    {
        using var fixture = new Fixture(); var provider = fixture.Provider(sign: true);
        var transaction = await provider.StartLoginAsync(true, [new("urn:auth:strong")]);
        Assert.AreEqual(Issuer + "/protocol/saml", transaction.AuthorizationUri.GetLeftPart(UriPartial.Path));
        StringAssert.Contains(transaction.AuthorizationUri.Query, "SAMLRequest="); StringAssert.Contains(transaction.AuthorizationUri.Query, "Signature=");
        var metadata = XDocument.Parse(provider.CreateMetadata()); XNamespace md = "urn:oasis:names:tc:SAML:2.0:metadata";
        Assert.AreEqual(Entity, metadata.Root!.Attribute("entityID")!.Value);
        var consumers = metadata.Descendants(md + "AssertionConsumerService").ToArray();
        Assert.AreEqual(3, consumers.Length); Assert.IsTrue(consumers.All(c => c.Attribute("Location")!.Value == Callback.AbsoluteUri));
        Assert.AreEqual("signing", metadata.Descendants(md + "KeyDescriptor").Single().Attribute("use")!.Value);
        Assert.IsFalse(provider.CreateMetadata().Contains("PRIVATE", StringComparison.Ordinal));
        await fixture.Provider().StartLoginAsync();
        await Assert.ThrowsAsync<ArgumentException>(() => provider.StartLoginAsync(authenticationContexts: [new("relative", UriKind.Relative)]));
        var closed = fixture.Provider(gate: new KeycloakFeatureSnapshotGate([]));
        await Assert.ThrowsAsync<InvalidOperationException>(() => closed.StartLoginAsync());
        await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Transaction(closed).CompleteAsync(Callback, fixture.Response(), "state"));
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        await Assert.ThrowsAsync<OperationCanceledException>(() => provider.StartLoginAsync(cancellationToken: cancelled.Token));
        Assert.Throws<ArgumentNullException>(() => new KeycloakSamlServiceProvider(null!, Entity, Callback, [fixture.Certificate], new InMemoryDpopReplayStore()));
        Assert.Throws<ArgumentException>(() => new KeycloakSamlServiceProvider(fixture.Transport(), "", Callback, [fixture.Certificate], new InMemoryDpopReplayStore()));
        Assert.Throws<ArgumentNullException>(() => new KeycloakSamlServiceProvider(fixture.Transport(), Entity, null!, [fixture.Certificate], new InMemoryDpopReplayStore()));
        foreach (var invalid in new Uri[] { new("relative", UriKind.Relative), new("file:///tmp"), new("https://user:password@app.invalid/"), new("https://app.invalid/?query"), new("https://app.invalid/#fragment") })
            Assert.Throws<ArgumentException>(() => new KeycloakSamlServiceProvider(fixture.Transport(), Entity, invalid, [fixture.Certificate], new InMemoryDpopReplayStore()));
        Assert.Throws<ArgumentNullException>(() => new KeycloakSamlServiceProvider(fixture.Transport(), Entity, Callback, null!, new InMemoryDpopReplayStore()));
        Assert.Throws<ArgumentException>(() => new KeycloakSamlServiceProvider(fixture.Transport(), Entity, Callback, [], new InMemoryDpopReplayStore()));
        Assert.Throws<ArgumentException>(() => new KeycloakSamlServiceProvider(fixture.Transport(), Entity, Callback, [null!], new InMemoryDpopReplayStore()));
        Assert.Throws<ArgumentNullException>(() => new KeycloakSamlServiceProvider(fixture.Transport(), Entity, Callback, [fixture.Certificate], null!));
        using var publicOnly = X509CertificateLoader.LoadCertificate(fixture.Certificate.RawData);
        Assert.Throws<ArgumentException>(() => new KeycloakSamlServiceProvider(fixture.Transport(), Entity, Callback, [fixture.Certificate], new InMemoryDpopReplayStore(), publicOnly));
        Assert.Throws<ArgumentException>(() => new KeycloakSamlServiceProvider(fixture.Transport(), Entity, Callback, [fixture.Certificate], new InMemoryDpopReplayStore(), decryptionCertificates: [publicOnly]));
    }

    [TestMethod]
    public async Task SamlMetadataCannotChangeIssuerEndpointOrCertificateTrustThroughUntrustedInputs()
    {
        using var fixture = new Fixture(); fixture.Handler.Response = fixture.Metadata();
        var certificates = await KeycloakSamlMetadata.LoadSigningCertificatesAsync(fixture.Http, fixture.Transport());
        Assert.AreEqual(fixture.Certificate.Thumbprint, certificates.Single().Thumbprint); foreach (var certificate in certificates) certificate.Dispose();
        Assert.AreEqual(Issuer + "/protocol/saml/descriptor", fixture.Handler.Url);
        foreach (string invalid in new[] { fixture.Metadata().Replace(Issuer, "https://attacker.invalid", StringComparison.Ordinal), "<EntityDescriptor/>",
            fixture.Metadata().Replace("IDPSSODescriptor", "SPSSODescriptor", StringComparison.Ordinal), fixture.Metadata().Replace("HTTP-Redirect", "HTTP-POST", StringComparison.Ordinal),
            fixture.Metadata().Replace("<md:KeyDescriptor>", "<md:KeyDescriptor use=\"encryption\">", StringComparison.Ordinal), new string('a', 262145) })
        { fixture.Handler.Response = invalid; await Assert.ThrowsAsync<InvalidDataException>(() => KeycloakSamlMetadata.LoadSigningCertificatesAsync(fixture.Http, fixture.Transport())); }
        fixture.Handler.Status = HttpStatusCode.InternalServerError;
        await Assert.ThrowsAsync<HttpRequestException>(() => KeycloakSamlMetadata.LoadSigningCertificatesAsync(fixture.Http, fixture.Transport()));
        await Assert.ThrowsAsync<ArgumentException>(() => KeycloakSamlMetadata.LoadSigningCertificatesAsync(fixture.Http, new(fixture.Http, new("http://identity.invalid/"), "r")));
        fixture.Http.DefaultRequestHeaders.Authorization = new("Bearer", "admin");
        await Assert.ThrowsAsync<ArgumentException>(() => KeycloakSamlMetadata.LoadSigningCertificatesAsync(fixture.Http, fixture.Transport())); fixture.Http.DefaultRequestHeaders.Authorization = null;
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        await Assert.ThrowsAsync<OperationCanceledException>(() => KeycloakSamlMetadata.LoadSigningCertificatesAsync(fixture.Http, fixture.Transport(), cancellationToken: cancelled.Token));
    }
    private sealed class Fixture : IDisposable
    {
        private readonly RSA key = RSA.Create(2048), other = RSA.Create(2048);
        internal readonly X509Certificate2 Certificate, Other; internal readonly Handler Handler = new(); internal readonly HttpClient Http;
        internal Fixture()
        {
            Certificate = new CertificateRequest("CN=idp", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
            Other = new CertificateRequest("CN=other", other, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1)); Http = new(Handler);
        }
        internal ProtocolTransport Transport(IKeycloakFeatureGate? gate = null) => new(Http, new("https://identity.invalid/"), "r", gate);
        internal KeycloakSamlServiceProvider Provider(bool sign = false, IKeycloakFeatureGate? gate = null, bool decrypt = false) => new(Transport(gate), Entity, Callback, [Certificate], new InMemoryDpopReplayStore(), sign ? Certificate : null, decrypt ? [Certificate] : null);
        internal SamlLoginTransaction Transaction(KeycloakSamlServiceProvider provider) => new(provider, "_request", "state", new("https://identity.invalid/"));
        internal string Response(string audience = Entity, bool wrongKey = false, Action<Saml2AuthnResponse>? mutate = null, bool encrypt = false)
        {
            var configuration = new Saml2Configuration { Issuer = Issuer, SigningCertificate = wrongKey ? Other : Certificate, EncryptionCertificate = encrypt ? Certificate : null, AuthnResponseSignType = Saml2AuthnResponseSignTypes.SignAssertionAndResponse };
            var response = new Saml2AuthnResponse(configuration) { Destination = Callback, InResponseTo = new Saml2Id("_request"), Status = Saml2StatusCodes.Success,
                SessionIndex = "session", ClaimsIdentity = new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, "user"), new Claim("display_name", "User")], "saml") };
            response.CreateSecurityToken(audience); mutate?.Invoke(response); new Saml2PostBinding().Bind(response);
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(response.XmlDocument.OuterXml));
        }
        internal (Uri Uri, string Encoded) Logout(Action<Saml2LogoutResponse>? mutate = null)
        {
            var response = new Saml2LogoutResponse(new() { Issuer = Issuer, SigningCertificate = Certificate }) { Destination = Callback, InResponseTo = new("_logout"), Status = Saml2StatusCodes.Success };
            mutate?.Invoke(response); var redirect = new Saml2RedirectBinding { RelayState = "state" }; redirect.Bind(response);
            new Saml2PostBinding().Bind(response); return (redirect.RedirectLocation, Convert.ToBase64String(Encoding.UTF8.GetBytes(response.XmlDocument.OuterXml)));
        }
        internal (Uri Uri, string Encoded, string Soap) LogoutRequest(bool wrongKey = false, Action<Saml2LogoutRequest>? mutate = null)
        {
            var request = new Saml2LogoutRequest(new() { Issuer = Issuer, SigningCertificate = wrongKey ? Other : Certificate })
                { Id = new("_idp-logout"), Destination = Callback, NameId = new("user"), SessionIndex = "session", NotOnOrAfter = DateTimeOffset.UtcNow.AddMinutes(2) };
            mutate?.Invoke(request); var redirect = new Saml2RedirectBinding { RelayState = "state" }; redirect.Bind(request);
            var post = new Saml2PostBinding(); post.Bind(request); string xml = post.XmlDocument.OuterXml;
            return (redirect.RedirectLocation, Convert.ToBase64String(Encoding.UTF8.GetBytes(xml)), "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body>" + xml + "</soap:Body></soap:Envelope>");
        }
        internal string Metadata() => "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"" + Issuer + "\"><md:IDPSSODescriptor><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"" + Issuer + "/protocol/saml\"/><md:KeyDescriptor><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>" + Convert.ToBase64String(Certificate.RawData) + "</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor></md:IDPSSODescriptor></md:EntityDescriptor>";
        public void Dispose() { Http.Dispose(); Certificate.Dispose(); Other.Dispose(); key.Dispose(); other.Dispose(); }
    }
    private sealed class Handler : HttpMessageHandler
    {
        internal string Response = "", Url = ""; internal HttpStatusCode Status = HttpStatusCode.OK; internal int Calls;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        { cancellationToken.ThrowIfCancellationRequested(); Calls++; Url = request.RequestUri!.AbsoluteUri; return Task.FromResult(new HttpResponseMessage(Status) { Content = new StringContent(Response) }); }
    }
    private sealed class LogoutStore : ISamlLogoutSessionStore
    {
        internal bool Fail; internal int Effects; internal SamlLogoutNotification? Last; private readonly HashSet<string> receipts = [];
        public ValueTask RevokeOnceAsync(SamlLogoutNotification notification, CancellationToken cancellationToken = default)
        { cancellationToken.ThrowIfCancellationRequested(); if (Fail) throw new IOException("Storage unavailable."); Last = notification; if (receipts.Add(notification.ReplayKey)) Effects++; return ValueTask.CompletedTask; }
    }
}
