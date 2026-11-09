using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Security;
using System.Xml.Linq;
using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Schemas;
using Keycloak.Admin.Sdk.Hosting;
using Keycloak.Admin.Sdk.Protocols;
using Microsoft.IdentityModel.Tokens.Saml2;
using Microsoft.VisualStudio.TestTools.UnitTesting;

public sealed partial class SamlTests
{
    [TestMethod]
    public void SignedAssertionPostconditionsRejectEveryIndependentCorrelationIdentityAndLifetimeFailure()
    {
        using var fixture = new Fixture(); var provider = fixture.Provider();
        foreach (var mutate in new Action<Saml2AuthnResponse>[]
        {
            r => r.Status = Saml2StatusCodes.Responder,
            r => r.Destination = new("https://attacker.invalid"),
            r => r.InResponseTo = null,
            r => r.InResponseTo = new("wrong"),
            r => r.Saml2SecurityToken.Assertion.Issuer = new("https://attacker.invalid"),
            r => r.Saml2SecurityToken.Assertion.Subject.NameId = null!,
            r => r.Saml2SecurityToken.Assertion.Subject.NameId = new(" "),
            r => r.Saml2SecurityToken.Assertion.Conditions = null!,
            r => r.Saml2SecurityToken.Assertion.Conditions.NotOnOrAfter = null,
            r => r.Saml2SecurityToken.Assertion.Conditions.NotOnOrAfter = DateTime.UtcNow.AddMinutes(-1),
            r => r.Saml2SecurityToken.Assertion.Conditions.NotOnOrAfter = DateTime.UtcNow.AddDays(2),
            r => r.Saml2SecurityToken.Assertion.Subject.SubjectConfirmations.Clear(),
            r => r.Saml2SecurityToken.Assertion.Subject.SubjectConfirmations.Single().Method = new("urn:wrong"),
            r => r.Saml2SecurityToken.Assertion.Subject.SubjectConfirmations.Single().SubjectConfirmationData = null,
            r => r.Saml2SecurityToken.Assertion.Subject.SubjectConfirmations.Single().SubjectConfirmationData.Recipient = new("https://attacker.invalid"),
            r => r.Saml2SecurityToken.Assertion.Subject.SubjectConfirmations.Single().SubjectConfirmationData.InResponseTo = null,
            r => r.Saml2SecurityToken.Assertion.Subject.SubjectConfirmations.Single().SubjectConfirmationData.InResponseTo = new("wrong"),
            r => r.Saml2SecurityToken.Assertion.Subject.SubjectConfirmations.Single().SubjectConfirmationData.NotOnOrAfter = DateTime.UtcNow.AddMinutes(-1),
            r => r.Saml2SecurityToken.Assertion.Subject.SubjectConfirmations.Single().SubjectConfirmationData.NotOnOrAfter = null,
            r => r.Saml2SecurityToken.Assertion.Conditions.AudienceRestrictions.Clear(),
            r => { var audience = r.Saml2SecurityToken.Assertion.Conditions.AudienceRestrictions.Single(); audience.Audiences.Clear(); audience.Audiences.Add(Entity + "/"); }
        })
        {
            var response = ReadVerifiedResponse(fixture); mutate(response);
            Assert.Throws<InvalidDataException>(() => provider.ValidateAuthenticationResponse(response, "_request", []));
        }
        var valid = ReadVerifiedResponse(fixture);
        valid.Saml2SecurityToken.Assertion.Conditions.AudienceRestrictions.Add(new Saml2AudienceRestriction(Entity));
        Assert.IsTrue(provider.ValidateAuthenticationResponse(valid, "_request", []).NotAfter > DateTime.UtcNow);
        Assert.Throws<InvalidDataException>(() => provider.ValidateAuthenticationResponse(valid, "_request", ["urn:strong"]));
        var context = valid.Saml2SecurityToken.Assertion.Statements.OfType<Saml2AuthenticationStatement>().Single().AuthenticationContext;
        string expected = context.ClassReference.OriginalString;
        Assert.AreEqual(expected, provider.ValidateAuthenticationResponse(valid, "_request", [expected]).AuthenticationContext);
        valid.Saml2SecurityToken.Assertion.Statements.OfType<Saml2AuthenticationStatement>().Single().AuthenticationContext = new Saml2AuthenticationContext { DeclarationReference = new("urn:declared") };
        Assert.IsNull(provider.ValidateAuthenticationResponse(valid, "_request", []).AuthenticationContext);
        Assert.Throws<InvalidDataException>(() => provider.ValidateAuthenticationResponse(valid, "_request", [expected]));
    }

    [TestMethod]
    public void SignedEnvelopeRequiresOneDirectAssertionOrOneDirectEncryptedAssertion()
    {
        using var fixture = new Fixture(); var provider = fixture.Provider();
        XNamespace assertion = "urn:oasis:names:tc:SAML:2.0:assertion", protocol = "urn:oasis:names:tc:SAML:2.0:protocol";
        XDocument Envelope(params XElement[] children) => new(new XElement(protocol + "Response", new XElement(assertion + "Issuer", Issuer), children));
        provider.ValidateAuthenticationEnvelope(Envelope(new XElement(assertion + "Assertion")));
        provider.ValidateAuthenticationEnvelope(Envelope(new XElement(assertion + "EncryptedAssertion", new XElement(assertion + "Assertion"))));
        foreach (var document in new[]
        {
            new XDocument(), new XDocument(new XElement(assertion + "Assertion")),
            Envelope(), Envelope(new XElement(assertion + "Assertion"), new XElement(assertion + "Assertion")),
            Envelope(new XElement("wrapper", new XElement(assertion + "Assertion"))),
            Envelope(new XElement("wrapper", new XElement(assertion + "EncryptedAssertion", new XElement(assertion + "Assertion")))),
            new XDocument(new XElement(protocol + "Response", new XElement(assertion + "Assertion"))),
            new XDocument(new XElement(protocol + "Response", new XElement(assertion + "Issuer", "https://attacker.invalid"), new XElement(assertion + "Assertion")))
        }) Assert.Throws<InvalidDataException>(() => provider.ValidateAuthenticationEnvelope(document));
    }

    [TestMethod]
    public async Task SamlRegistrationAndTransactionBoundsRetainManagedCertificateAndBrowserRequirements()
    {
        using var fixture = new Fixture(); var provider = fixture.Provider(sign: true);
        KeycloakSamlServiceProvider.EnsureManagedRuntime(true);
        Assert.Throws<PlatformNotSupportedException>(() => KeycloakSamlServiceProvider.EnsureManagedRuntime(false));
        Assert.Throws<ArgumentException>(() => new KeycloakSamlServiceProvider(fixture.Transport(), "relative", Callback, [fixture.Certificate], new InMemoryDpopReplayStore()));
        Assert.Throws<ArgumentException>(() => new KeycloakSamlServiceProvider(fixture.Transport(), Entity, Callback, [fixture.Certificate], new InMemoryDpopReplayStore(), decryptionCertificates: [null!]));
        using var key = RSA.Create(2048);
        using var expired = new CertificateRequest("CN=expired", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-2), DateTimeOffset.UtcNow.AddDays(-1));
        using var future = new CertificateRequest("CN=future", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(1), DateTimeOffset.UtcNow.AddDays(2));
        foreach (var invalid in new[] { expired, future })
            await Assert.ThrowsAsync<InvalidDataException>(() => new KeycloakSamlServiceProvider(fixture.Transport(), Entity, Callback, [invalid], new InMemoryDpopReplayStore()).StartLoginAsync());
        await Assert.ThrowsAsync<InvalidDataException>(() => provider.CompleteAsync("_request", "state", DateTimeOffset.UtcNow.AddSeconds(-1), [], () => Assert.Fail(), Callback, fixture.Response(), "state", default));
        await Assert.ThrowsAsync<InvalidDataException>(() => provider.CompleteAsync("_request", "state", DateTimeOffset.UtcNow.AddMinutes(1), [], () => Assert.Fail(), Callback, fixture.Response(), null!, default));
        await Assert.ThrowsAsync<ArgumentNullException>(() => provider.StartLoginAsync(new SamlLoginOptions { AuthenticationContexts = null! }));
        await Assert.ThrowsAsync<ArgumentException>(() => provider.StartLoginAsync(new SamlLoginOptions { AuthenticationContexts = [null!] }));
        var session = new VerifiedSamlSession(new(), new("user") { Format = new("urn:nameid"), NameQualifier = "idp", SPNameQualifier = "sp" }, "session", Issuer, Entity);
        var logout = await provider.StartLogoutAsync(session, SamlBrowserBinding.Post);
        Assert.IsNotNull(logout.FormFields); Assert.IsTrue(logout.FormFields.ContainsKey("SAMLRequest"));
        Assert.AreEqual("urn:nameid", session.NameIdFormat);
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => provider.StartLogoutAsync(session, SamlBrowserBinding.Artifact));
        await Assert.ThrowsAsync<ArgumentException>(() => provider.StartLogoutAsync(new VerifiedSamlSession(new(), new("user"), "session", Issuer, "urn:other")));
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        await Assert.ThrowsAsync<OperationCanceledException>(() => fixture.Transaction(provider).CompleteAsync(Callback, "x", "state", cancelled.Token));
        await Assert.ThrowsAsync<OperationCanceledException>(() => fixture.Transaction(provider).CompleteRedirectAsync(Callback, cancelled.Token));
        await Assert.ThrowsAsync<OperationCanceledException>(() => fixture.Transaction(provider).CompleteArtifactAsync(Callback, "x", "state", fixture.Http, cancelled.Token));
        string metadata = fixture.Provider(decrypt: true).CreateMetadata(); StringAssert.Contains(metadata, "encryption");
        var config = new Saml2Configuration { Issuer = Issuer, SigningCertificate = fixture.Certificate };
        var artifactResponse = new Saml2ArtifactResponse(config, ReadVerifiedResponse(fixture)) { InResponseTo = new("_resolve"), Status = Saml2StatusCodes.Success };
        provider.ValidateArtifactResponse(artifactResponse, "_resolve");
        foreach (var mutate in new Action<Saml2ArtifactResponse>[] { r => r.Status = Saml2StatusCodes.Responder, r => r.InResponseTo = null,
            r => r.InResponseTo = new("wrong"), r => r.Issuer = "urn:other", r => r.IssueInstant = DateTimeOffset.UtcNow.AddMinutes(-6), r => r.IssueInstant = DateTimeOffset.UtcNow.AddMinutes(1) })
        {
            var response = new Saml2ArtifactResponse(config, ReadVerifiedResponse(fixture)) { InResponseTo = new("_resolve"), Status = Saml2StatusCodes.Success };
            mutate(response); Assert.Throws<InvalidDataException>(() => provider.ValidateArtifactResponse(response, "_resolve"));
        }
    }

    private static Saml2AuthnResponse ReadVerifiedResponse(Fixture fixture)
    {
        var response = new Saml2AuthnResponse(new() { Issuer = Entity, AllowedIssuer = Issuer, AllowedAudienceUris = [Entity],
            SignatureValidationCertificates = [fixture.Certificate], CertificateValidationMode = X509CertificateValidationMode.None });
        new Saml2PostBinding().Unbind(new ITfoxtec.Identity.Saml2.Http.HttpRequest { Method = "POST", Form = new() { ["SAMLResponse"] = fixture.Response() } }, response);
        return response;
    }
}

