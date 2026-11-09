using System.Net;
using System.Text;
using System.Xml.Linq;
using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Schemas;
using Keycloak.Admin.Sdk.Hosting;
using Keycloak.Admin.Sdk.Protocols;
using Microsoft.VisualStudio.TestTools.UnitTesting;

public sealed partial class SamlTests
{
    [TestMethod]
    public async Task IncomingLogoutRejectsMalformedTransportAndValidatesNotificationFields()
    {
        using var fixture = new Fixture(); var provider = fixture.Provider(sign: true); var store = new LogoutStore();
        foreach (Uri uri in new Uri[] { new("relative", UriKind.Relative), new(Callback + "#fragment"), new("https://app.invalid/other") })
            await Assert.ThrowsAsync<InvalidDataException>(() => provider.HandleLogoutRedirectAsync(uri, store));
        await Assert.ThrowsAsync<ArgumentNullException>(() => provider.HandleLogoutRedirectAsync(null!, store));
        await Assert.ThrowsAsync<ArgumentNullException>(() => provider.HandleLogoutPostAsync(Callback, "x", null, null!));
        await Assert.ThrowsAsync<InvalidDataException>(() => provider.HandleLogoutPostAsync(new("https://app.invalid/other"), "x", null, store));
        await Assert.ThrowsAsync<InvalidDataException>(() => provider.HandleLogoutPostAsync(Callback, "x", new string('s', 1025), store));
        await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Provider().HandleLogoutPostAsync(Callback, "x", null, store));
        foreach (string xml in new[] { "<invalid/>", "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"/>",
            Soap(""), Soap("<wrapper><soap:Body/></wrapper>"), "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><wrapper><soap:Body/></wrapper></soap:Envelope>" })
            await Assert.ThrowsAsync<InvalidDataException>(() => provider.HandleLogoutSoapAsync(Callback, xml, store));
        var signed = fixture.LogoutRequest(mutate: r => r.NameId.Format = new("urn:format"));
        var reply = await provider.HandleLogoutPostAsync(Callback, signed.Encoded, null, store);
        Assert.IsFalse(reply.FormFields!.ContainsKey("RelayState")); Assert.IsTrue(reply.Destination.AbsoluteUri.StartsWith(Issuer, StringComparison.Ordinal));
        Assert.AreEqual("urn:format", store.Last!.NameIdFormat); Assert.IsTrue(store.Last.ExpiresAt > DateTimeOffset.UtcNow);
        var validXml = XDocument.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(signed.Encoded)));
        Saml2LogoutRequest Request() => new(new() { Issuer = Issuer }) { Id = new("_logout"), Destination = Callback, NameId = new("user"), SessionIndex = "session", IssueInstant = DateTimeOffset.UtcNow };
        foreach (Action<Saml2LogoutRequest> mutate in new Action<Saml2LogoutRequest>[]
        { r => r.Destination = new("https://app.invalid/other"), r => r.Issuer = "urn:other", r => r.NameId = null, r => r.NameId = new(" "),
            r => r.SessionIndex = " ", r => r.IssueInstant = DateTimeOffset.UtcNow.AddMinutes(-6), r => r.IssueInstant = DateTimeOffset.UtcNow.AddMinutes(1) })
        { var request = Request(); mutate(request); Assert.Throws<InvalidDataException>(() => provider.ValidateIncomingLogoutRequest(request, validXml)); }
        foreach (XDocument invalid in new[]
        {
            new XDocument(new XElement("wrong")),
            Changed(validXml, x => x.Root!.Add(new XElement(KeycloakSamlServiceProvider.Protocol + "SessionIndex", "other"))),
            Changed(validXml, x => x.Root!.Add(new XElement(KeycloakSamlServiceProvider.Assertion + "NameID", "other"))),
            Changed(validXml, x => x.Root!.Add(new XElement(KeycloakSamlServiceProvider.Assertion + "Issuer", Issuer))),
            Changed(validXml, x => x.Root!.SetAttributeValue("NotOnOrAfter", DateTimeOffset.UtcNow.AddSeconds(-1).ToString("O"))),
            Changed(validXml, x => x.Root!.SetAttributeValue("NotOnOrAfter", DateTimeOffset.UtcNow.AddHours(1).ToString("O")))
        }) Assert.Throws<InvalidDataException>(() => provider.ValidateIncomingLogoutRequest(Request(), invalid));
        Assert.Throws<InvalidDataException>(() => KeycloakSamlServiceProvider.ArtifactAuthenticationResponse(new(new XElement(KeycloakSamlServiceProvider.Protocol + "ArtifactResponse"))));
        var custom = new KeycloakSamlServiceProvider(fixture.Transport(), Entity, Callback, [fixture.Certificate], new InMemoryDpopReplayStore(), fixture.Certificate, singleLogoutService: new("https://app.invalid/logout"));
        StringAssert.Contains(custom.CreateMetadata(), "https://app.invalid/logout");
        var development = new KeycloakSamlServiceProvider(fixture.Transport(), Entity, new("http://127.0.0.1/callback"), [fixture.Certificate], new InMemoryDpopReplayStore());
        StringAssert.Contains(development.CreateMetadata(), "http://127.0.0.1/callback");
    }

    [TestMethod]
    public async Task LogoutResponsePostconditionsRejectUnsuccessfulMissingAndSubstitutedCorrelations()
    {
        using var fixture = new Fixture(); var provider = fixture.Provider(sign: true);
        Saml2LogoutResponse Response() => new(new() { Issuer = Issuer }) { Destination = Callback, InResponseTo = new("_logout"), Status = Saml2StatusCodes.Success };
        provider.ValidateLogoutResponse(Response(), "_logout");
        foreach (string? id in new[] { null, "", " " }) Assert.Throws<InvalidDataException>(() => KeycloakSamlServiceProvider.ValidateMessageId(id));
        KeycloakSamlServiceProvider.ValidateMessageId("_valid");
        foreach (var mutate in new Action<Saml2LogoutResponse>[] { r => r.Status = Saml2StatusCodes.Responder, r => r.Destination = new("https://app.invalid/other"),
            r => r.InResponseTo = null, r => r.InResponseTo = new("wrong"), r => r.Issuer = "urn:other", r => r.IssueInstant = DateTimeOffset.UtcNow.AddMinutes(-6), r => r.IssueInstant = DateTimeOffset.UtcNow.AddMinutes(1) })
        { var response = Response(); mutate(response); Assert.Throws<InvalidDataException>(() => provider.ValidateLogoutResponse(response, "_logout")); }
        var valid = fixture.Logout();
        await Assert.ThrowsAsync<InvalidDataException>(() => provider.CompleteLogoutAsync("_logout", "state", DateTimeOffset.UtcNow.AddSeconds(-1), () => Assert.Fail(), valid.Uri, null, null, default));
        await Assert.ThrowsAsync<InvalidDataException>(() => provider.CompleteLogoutAsync("_logout", "state", DateTimeOffset.UtcNow.AddMinutes(1), () => Assert.Fail(), new("relative", UriKind.Relative), null, null, default));
        await Assert.ThrowsAsync<InvalidDataException>(() => provider.CompleteLogoutAsync("_logout", "state", DateTimeOffset.UtcNow.AddMinutes(1), () => Assert.Fail(), new(Callback + "?query"), valid.Encoded, "state", default));
    }

    [TestMethod]
    public async Task MetadataLoadsExplicitSigningKeysAndDisposesPartialResultsOnMalformedCertificates()
    {
        using var fixture = new Fixture();
        fixture.Handler.Response = fixture.Metadata().Replace("<md:KeyDescriptor>", "<md:KeyDescriptor use=\"signing\">", StringComparison.Ordinal);
        var certificates = await KeycloakSamlMetadata.LoadSigningCertificatesAsync(fixture.Http, fixture.Transport());
        foreach (var certificate in certificates) certificate.Dispose();
        fixture.Handler.Response = fixture.Metadata().Replace("</md:KeyDescriptor>", "<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>invalid</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>", StringComparison.Ordinal);
        await Assert.ThrowsAsync<FormatException>(() => KeycloakSamlMetadata.LoadSigningCertificatesAsync(fixture.Http, fixture.Transport()));
        fixture.Http.DefaultRequestHeaders.Add("Cookie", "private");
        await Assert.ThrowsAsync<ArgumentException>(() => KeycloakSamlMetadata.LoadSigningCertificatesAsync(fixture.Http, fixture.Transport()));
        fixture.Http.DefaultRequestHeaders.Remove("Cookie");
        await Assert.ThrowsAsync<ArgumentException>(() => KeycloakSamlMetadata.LoadSigningCertificatesAsync(fixture.Http, new(fixture.Http, new("http://identity.invalid/"), "r"), true));
        fixture.Handler.Response = fixture.Metadata().Replace(Issuer, "http://127.0.0.1/realms/r", StringComparison.Ordinal);
        certificates = await KeycloakSamlMetadata.LoadSigningCertificatesAsync(fixture.Http, new(fixture.Http, new("http://127.0.0.1/"), "r"), true);
        foreach (var certificate in certificates) certificate.Dispose();
        fixture.Handler.Response = fixture.Metadata().Replace(Issuer + "/protocol/saml", Issuer + "/other", StringComparison.Ordinal);
        await Assert.ThrowsAsync<InvalidDataException>(() => KeycloakSamlMetadata.LoadSigningCertificatesAsync(fixture.Http, fixture.Transport()));
    }

    private static XDocument Changed(XDocument source, Action<XDocument> mutate) { var copy = new XDocument(source); mutate(copy); return copy; }
}

