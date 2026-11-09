using System.IO.Compression;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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
    public async Task RedirectLoginCompletesSignedBindingAndRejectsInvalidDestinationsExpansionAndConsumption()
    {
        using var fixture = new Fixture(); var provider = fixture.Provider(sign: true);
        var response = IdpResponse(fixture, "_request", Saml2AuthnResponseSignTypes.SignResponse);
        var redirect = new Saml2RedirectBinding { RelayState = "state" }; redirect.Bind(response);
        var transaction = new SamlLoginTransaction(provider, "_request", "state", new("https://identity.invalid"), responseBinding: SamlBrowserBinding.Redirect);
        Assert.AreEqual("user", (await transaction.CompleteRedirectAsync(redirect.RedirectLocation)).NameId);
        await Assert.ThrowsAsync<InvalidDataException>(() => transaction.CompleteRedirectAsync(redirect.RedirectLocation));
        foreach (var uri in new[] { new Uri("relative", UriKind.Relative), new Uri(Callback + "#fragment") })
            await Assert.ThrowsAsync<InvalidDataException>(() => provider.CompleteRedirectLoginAsync("_request", "state", DateTimeOffset.UtcNow.AddMinutes(1), [], () => Assert.Fail(), uri, default));
        await Assert.ThrowsAsync<ArgumentNullException>(() => provider.CompleteRedirectLoginAsync("_request", "state", DateTimeOffset.UtcNow.AddMinutes(1), [], () => Assert.Fail(), null!, default));
        Assert.Throws<ArgumentOutOfRangeException>(() => KeycloakSamlServiceProvider.BindingUri((SamlBrowserBinding)99));
        Assert.Throws<InvalidDataException>(() => KeycloakSamlServiceProvider.ReadQuery(new string('x', 350001)));
        Assert.Throws<InvalidDataException>(() => KeycloakSamlServiceProvider.ReadQuery("?no-equals"));
        using var memory = new MemoryStream();
        using (var deflate = new DeflateStream(memory, CompressionMode.Compress, true)) deflate.Write(Encoding.UTF8.GetBytes(new string('x', 262145)));
        var bomb = new Uri(Callback + "?SAMLResponse=" + Uri.EscapeDataString(Convert.ToBase64String(memory.ToArray())) + "&RelayState=state");
        await Assert.ThrowsAsync<InvalidDataException>(() => new SamlLogoutTransaction(provider, "_logout", "state", Callback).CompleteRedirectAsync(bomb));
    }

    [TestMethod]
    public async Task ArtifactResolutionValidatesOuterAndInnerSignedResponseAgainstTheOriginalBrowserTransaction()
    {
        using var fixture = new Fixture(); var provider = fixture.Provider(sign: true);
        string variant = "valid";
        fixture.Handler.Respond = async (request, ct) =>
        {
            Assert.AreEqual(Issuer + "/protocol/saml/resolve", request.RequestUri!.AbsoluteUri);
            var document = XDocument.Parse(await request.Content!.ReadAsStringAsync(ct));
            string id = document.Descendants(KeycloakSamlServiceProvider.Protocol + "ArtifactResolve").Single().Attribute("ID")!.Value;
            string artifactXml = SignArtifact(fixture, id, Encoding.UTF8.GetString(Convert.FromBase64String(fixture.Response(wrongKey: variant == "inner-key"))), variant == "outer-key");
            return new(HttpStatusCode.OK) { Content = new StringContent(Soap(artifactXml), Encoding.UTF8, "text/xml") };
        };
        var transaction = new SamlLoginTransaction(provider, "_request", "state", Callback, responseBinding: SamlBrowserBinding.Artifact);
        Assert.AreEqual("user", (await transaction.CompleteArtifactAsync(Callback, Artifact(), "state", fixture.Http)).NameId);
        await Assert.ThrowsAsync<InvalidDataException>(() => transaction.CompleteArtifactAsync(Callback, Artifact(), "state", fixture.Http));
        foreach (string forged in new[] { "outer-key", "inner-key" })
        {
            variant = forged;
            await Assert.ThrowsAsync<InvalidDataException>(() => new SamlLoginTransaction(provider, "_request", "state", Callback, responseBinding: SamlBrowserBinding.Artifact)
                .CompleteArtifactAsync(Callback, Artifact(), "state", fixture.Http));
        }
        await Assert.ThrowsAsync<InvalidDataException>(() => provider.CompleteArtifactLoginAsync("_request", "state", DateTimeOffset.UtcNow.AddSeconds(-1), [], () => Assert.Fail(), Callback, Artifact(), "state", fixture.Http, default));
        foreach (string header in new[] { "Authorization", "Cookie" })
        {
            fixture.Http.DefaultRequestHeaders.Add(header, "must-not-leak");
            await Assert.ThrowsAsync<ArgumentException>(() => provider.CompleteArtifactLoginAsync("_request", "state", DateTimeOffset.UtcNow.AddMinutes(1), [], () => Assert.Fail(), Callback, Artifact(), "state", fixture.Http, default));
            fixture.Http.DefaultRequestHeaders.Remove(header);
        }
        await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Provider().CompleteArtifactLoginAsync("_request", "state", DateTimeOffset.UtcNow.AddMinutes(1), [], () => Assert.Fail(), Callback, Artifact(), "state", fixture.Http, default));
        var badType = Convert.FromBase64String(Artifact()); badType[0] = 1;
        await Assert.ThrowsAsync<InvalidDataException>(() => provider.CompleteArtifactLoginAsync("_request", "state", DateTimeOffset.UtcNow.AddMinutes(1), [], () => { }, Callback, Convert.ToBase64String(badType), "state", fixture.Http, default));
    }

    [TestMethod]
    public async Task EcpBindsCredentialsToThePinnedEndpointAndOriginalSignedRequest()
    {
        using var fixture = new Fixture(); var provider = fixture.Provider(sign: true);
        fixture.Handler.Respond = async (request, ct) =>
        {
            Assert.AreEqual(Issuer + "/protocol/saml", request.RequestUri!.AbsoluteUri);
            Assert.AreEqual("Basic", request.Headers.Authorization!.Scheme);
            var xml = XDocument.Parse(await request.Content!.ReadAsStringAsync(ct));
            string id = xml.Descendants(KeycloakSamlServiceProvider.Protocol + "AuthnRequest").Single().Attribute("ID")!.Value;
            var response = IdpResponse(fixture, id); new Saml2PostBinding().Bind(response);
            return new(HttpStatusCode.OK) { Content = new StringContent(Soap(response.XmlDocument.OuterXml, EcpHeader), Encoding.UTF8, "text/xml") };
        };
        Assert.AreEqual("user", (await provider.AuthenticateEcpAsync(fixture.Http, _ => ValueTask.FromResult(new NetworkCredential("user", "password")))).NameId);
        foreach (NetworkCredential? invalid in new NetworkCredential?[] { null, new("", "password"), new("user", ""), new("with:colon", "password") })
            await Assert.ThrowsAsync<ArgumentException>(() => provider.AuthenticateEcpAsync(fixture.Http, _ => ValueTask.FromResult(invalid!)));
        fixture.Handler.Respond = null; fixture.Handler.Status = HttpStatusCode.Unauthorized; fixture.Handler.Response = Soap("", EcpHeader);
        await Assert.ThrowsAsync<InvalidDataException>(() => provider.AuthenticateEcpAsync(fixture.Http, _ => ValueTask.FromResult(new NetworkCredential("user", "wrong"))));
        fixture.Handler.Status = HttpStatusCode.OK;
        foreach (string xml in new[] { Soap(""), Soap("", "<soap:Header/>"), Soap("", EcpHeader), Soap("", "<soap:Header><ecp:Response xmlns:ecp=\"urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp\"/></soap:Header>") })
        {
            fixture.Handler.Response = xml;
            await Assert.ThrowsAsync<InvalidDataException>(() => provider.AuthenticateEcpAsync(fixture.Http, _ => ValueTask.FromResult(new NetworkCredential("user", "password"))));
        }
        fixture.Http.DefaultRequestHeaders.Add("Cookie", "must-not-leak");
        await Assert.ThrowsAsync<ArgumentException>(() => provider.AuthenticateEcpAsync(fixture.Http, _ => throw new AssertFailedException()));
        fixture.Http.DefaultRequestHeaders.Remove("Cookie");
        foreach (var (server, allow) in new[] { ("http://identity.invalid/", false), ("http://identity.invalid/", true), ("http://127.0.0.1/", true) })
        {
            var insecure = new KeycloakSamlServiceProvider(new(fixture.Http, new(server), "r"), Entity, Callback, [fixture.Certificate], new InMemoryDpopReplayStore());
            if (server.Contains("127.0.0.1", StringComparison.Ordinal))
                await Assert.ThrowsAsync<InvalidDataException>(() => insecure.AuthenticateEcpAsync(fixture.Http, _ => ValueTask.FromResult(new NetworkCredential("user", "password")), allow));
            else await Assert.ThrowsAsync<ArgumentException>(() => insecure.AuthenticateEcpAsync(fixture.Http, _ => throw new AssertFailedException(), allow));
        }
    }

    [TestMethod]
    public async Task SoapTransportRejectsUnpinnedMethodsOversizedBodiesAndNestedEnvelopes()
    {
        using var fixture = new Fixture(); var endpoint = new Uri(Issuer + "/protocol/saml/resolve");
        using var bounded = new HttpClient(new KeycloakSamlServiceProvider.ArtifactHttpHandler(fixture.Http, endpoint, _ => ValueTask.CompletedTask));
        foreach (var request in new[] { new HttpRequestMessage(HttpMethod.Get, endpoint), new HttpRequestMessage(HttpMethod.Post, "https://attacker.invalid"),
            new HttpRequestMessage(HttpMethod.Post, endpoint) { Content = new StringContent(new string('x', 262145)) } })
        { using (request) await Assert.ThrowsAsync<InvalidDataException>(() => bounded.SendAsync(request)); }
        fixture.Handler.Response = Soap("");
        using (var reply = await bounded.PostAsync(endpoint, null)) Assert.AreEqual(HttpStatusCode.OK, reply.StatusCode);
        foreach (string xml in new[] { "<invalid/>", Soap("<soap:Body/>") , "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"/>",
            "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body/><soap:Body/></soap:Envelope>" })
        {
            fixture.Handler.Response = xml;
            await Assert.ThrowsAsync<InvalidDataException>(() => bounded.PostAsync(endpoint, null));
        }
    }

    private const string EcpHeader = "<soap:Header><ecp:Response xmlns:ecp=\"urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp\" AssertionConsumerServiceURL=\"https://app.invalid/saml/callback\"/></soap:Header>";
    private static string Soap(string body, string header = "") => "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">" + header + "<soap:Body>" + body + "</soap:Body></soap:Envelope>";
    private static string SignArtifact(Fixture fixture, string requestId, string inner, bool wrongKey = false)
    {
        var document = new System.Xml.XmlDocument { PreserveWhitespace = true };
        document.LoadXml(new XDocument(new XElement(KeycloakSamlServiceProvider.Protocol + "ArtifactResponse",
            new XAttribute("ID", "_artifact"), new XAttribute("Version", "2.0"), new XAttribute("IssueInstant", System.Xml.XmlConvert.ToString(DateTimeOffset.UtcNow)),
            new XAttribute("InResponseTo", requestId), new XElement(KeycloakSamlServiceProvider.Assertion + "Issuer", Issuer),
            new XElement(KeycloakSamlServiceProvider.Protocol + "Status", new XElement(KeycloakSamlServiceProvider.Protocol + "StatusCode", new XAttribute("Value", "urn:oasis:names:tc:SAML:2.0:status:Success"))),
            XElement.Parse(inner, LoadOptions.PreserveWhitespace))).ToString(SaveOptions.DisableFormatting));
        var certificate = wrongKey ? fixture.Other : fixture.Certificate;
        using var key = certificate.GetRSAPrivateKey();
        var signed = new System.Security.Cryptography.Xml.SignedXml(document) { SigningKey = key };
        signed.SignedInfo!.CanonicalizationMethod = System.Security.Cryptography.Xml.SignedXml.XmlDsigExcC14NTransformUrl;
        signed.SignedInfo.SignatureMethod = System.Security.Cryptography.Xml.SignedXml.XmlDsigRSASHA256Url;
        var reference = new System.Security.Cryptography.Xml.Reference("#_artifact") { DigestMethod = System.Security.Cryptography.Xml.SignedXml.XmlDsigSHA256Url };
        reference.AddTransform(new System.Security.Cryptography.Xml.XmlDsigEnvelopedSignatureTransform());
        reference.AddTransform(new System.Security.Cryptography.Xml.XmlDsigExcC14NTransform()); signed.AddReference(reference);
        signed.KeyInfo = new System.Security.Cryptography.Xml.KeyInfo(); signed.KeyInfo.AddClause(new System.Security.Cryptography.Xml.KeyInfoX509Data(certificate));
        signed.ComputeSignature(); document.DocumentElement!.InsertAfter(document.ImportNode(signed.GetXml(), true), document.DocumentElement.FirstChild);
        return document.OuterXml;
    }
    private static string Artifact()
    {
        var bytes = new byte[44]; bytes[1] = 4; SHA1.HashData(Encoding.UTF8.GetBytes(Issuer)).CopyTo(bytes, 4); RandomNumberGenerator.Fill(bytes.AsSpan(24));
        return Convert.ToBase64String(bytes);
    }
    private static Saml2AuthnResponse IdpResponse(Fixture fixture, string id, Saml2AuthnResponseSignTypes signType = Saml2AuthnResponseSignTypes.SignAssertionAndResponse)
    {
        var response = new Saml2AuthnResponse(new() { Issuer = Issuer, SigningCertificate = fixture.Certificate, AuthnResponseSignType = signType })
        { Destination = Callback, InResponseTo = new(id), Status = Saml2StatusCodes.Success, SessionIndex = "session", ClaimsIdentity = new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, "user"), new Claim("display_name", "User")], "saml") };
        response.CreateSecurityToken(Entity); return response;
    }
}
