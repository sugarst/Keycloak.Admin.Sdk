using System.Net;
using Keycloak.Admin.Sdk.Capabilities;
using Keycloak.Admin.Sdk.Protocols;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualStudio.TestTools.UnitTesting;

[TestClass]
public sealed class IdentityAssertionTests
{
    [TestMethod]
    public async Task IdJagCannotUseTheStableJwtGrantGateToBypassItsIndependentExperimentalGate()
    {
        using var handler = new Handler(); using var http = new HttpClient(handler); var flags = new KeycloakFeatureSnapshotGate(new Dictionary<string, bool>
        { ["KeycloakSdk.Protocols"] = true, ["KeycloakSdk.Protocols.Oidc"] = true, ["KeycloakSdk.Protocols.OidcJwtGrant"] = true });
        var oidc = new OidcClient(new(http, new("https://identity.invalid/"), "r", flags)); int reads = 0;
        var client = OAuthClientAuthentication.SecretBasic("client", _ => { reads++; return ValueTask.FromResult("secret"); });
        string assertion = Jwt("""{"typ":"oauth-id-jag+jwt","alg":"RS256"}""");
        await Assert.ThrowsAsync<InvalidOperationException>(() => oidc.JwtGrantAsync(client, assertion));
        await Assert.ThrowsAsync<InvalidOperationException>(() => oidc.IdentityAssertionGrantAsync(client, assertion));
        foreach (string duplicate in new[] { """{"typ":"oauth-id-jag+jwt","typ":"JWT"}""", """{"typ":"JWT","typ":"oauth-id-jag+jwt"}""" })
            await Assert.ThrowsAsync<InvalidOperationException>(() => oidc.JwtGrantAsync(client, Jwt(duplicate)));
        Assert.AreEqual(0, handler.Sends); Assert.AreEqual(0, reads);
        flags.Replace(new Dictionary<string, bool> { ["KeycloakSdk.Protocols"] = true, ["KeycloakSdk.Protocols.Oidc"] = true, ["KeycloakSdk.Protocols.OidcIdentityAssertion"] = true });
        await Assert.ThrowsAsync<InvalidOperationException>(() => oidc.IdentityAssertionGrantAsync(client, assertion));
        Assert.AreEqual(0, reads);
        var enabled = new OidcClient(new(http, new("https://identity.invalid/"), "r"));
        await enabled.IdentityAssertionGrantAsync(client, assertion, "openid"); StringAssert.Contains(handler.Body, "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer");
        await enabled.JwtGrantAsync(client, Jwt("""{"alg":"RS256","typ":"JWT"}""")); await enabled.JwtGrantAsync(client, Jwt("""{"typ":42}""")); await enabled.JwtGrantAsync(client, Jwt("{}")); await enabled.JwtGrantAsync(client, Jwt("[]"));
    }
    [TestMethod]
    public void InvalidOrUnboundedHeadersNeverFallBackToAStableGrantOrExposeCredentialData()
    {
        using var http = new HttpClient(); var oidc = new OidcClient(new(http, new("https://identity.invalid/"), "r")); var client = OAuthClientAuthentication.Public("client");
        Assert.Throws<ArgumentException>(() => oidc.IdentityAssertionGrantAsync(client, ""));
        Assert.Throws<ArgumentException>(() => oidc.IdentityAssertionGrantAsync(client, "opaque"));
        Assert.Throws<ArgumentException>(() => oidc.IdentityAssertionGrantAsync(client, Jwt("{}")));
        foreach (string assertion in new[] { new string('x', 65537), new string('x', 8193) + ".payload.signature", "%.secret.signature", ".secret.signature", Jwt("{"), Jwt(new string('[', 17) + new string(']', 17)) })
        {
            var error = Assert.Throws<ArgumentException>(() => oidc.JwtGrantAsync(client, assertion));
            Assert.IsFalse(error.ToString().Contains("secret", StringComparison.Ordinal));
        }
    }
    private static string Jwt(string header) => Base64UrlEncoder.Encode(header) + ".e30.signature";
    private sealed class Handler : HttpMessageHandler
    {
        internal int Sends; internal string Body = "";
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        { Sends++; Body = await request.Content!.ReadAsStringAsync(cancellationToken); return new(HttpStatusCode.OK) { Content = new StringContent("{}") }; }
    }
}
