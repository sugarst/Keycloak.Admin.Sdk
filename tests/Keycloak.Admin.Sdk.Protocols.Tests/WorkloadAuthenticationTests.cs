using System.Net;
using Keycloak.Admin.Sdk.Capabilities;
using Keycloak.Admin.Sdk.Protocols;
using Microsoft.VisualStudio.TestTools.UnitTesting;

[TestClass]
public sealed class WorkloadAuthenticationTests
{
    [TestMethod]
    public async Task WorkloadAuthenticationGatesBeforeCredentialSourcesAndUsesTheCorrectAssertionType()
    {
        using var handler = new Handler(); using var http = new HttpClient(handler);
        var flags = new KeycloakFeatureSnapshotGate(new Dictionary<string, bool> { ["KeycloakSdk.Protocols"] = true, ["KeycloakSdk.Protocols.Oidc"] = true, ["KeycloakSdk.Protocols.IdentityBrokering"] = true });
        var transport = new ProtocolTransport(http, new("https://identity.invalid/"), "r", flags); var oidc = new OidcClient(transport);
        int reads = 0; ValueTask<string> Read(CancellationToken ct) { ct.ThrowIfCancellationRequested(); reads++; return ValueTask.FromResult("assertion"); }
        foreach (var auth in new[] { OAuthClientAuthentication.FederatedAssertion("c", Read), OAuthClientAuthentication.SpiffeAssertion("c", Read), OAuthClientAuthentication.MutualTls("c") })
        {
            await Assert.ThrowsAsync<InvalidOperationException>(() => oidc.ClientCredentialsAsync(auth));
            await Assert.ThrowsAsync<InvalidOperationException>(() => new IdentityBrokerClient(transport).GetTokenAsync("upstream", auth, "user"));
        }
        Assert.AreEqual(0, reads); Assert.AreEqual(0, handler.Sends);
        var tlsTransport = new ProtocolTransport(http, new("https://identity.invalid/"), "r", flags, mutualTls: true);
        await Assert.ThrowsAsync<InvalidOperationException>(() => new OidcClient(tlsTransport).GetUserInfoAsync("existing-token"));
        await Assert.ThrowsAsync<InvalidOperationException>(() => tlsTransport.EnsureEnabledAsync("KeycloakSdk.Protocols.Oidc").AsTask());
        flags.Replace(new Dictionary<string, bool> { ["KeycloakSdk.Protocols"] = true, ["KeycloakSdk.Protocols.Oidc"] = true, ["KeycloakSdk.Protocols.FederatedClientAuth"] = true, ["KeycloakSdk.Protocols.SpiffeClientAuth"] = true, ["KeycloakSdk.Protocols.MutualTls"] = true });
        await oidc.ClientCredentialsAsync(OAuthClientAuthentication.SpiffeAssertion("c", Read));
        StringAssert.Contains(handler.Body, "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-spiffe");
        await oidc.ClientCredentialsAsync(OAuthClientAuthentication.FederatedAssertion("c", Read));
        StringAssert.Contains(handler.Body, "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer");
        await new OidcClient(tlsTransport).ClientCredentialsAsync(OAuthClientAuthentication.MutualTls("c"));
        Assert.AreEqual("grant_type=client_credentials&client_id=c", handler.Body);
        Assert.AreEqual(2, reads);
        flags.Replace(new Dictionary<string, bool> { ["KeycloakSdk.Protocols"] = true, ["KeycloakSdk.Protocols.Oidc"] = true, ["KeycloakSdk.Protocols.SpiffeClientAuth"] = true });
        await oidc.ClientCredentialsAsync(OAuthClientAuthentication.SpiffeAssertion("c", Read));
        await Assert.ThrowsAsync<InvalidOperationException>(() => oidc.ClientCredentialsAsync(OAuthClientAuthentication.FederatedAssertion("c", Read)));
        Assert.AreEqual(3, reads);
        Assert.Throws<ArgumentNullException>(() => OAuthClientAuthentication.FederatedAssertion("c", null!)); Assert.Throws<ArgumentNullException>(() => OAuthClientAuthentication.SpiffeAssertion("c", null!));
        using var cancel = new CancellationTokenSource(); cancel.Cancel();
        await Assert.ThrowsAsync<OperationCanceledException>(() => oidc.ClientCredentialsAsync(OAuthClientAuthentication.FederatedAssertion("c", Read), cancellationToken: cancel.Token)); Assert.AreEqual(3, reads);
    }
    private sealed class Handler : HttpMessageHandler
    {
        internal int Sends; internal string Body = "";
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        { Sends++; Body = request.Content is null ? "" : await request.Content.ReadAsStringAsync(cancellationToken); return new(HttpStatusCode.OK) { Content = new StringContent("{}") }; }
    }
}
