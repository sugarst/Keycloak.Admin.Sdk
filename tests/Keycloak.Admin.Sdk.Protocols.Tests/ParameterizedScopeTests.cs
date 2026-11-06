using System.Net;
using System.Text.Json;
using Keycloak.Admin.Sdk.Capabilities;
using Keycloak.Admin.Sdk.Protocols;
using Microsoft.VisualStudio.TestTools.UnitTesting;

[TestClass]
public sealed class ParameterizedScopeTests
{
    [TestMethod]
    public async Task ExplicitParameterizedScopesGateBeforeSecretsAndPreserveTheirExactValues()
    {
        using var handler = new Handler(); using var http = new HttpClient(handler); var flags = new KeycloakFeatureSnapshotGate(new Dictionary<string, bool>
        { ["KeycloakSdk.Protocols"] = true, ["KeycloakSdk.Protocols.Oidc"] = true });
        var transport = new ProtocolTransport(http, new("https://identity.invalid/"), "r", flags); var oidc = new OidcClient(transport);
        var credential = OAuthClientAuthentication.SecretBasic("client", _ => throw new AssertFailedException("No secret before the parameterized-scope gate."));
        await Assert.ThrowsAsync<InvalidOperationException>(() => oidc.ClientCredentialsWithParameterizedScopesAsync(credential, [new("project", "alpha")])); Assert.AreEqual(0, handler.Sends);
        await Assert.ThrowsAsync<InvalidOperationException>(() => OidcLoginTransaction.StartAsync(oidc, "client", new("https://app.invalid/cb"), options: new() { ParameterizedScopes = [new("project", "alpha")] }));
        var enabled = new OidcClient(new(http, new("https://identity.invalid/"), "r"));
        await enabled.ClientCredentialsWithParameterizedScopesAsync(OAuthClientAuthentication.Public("client"), [new("project", "a+b")], "openid"); StringAssert.Contains(handler.Body, "scope=openid+project%3Aa%2Bb");
        await enabled.ClientCredentialsWithParameterizedScopesAsync(OAuthClientAuthentication.Public("client"), [new("project", "alpha")]);
        await enabled.ClientCredentialsWithParameterizedScopesAsync(OAuthClientAuthentication.Public("client"), [new("project", "alpha")], " ");
        Assert.Throws<ArgumentNullException>(() => enabled.ClientCredentialsWithParameterizedScopesAsync(credential, null!));
        Assert.Throws<ArgumentException>(() => enabled.ClientCredentialsWithParameterizedScopesAsync(credential, []));
        Assert.Throws<ArgumentException>(() => enabled.ClientCredentialsWithParameterizedScopesAsync(credential, [null!]));
        foreach (var (name, value) in new[] { ("", "a"), ("n", ""), ("n:x", "a"), ("with space", "a"), ("n", new string('a', 256)), ("n", "bad value"), ("n", "\""), ("n", "\\"), ("n", "中文") })
            Assert.Throws<ArgumentException>(() => new OidcParameterizedScope(name, value));
    }
    [TestMethod]
    public async Task BrowserWorkflowCapturesItsRequiredGatesAndMultiFeatureChecksAreConjunctive()
    {
        using var handler = new Handler(); using var http = new HttpClient(handler); var transport = new ProtocolTransport(http, new("https://identity.invalid/"), "r"); var oidc = new OidcClient(transport);
        var transaction = await OidcLoginTransaction.StartAsync(oidc, "client", new("https://app.invalid/cb"), options: new() { Resources = [new("urn:resource:first")], ParameterizedScopes = [new("project", "alpha")] });
        StringAssert.Contains(transaction.AuthorizationUri.Query, "openid%20project%3Aalpha");
        await OidcLoginTransaction.StartAsync(oidc, "client", new("https://app.invalid/cb"));
        await OidcLoginTransaction.StartAsync(oidc, "client", new("https://app.invalid/cb"), "openid delegation:client:actor");
        await OidcLoginTransaction.StartAsync(oidc, "client", new("https://app.invalid/cb"), options: new() { ParameterizedScopes = null! });
        await transport.EnsureEnabledAsync(["KeycloakSdk.Protocols.Account"]);
        Assert.Throws<ArgumentNullException>(() => transport.EnsureEnabledAsync((IEnumerable<string>)null!));
        Assert.Throws<ArgumentException>(() => transport.EnsureEnabledAsync(Array.Empty<string>()));
        Assert.Throws<ArgumentException>(() => transport.EnsureEnabledAsync([" "]));
        using var cancel = new CancellationTokenSource(); cancel.Cancel();
        await Assert.ThrowsAsync<OperationCanceledException>(() => OidcLoginTransaction.StartAsync(oidc, "c", new("https://app.invalid/cb"), cancellationToken: cancel.Token));
        Assert.Throws<ArgumentNullException>(() => oidc.CreateAuthorizationUri("client", new("https://app.invalid/cb"), "s", "n", new string('v', 43), options: new() { ParameterizedScopes = [null!] }));
        var parameterized = new List<OidcParameterizedScope> { new("project", "alpha") };
        var flags = new KeycloakFeatureSnapshotGate(new Dictionary<string, bool> { ["KeycloakSdk.Protocols"] = true, ["KeycloakSdk.Protocols.Oidc"] = true });
        var bound = new OidcLoginTransaction(new(new(http, new("https://identity.invalid/"), "r", flags)), "client", new("https://app.invalid/cb"), options: new() { ParameterizedScopes = parameterized }); parameterized.Clear();
        await Assert.ThrowsAsync<InvalidOperationException>(() => bound.CompleteAsync(new("https://app.invalid/cb?state=" + bound.State + "&code=c"), OAuthClientAuthentication.Public("client"), new(oidc, "client")));
        Assert.AreEqual(0, handler.Sends);
    }
    private sealed class Handler : HttpMessageHandler
    {
        internal int Sends; internal string Body = "";
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        { Sends++; Body = await request.Content!.ReadAsStringAsync(cancellationToken); return new(HttpStatusCode.OK) { Content = new StringContent("{}") }; }
    }
}
