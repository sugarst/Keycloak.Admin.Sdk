using Keycloak.Admin.Sdk.Capabilities;
using Keycloak.Admin.Sdk.Protocols;
using Microsoft.VisualStudio.TestTools.UnitTesting;

[TestClass]
public sealed class BrokerLoginTests
{
    [TestMethod]
    public async Task BrowserBrokerLoginLinkingAndClientAuthenticationHaveIndependentGatesBeforeAnyCredentialRead()
    {
        using var http = new HttpClient(); var flags = new KeycloakFeatureSnapshotGate(new Dictionary<string, bool>
        { ["KeycloakSdk.Protocols"] = true, ["KeycloakSdk.Protocols.Oidc"] = true, ["KeycloakSdk.Protocols.IdentityBrokerLogin"] = true, ["KeycloakSdk.Protocols.Authentication"] = true });
        var oidc = new OidcClient(new(http, new("https://identity.invalid/"), "r", flags)); var callback = new Uri("https://app.invalid/cb");
        var auth = OAuthClientAuthentication.SecretBasic("client", _ => throw new AssertFailedException("Login initiation cannot read a secret."));
        var login = await OidcLoginTransaction.StartAsync(oidc, auth, callback, options: new() { IdentityProvider = "upstream" });
        StringAssert.Contains(login.AuthorizationUri.Query, "kc_idp_hint=upstream");
        await Assert.ThrowsAsync<InvalidOperationException>(() => OidcLoginTransaction.StartAsync(oidc, auth, callback, options: new() { Action = "idp_link:upstream" }));
        await Assert.ThrowsAsync<InvalidOperationException>(() => OidcLoginTransaction.StartAsync(oidc, OAuthClientAuthentication.MutualTls("client"), callback));
        await OidcLoginTransaction.StartAsync(oidc, "client", callback, options: new() { Action = "UPDATE_PASSWORD" });
        flags.Replace(new Dictionary<string, bool> { ["KeycloakSdk.Protocols"] = true, ["KeycloakSdk.Protocols.Oidc"] = true, ["KeycloakSdk.Protocols.IdentityLinking"] = true });
        var link = await OidcLoginTransaction.StartAsync(oidc, auth, callback, options: new() { Action = "idp_link:upstream" });
        StringAssert.Contains(link.AuthorizationUri.Query, "kc_action=idp_link%3Aupstream");
        await Assert.ThrowsAsync<InvalidOperationException>(() => OidcLoginTransaction.StartAsync(oidc, auth, callback, options: new() { IdentityProvider = "upstream" }));
        await Assert.ThrowsAsync<ArgumentNullException>(() => OidcLoginTransaction.StartAsync(oidc, (OAuthClientAuthentication)null!, callback));
        using var cancel = new CancellationTokenSource(); cancel.Cancel();
        await Assert.ThrowsAsync<OperationCanceledException>(() => OidcLoginTransaction.StartAsync(oidc, auth, callback, cancellationToken: cancel.Token));
    }
}
