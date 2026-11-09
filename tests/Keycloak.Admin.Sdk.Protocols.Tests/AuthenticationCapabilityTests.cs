using Keycloak.Admin.Sdk.Capabilities;
using Keycloak.Admin.Sdk.Protocols;
using Microsoft.VisualStudio.TestTools.UnitTesting;

[TestClass]
public sealed class AuthenticationCapabilityTests
{
    [TestMethod]
    public async Task ServerHostedMethodsAndActionsHaveIndependentGatesWithoutReadingSecrets()
    {
        using var http = new HttpClient(); var values = Enum.GetValues<KeycloakAuthenticationCapability>();
        var flags = new Dictionary<string, bool> { ["KeycloakSdk.Protocols"] = true, ["KeycloakSdk.Protocols.Oidc"] = true, ["KeycloakSdk.Protocols.Authentication"] = true };
        var gate = new KeycloakFeatureSnapshotGate(flags); var oidc = new OidcClient(new(http, new("https://issuer.invalid"), "r", gate));
        var client = OAuthClientAuthentication.SecretBasic("app", _ => throw new AssertFailedException("Initiation must not read a client secret."));
        var callback = new Uri("https://app.invalid/callback");
        foreach (var value in values)
        {
            var options = new OidcAuthorizationOptions { RequiredAuthenticationCapabilities = [value] };
            await Assert.ThrowsAsync<InvalidOperationException>(() => OidcLoginTransaction.StartAsync(oidc, client, callback, options: options));
            flags[value.Feature()] = true; gate.Replace(flags);
            await OidcLoginTransaction.StartAsync(oidc, client, callback, options: options);
            flags[value.Feature()] = false; gate.Replace(flags);
        }
        foreach (var (action, capability) in new[] { ("webauthn-register", KeycloakAuthenticationCapability.WebAuthn), ("webauthn-register-passwordless", KeycloakAuthenticationCapability.WebAuthn),
            ("CONFIGURE_RECOVERY_AUTHN_CODES", KeycloakAuthenticationCapability.RecoveryCodes), ("UPDATE_EMAIL", KeycloakAuthenticationCapability.UpdateEmail) })
        {
            var options = new OidcAuthorizationOptions { Action = action };
            await Assert.ThrowsAsync<InvalidOperationException>(() => OidcLoginTransaction.StartAsync(oidc, client, callback, options: options));
            flags[capability.Feature()] = true; gate.Replace(flags);
            var login = await OidcLoginTransaction.StartAsync(oidc, client, callback, options: options); StringAssert.Contains(login.AuthorizationUri.Query, "kc_action=" + action);
            flags[capability.Feature()] = false; gate.Replace(flags);
        }
        await OidcLoginTransaction.StartAsync(oidc, client, callback, options: new() { Action = "UPDATE_PASSWORD" });
        flags["KeycloakSdk.Protocols.Authentication"] = false; gate.Replace(flags);
        await Assert.ThrowsAsync<InvalidOperationException>(() => OidcLoginTransaction.StartAsync(oidc, client, callback, options: new() { Action = "UPDATE_PASSWORD" }));
        flags[KeycloakAuthenticationCapability.WebAuthn.Feature()] = true; gate.Replace(flags);
        await Assert.ThrowsAsync<InvalidOperationException>(() => OidcLoginTransaction.StartAsync(oidc, client, callback, options: new() { RequiredAuthenticationCapabilities = [KeycloakAuthenticationCapability.WebAuthn] }));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => OidcLoginTransaction.StartAsync(oidc, client, callback, options: new() { RequiredAuthenticationCapabilities = [(KeycloakAuthenticationCapability)999] }));
        Assert.AreEqual(0, AuthenticationCapabilities.Required(null).Count());
        Assert.AreEqual(0, AuthenticationCapabilities.Required(new() { Action = "idp_link:external" }).Count());
        await Assert.ThrowsAsync<ArgumentNullException>(() => oidc.EnsureAuthorizationEnabledAsync(null!).AsTask());
        await oidc.EnsureAuthorizationEnabledAsync(new());
    }
}
