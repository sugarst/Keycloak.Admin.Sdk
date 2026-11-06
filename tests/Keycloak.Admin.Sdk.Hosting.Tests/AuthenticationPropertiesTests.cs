using Keycloak.Admin.Sdk.Hosting;
using Keycloak.Admin.Sdk.Protocols;
using Microsoft.AspNetCore.Authentication;
using Microsoft.VisualStudio.TestTools.UnitTesting;

[TestClass]
public sealed class AuthenticationPropertiesTests
{
    [TestMethod]
    public void TrustedAuthenticationChoicesRoundTripWithoutAcceptingUnknownOrUnboundedProfiles()
    {
        var properties = new AuthenticationProperties().WithKeycloakAuthentication(Enum.GetValues<KeycloakAuthenticationCapability>(), "UPDATE_EMAIL", "upstream");
        var options = KeycloakAuthenticationProperties.Read(properties);
        Assert.AreEqual("UPDATE_EMAIL", options.Action); Assert.AreEqual("upstream", options.IdentityProvider); Assert.AreEqual(10, options.RequiredAuthenticationCapabilities.Count);
        Assert.AreEqual(0, KeycloakAuthenticationProperties.Read(null).RequiredAuthenticationCapabilities.Count);
        Assert.AreEqual(0, KeycloakAuthenticationProperties.Read(new()).RequiredAuthenticationCapabilities.Count);
        Assert.Throws<ArgumentNullException>(() => KeycloakAuthenticationProperties.WithKeycloakAuthentication(null!));
        Assert.Throws<ArgumentException>(() => new AuthenticationProperties().WithKeycloakAuthentication([(KeycloakAuthenticationCapability)999]));
        Assert.Throws<ArgumentException>(() => new AuthenticationProperties().WithKeycloakAuthentication(Enumerable.Repeat(KeycloakAuthenticationCapability.Passkeys, 11)));
        foreach (string invalid in new[] { "", " ", "invalid\n", new string('a', 2049) })
        { Assert.Throws<ArgumentException>(() => new AuthenticationProperties().WithKeycloakAuthentication(action: invalid)); Assert.Throws<ArgumentException>(() => new AuthenticationProperties().WithKeycloakAuthentication(identityProvider: invalid)); }
        foreach (string invalid in new[] { "unknown", "999", string.Join(',', Enumerable.Repeat("Passkeys", 11)) })
        {
            var corrupt = new AuthenticationProperties(); corrupt.Items[".keycloak.authentication-capabilities"] = invalid;
            Assert.Throws<InvalidDataException>(() => KeycloakAuthenticationProperties.Read(corrupt));
        }
    }
}
