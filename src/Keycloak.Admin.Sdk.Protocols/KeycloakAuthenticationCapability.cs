namespace Keycloak.Admin.Sdk.Protocols;

/// <summary>Explicit server-hosted authentication dependencies. These control availability, not proof of an
/// authentication method; enforce signed acr/auth_time/amr with OidcAssuranceRequirement when required.</summary>
public enum KeycloakAuthenticationCapability
{
    WebAuthn, Passkeys, Kerberos, RecoveryCodes, UpdateEmail, TransientUsers,
    LegacyLogoutAllSessions, LegacyConditionalPasskeyUi, Instagram, Twitter
}

internal static class AuthenticationCapabilities
{
    internal static string Feature(this KeycloakAuthenticationCapability capability) => "KeycloakSdk.Protocols.Authentication" + (capability switch
    {
        KeycloakAuthenticationCapability.WebAuthn => "WebAuthn", KeycloakAuthenticationCapability.Passkeys => "Passkeys",
        KeycloakAuthenticationCapability.Kerberos => "Kerberos", KeycloakAuthenticationCapability.RecoveryCodes => "RecoveryCodes",
        KeycloakAuthenticationCapability.UpdateEmail => "UpdateEmail", KeycloakAuthenticationCapability.TransientUsers => "TransientUsers",
        KeycloakAuthenticationCapability.LegacyLogoutAllSessions => "LegacyLogoutAllSessions", KeycloakAuthenticationCapability.LegacyConditionalPasskeyUi => "LegacyConditionalPasskeyUi",
        KeycloakAuthenticationCapability.Instagram => "Instagram", KeycloakAuthenticationCapability.Twitter => "Twitter",
        _ => throw new ArgumentOutOfRangeException(nameof(capability))
    });
    internal static IEnumerable<string> Required(OidcAuthorizationOptions? options)
    {
        if (options is null) yield break;
        if (options.RequiredAuthenticationCapabilities.Count != 0) yield return "KeycloakSdk.Protocols.Authentication";
        foreach (var capability in options.RequiredAuthenticationCapabilities) yield return capability.Feature();
        if (options.Action is null || options.Action.StartsWith("idp_link:", StringComparison.Ordinal)) yield break;
        yield return "KeycloakSdk.Protocols.Authentication";
        switch (options.Action.Split(':', 2)[0])
        {
            case "webauthn-register": case "webauthn-register-passwordless": yield return KeycloakAuthenticationCapability.WebAuthn.Feature(); break;
            case "CONFIGURE_RECOVERY_AUTHN_CODES": yield return KeycloakAuthenticationCapability.RecoveryCodes.Feature(); break;
            case "UPDATE_EMAIL": yield return KeycloakAuthenticationCapability.UpdateEmail.Feature(); break;
        }
    }
}
