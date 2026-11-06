using Keycloak.Admin.Sdk.Protocols;
using Microsoft.AspNetCore.Authentication;

namespace Keycloak.Admin.Sdk.Hosting;

/// <summary>Trusted application choices retained in the framework's protected OIDC state. Do not copy
/// arbitrary request query parameters here. Browser UI and authenticator mediation remain with Keycloak.</summary>
public static class KeycloakAuthenticationProperties
{
    private const string Action = ".keycloak.action", Provider = ".keycloak.provider", Capabilities = ".keycloak.authentication-capabilities";
    public static AuthenticationProperties WithKeycloakAuthentication(this AuthenticationProperties properties,
        IEnumerable<KeycloakAuthenticationCapability>? requiredCapabilities = null, string? action = null, string? identityProvider = null)
    {
        ArgumentNullException.ThrowIfNull(properties);
        var required = (requiredCapabilities ?? []).ToArray();
        if (required.Length > 10 || required.Any(c => !Enum.IsDefined(c))) throw new ArgumentException("Explicit bounded authentication capabilities are required.", nameof(requiredCapabilities));
        Validate(action); Validate(identityProvider);
        properties.Items[Action] = action; properties.Items[Provider] = identityProvider;
        properties.Items[Capabilities] = string.Join(',', required.Distinct()); return properties;
    }
    internal static OidcAuthorizationOptions Read(AuthenticationProperties? properties)
    {
        if (properties is null) return new();
        properties.Items.TryGetValue(Action, out string? action); properties.Items.TryGetValue(Provider, out string? provider);
        properties.Items.TryGetValue(Capabilities, out string? list); Validate(action); Validate(provider);
        var required = new List<KeycloakAuthenticationCapability>();
        if (!string.IsNullOrEmpty(list))
        {
            foreach (string name in list.Split(','))
            {
                if (required.Count >= 10 || !Enum.TryParse<KeycloakAuthenticationCapability>(name, out var capability) || !Enum.IsDefined(capability)) throw new InvalidDataException("Invalid protected authentication capability.");
                required.Add(capability);
            }
        }
        return new() { Action = action, IdentityProvider = provider, RequiredAuthenticationCapabilities = required };
    }
    private static void Validate(string? value)
    { if (value is not null && (string.IsNullOrWhiteSpace(value) || value.Length > 2048 || value.Any(char.IsControl))) throw new ArgumentException("A bounded protocol choice is required."); }
}
