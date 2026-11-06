using System.Text;

namespace Keycloak.Admin.Sdk.Protocols;

/// <summary>Provider-specific dynamic registration complements the OIDC/default JSON resource clients.</summary>
public sealed class ClientRegistrationClient(ProtocolTransport transport)
{
    private readonly ProtocolTransport transport = transport ?? throw new ArgumentNullException(nameof(transport));
    /// <summary>Deprecated adapter installation provider. The returned configuration can contain client credentials.</summary>
    public Task<ProtocolResponse> GetInstallationAsync(string clientId, string registrationAccessToken, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(registrationAccessToken);
        return transport.SendAsync(HttpMethod.Get, "clients-registrations/install/" + ProtocolTransport.Segment(clientId), "Registration.Installation", "KeycloakSdk.Protocols.ClientRegistration",
            null, registrationAccessToken, null, null, cancellationToken);
    }
    /// <summary>Deprecated SAML entity descriptor registration. The descriptor is sent to Keycloak, not locally trusted as an identity assertion.</summary>
    public Task<ProtocolResponse> RegisterSamlDescriptorAsync(string descriptor, string initialAccessToken, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(descriptor); ArgumentException.ThrowIfNullOrWhiteSpace(initialAccessToken);
        return transport.SendAsync(HttpMethod.Post, "clients-registrations/saml2-entity-descriptor", "Registration.SamlDescriptor", "KeycloakSdk.Protocols.ClientRegistration",
            new StringContent(descriptor, Encoding.UTF8, "application/xml"), initialAccessToken, null, null, cancellationToken);
    }
}
