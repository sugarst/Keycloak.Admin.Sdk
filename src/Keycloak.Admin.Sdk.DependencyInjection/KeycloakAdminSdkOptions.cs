namespace Keycloak.Admin.Sdk;

/// <summary>One identity per registration. Use named registrations for different servers or credentials.</summary>
public sealed class KeycloakAdminSdkOptions
{
    public Uri Server { get; set; } = null!;
    public string AuthenticationRealm { get; set; } = "master";
    public string ClientId { get; set; } = "";
    /// <summary>Called for each acquisition; resolve secrets without storing them in options or logs.</summary>
    public Func<IServiceProvider, CancellationToken, ValueTask<string>> ClientSecret { get; set; } = null!;
    public KeycloakAdminClientOptions Client { get; set; } = new();
    public ClientCredentialsTokenProviderOptions Token { get; set; } = new();
}
