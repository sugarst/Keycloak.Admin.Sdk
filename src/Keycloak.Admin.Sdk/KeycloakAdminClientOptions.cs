namespace Keycloak.Admin.Sdk;

public sealed class KeycloakAdminClientOptions
{
    /// <summary>Conditionally invalidate rejected tokens. Generated, bodyless GET/HEAD requests may be replayed once. Default false.</summary>
    public bool EnableUnauthorizedRecovery { get; init; }
}

public sealed class KeycloakRequestOptions
{
    /// <summary>Explicitly allow one 401 replay for this raw, bodyless admin GET/HEAD, when client recovery is enabled.</summary>
    public bool AllowUnauthorizedReplay { get; init; }
}

public sealed class ClientCredentialsTokenProviderOptions
{
    /// <summary>Bounds the shared token acquisition, including secret resolution and response body reading. Default 30 seconds.</summary>
    public TimeSpan RequestTimeout { get; init; } = TimeSpan.FromSeconds(30);
    /// <summary>Share a failed acquisition during this interval to limit authentication failure bursts. Default one second; zero disables cooldown. Must fit a .NET timer.</summary>
    public TimeSpan FailureCooldown { get; init; } = TimeSpan.FromSeconds(1);
}
