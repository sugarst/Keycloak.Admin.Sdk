using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Keycloak.Admin.Sdk.Protocols;

/// <summary>Fresh private_key_jwt/client_secret_jwt assertions bound to one client and pinned realm token endpoint.
/// Host owns the key. Create a new signer or supply a live assertion callback when credentials rotate.</summary>
public sealed class ClientAssertionSigner
{
    private static readonly string[] Algorithms = [.. JwtAlgorithms.Asymmetric, "HS256", "HS384", "HS512"];
    private readonly string clientId, audience;
    private readonly SigningCredentials signing;
    private readonly TimeSpan lifetime;
    private readonly TimeProvider clock;
    public ClientAssertionSigner(string clientId, OidcClient issuer, SigningCredentials signing, TimeSpan? lifetime = null, TimeProvider? clock = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId); ArgumentNullException.ThrowIfNull(issuer); ArgumentNullException.ThrowIfNull(signing);
        this.clientId = clientId; audience = issuer.Issuer.AbsoluteUri + "/protocol/openid-connect/token"; this.signing = signing;
        if (!Algorithms.Contains(signing.Algorithm, StringComparer.Ordinal)) throw new ArgumentException("A secure signed client assertion algorithm is required.", nameof(signing));
        this.lifetime = lifetime ?? TimeSpan.FromMinutes(1); this.clock = clock ?? TimeProvider.System;
        if (this.lifetime <= TimeSpan.Zero || this.lifetime > TimeSpan.FromMinutes(5)) throw new ArgumentOutOfRangeException(nameof(lifetime));
    }
    public ValueTask<string> CreateAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested(); var now = clock.GetUtcNow();
        string assertion = new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = clientId, Audience = audience, IssuedAt = now.UtcDateTime, NotBefore = now.AddSeconds(-5).UtcDateTime, Expires = now.Add(lifetime).UtcDateTime,
            SigningCredentials = signing, Claims = new Dictionary<string, object> { ["sub"] = clientId, ["jti"] = Guid.NewGuid().ToString("N") }
        });
        cancellationToken.ThrowIfCancellationRequested(); return ValueTask.FromResult(assertion);
    }
}
