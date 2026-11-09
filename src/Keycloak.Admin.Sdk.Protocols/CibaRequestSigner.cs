using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Keycloak.Admin.Sdk.Protocols;

/// <summary>Signs a short-lived CIBA authentication request for the pinned realm. Client authentication is still supplied separately.</summary>
public sealed class CibaRequestSigner
{
    private readonly string clientId;
    private readonly OidcClient issuer;
    private readonly SigningCredentials signing;
    private readonly TimeProvider clock;
    public CibaRequestSigner(string clientId, OidcClient issuer, SigningCredentials signing, TimeProvider? clock = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId); this.clientId = clientId;
        this.issuer = issuer ?? throw new ArgumentNullException(nameof(issuer)); this.signing = signing ?? throw new ArgumentNullException(nameof(signing));
        if (!JwtAlgorithms.Asymmetric.Contains(signing.Algorithm, StringComparer.Ordinal)) throw new ArgumentException("CIBA request signing requires an asymmetric algorithm.", nameof(signing));
        this.clock = clock ?? TimeProvider.System;
    }
    public ValueTask<string> CreateAsync(CibaAuthenticationRequest request, string scope, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request); ArgumentException.ThrowIfNullOrWhiteSpace(scope);
        if (request.SignedRequest is not null) throw new ArgumentException("A CIBA request object cannot wrap another signed request.", nameof(request));
        cancellationToken.ThrowIfCancellationRequested();
        var claims = request.Form().ToDictionary(p => p.Key, p => (object)p.Value, StringComparer.Ordinal);
        if (request.RequestedExpirySeconds is { } expiry) claims["requested_expiry"] = expiry;
        claims.Add("scope", scope); claims.Add("client_id", clientId); claims.Add("jti", Guid.NewGuid().ToString("N"));
        var now = clock.GetUtcNow();
        string signed = new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(new SecurityTokenDescriptor
        { Issuer = clientId, Audience = issuer.Issuer.AbsoluteUri, IssuedAt = now.UtcDateTime, NotBefore = now.AddSeconds(-5).UtcDateTime, Expires = now.AddMinutes(1).UtcDateTime, Claims = claims, SigningCredentials = signing });
        cancellationToken.ThrowIfCancellationRequested(); return ValueTask.FromResult(signed);
    }
}
