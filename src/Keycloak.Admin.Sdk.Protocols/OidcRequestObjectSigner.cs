using System.Globalization;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Keycloak.Admin.Sdk.Protocols;

/// <summary>RFC 9101 signed authorization requests. The host owns the signing key and registers its public key at the client.
/// Use OidcLoginTransaction.StartSignedAsync to retain browser correlation, nonce, PKCE and independent capability gates.</summary>
public sealed class OidcRequestObjectSigner
{
    private readonly string clientId;
    private readonly SigningCredentials signing;
    private readonly TimeSpan lifetime;
    private readonly TimeProvider clock;
    private readonly EncryptingCredentials? encryption;
    public OidcRequestObjectSigner(string clientId, SigningCredentials signing, TimeSpan? lifetime = null, TimeProvider? clock = null, EncryptingCredentials? encryption = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId); ArgumentNullException.ThrowIfNull(signing);
        if (!JwtAlgorithms.Asymmetric.Contains(signing.Algorithm, StringComparer.Ordinal)) throw new ArgumentException("An explicitly supported asymmetric request signature is required.", nameof(signing));
        this.clientId = clientId; this.signing = signing; this.lifetime = lifetime ?? TimeSpan.FromMinutes(1); this.clock = clock ?? TimeProvider.System;
        if (this.lifetime <= TimeSpan.Zero || this.lifetime > TimeSpan.FromMinutes(5)) throw new ArgumentOutOfRangeException(nameof(lifetime));
        if (encryption is not null)
        {
            if (encryption.Alg is not ("RSA-OAEP" or "RSA-OAEP-256") || encryption.Enc is not ("A128CBC-HS256" or "A192CBC-HS384" or "A256CBC-HS512"))
                throw new ArgumentException("Request encryption requires an RSA-OAEP key and an explicitly supported authenticated content cipher.", nameof(encryption));
            this.encryption = new(encryption.Key, encryption.Alg, encryption.Enc) { CryptoProviderFactory = new JweCryptoProviderFactory() };
        }
    }
    public ValueTask<Uri> CreateAuthorizationUriAsync(Uri issuer, Uri authorizationUri, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(issuer); ArgumentNullException.ThrowIfNull(authorizationUri); cancellationToken.ThrowIfCancellationRequested();
        if (!issuer.IsAbsoluteUri || issuer.Scheme is not ("https" or "http") || issuer.UserInfo.Length != 0 || issuer.Query.Length != 0 || issuer.Fragment.Length != 0
            || !authorizationUri.IsAbsoluteUri || authorizationUri.Fragment.Length != 0 || authorizationUri.GetLeftPart(UriPartial.Path) != issuer.AbsoluteUri.TrimEnd('/') + "/protocol/openid-connect/auth")
            throw new ArgumentException("A request object must target the pinned realm authorization endpoint.", nameof(authorizationUri));
        if (authorizationUri.Query.Length > 32768) throw new ArgumentException("Authorization request exceeds its bound.", nameof(authorizationUri));
        var claims = new Dictionary<string, object>(StringComparer.Ordinal);
        string[] reserved = ["iss", "aud", "iat", "nbf", "exp", "jti", "request", "request_uri", "client_secret", "client_assertion", "client_assertion_type", "code_verifier"];
        foreach (string pair in authorizationUri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            string[] parts = pair.Split('=', 2); string name = Uri.UnescapeDataString(parts[0].Replace('+', ' '));
            if (parts.Length != 2 || name.Length == 0 || claims.Count >= 64 || claims.ContainsKey(name) || reserved.Contains(name, StringComparer.Ordinal))
                throw new ArgumentException("Invalid or duplicate request-object parameter.", nameof(authorizationUri));
            string value = Uri.UnescapeDataString(parts[1].Replace('+', ' '));
            if (name is "claims" or "authorization_details")
            {
                using var document = JsonDocument.Parse(value);
                if (document.RootElement.ValueKind != (name == "claims" ? JsonValueKind.Object : JsonValueKind.Array)) throw new ArgumentException("Invalid structured request-object parameter.", nameof(authorizationUri));
                claims.Add(name, document.RootElement.Clone());
            }
            else if (name == "max_age")
            {
                if (!long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out long age)) throw new ArgumentException("Invalid request-object maximum age.", nameof(authorizationUri));
                claims.Add(name, age);
            }
            else claims.Add(name, value);
        }
        if (!claims.TryGetValue("client_id", out var identity) || !Equals(identity, clientId)) throw new ArgumentException("Request-object client must match the initiating client.", nameof(authorizationUri));
        var now = clock.GetUtcNow(); claims.Add("jti", Guid.NewGuid().ToString("N"));
        string credential = new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = clientId, Audience = issuer.AbsoluteUri.TrimEnd('/'), TokenType = "oauth-authz-req+jwt", IssuedAt = now.UtcDateTime,
            NotBefore = now.AddSeconds(-5).UtcDateTime, Expires = now.Add(lifetime).UtcDateTime, SigningCredentials = signing, EncryptingCredentials = encryption, Claims = claims
        });
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(new Uri(authorizationUri.GetLeftPart(UriPartial.Path) + "?" + ProtocolTransport.Query([new("client_id", clientId), new("request", credential)])));
    }
}
