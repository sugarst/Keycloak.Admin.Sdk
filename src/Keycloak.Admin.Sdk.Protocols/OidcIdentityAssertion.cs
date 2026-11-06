using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace Keycloak.Admin.Sdk.Protocols;

public sealed partial class OidcClient
{
    /// <summary>Redeems an externally issued oauth-id-jag+jwt. Keycloak 26.8.1 consumes ID-JAGs; it does not provide an ID-JAG issuer/exchange endpoint.
    /// The configured trusted provider must verify signature, subject, client_id, audience, iat and one-time use. Use a supported transport to require the actual server feature.</summary>
    public Task<ProtocolResponse> IdentityAssertionGrantAsync(OAuthClientAuthentication client, string assertion, string? scope = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(assertion);
        if (!IsIdentityAssertion(assertion)) throw new ArgumentException("An oauth-id-jag+jwt assertion is required.", nameof(assertion));
        return JwtGrantAsync(client, assertion, scope, cancellationToken);
    }
    // This inspection selects independent capability gates, never authenticates any header or claim.
    // Examine every typ property conservatively so duplicate headers cannot bypass the experimental gate.
    private static bool IsIdentityAssertion(string assertion)
    {
        int separator = assertion.IndexOf('.');
        if (assertion.Length > 65536 || separator > 8192) throw new ArgumentException("JWT authorization assertions must be bounded.", nameof(assertion));
        if (separator < 0) return false;
        try
        {
            using var header = JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(assertion[..separator]), new JsonDocumentOptions { MaxDepth = 16 });
            return header.RootElement.ValueKind == JsonValueKind.Object && header.RootElement.EnumerateObject().Any(p => p.Name == "typ" && p.Value.ValueKind == JsonValueKind.String && p.Value.GetString() == "oauth-id-jag+jwt");
        }
        catch (Exception error) when (error is JsonException or FormatException or ArgumentException)
        { throw new ArgumentException("Invalid JWT authorization assertion header.", nameof(assertion)); }
    }
}
