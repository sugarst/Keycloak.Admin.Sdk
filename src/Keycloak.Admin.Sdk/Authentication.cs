using System.Text.Json;
using System.Text.Json.Serialization;

namespace Keycloak.Admin.Sdk;

public interface IAccessTokenProvider
{
    ValueTask<string> GetAccessTokenAsync(CancellationToken cancellationToken = default);
}

public sealed class StaticAccessTokenProvider : IAccessTokenProvider
{
    private readonly string token;
    public StaticAccessTokenProvider(string token)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);
        this.token = token;
    }
    public ValueTask<string> GetAccessTokenAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(token);
    }
}

public sealed class TokenResponse
{
    [JsonPropertyName("access_token")] public string? AccessToken { get; set; }
    [JsonPropertyName("expires_in")] public long ExpiresIn { get; set; }
    [JsonPropertyName("token_type")] public string? TokenType { get; set; }
}

/// <summary>Instance-local cache for one service account. Caller owns HttpClient and disposes provider after in-flight calls finish.</summary>
public sealed class ClientCredentialsTokenProvider : IAccessTokenProvider, IDisposable
{
    private readonly HttpClient client;
    private readonly Uri endpoint;
    private readonly string clientId;
    private readonly Func<CancellationToken, ValueTask<string>> secret;
    private readonly TimeProvider clock;
    private readonly SemaphoreSlim gate = new(1, 1);
    private string? cached;
    private DateTimeOffset refreshAt;

    public ClientCredentialsTokenProvider(HttpClient client, Uri server, string authenticationRealm, string clientId,
        Func<CancellationToken, ValueTask<string>> secret, TimeProvider? clock = null)
    {
        this.client = client ?? throw new ArgumentNullException(nameof(client));
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);
        this.clientId = clientId;
        this.secret = secret ?? throw new ArgumentNullException(nameof(secret));
        this.clock = clock ?? TimeProvider.System;
        endpoint = AdminUri.Combine(AdminUri.Base(server), AdminUri.Path("/realms/{0}/protocol/openid-connect/token", [authenticationRealm]), []);
    }

    public async ValueTask<string> GetAccessTokenAsync(CancellationToken cancellationToken = default)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (cached is not null && clock.GetUtcNow() < refreshAt) return cached;
            using var request = new HttpRequestMessage(HttpMethod.Post, endpoint)
            {
                Content = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["grant_type"] = "client_credentials", ["client_id"] = clientId,
                    ["client_secret"] = await secret(cancellationToken).ConfigureAwait(false)
                })
            };
            var started = clock.GetUtcNow();
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode) throw new KeycloakAdminException(response.StatusCode, "TOKEN POST");
            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            var token = await JsonSerializer.DeserializeAsync(stream, KeycloakJsonContext.Default.TokenResponse, cancellationToken).ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(token?.AccessToken) || token.ExpiresIn <= 0 || !string.Equals(token.TokenType, "Bearer", StringComparison.OrdinalIgnoreCase))
                throw new KeycloakResponseFormatException(response.StatusCode, new JsonException("Invalid token contract."));
            // Bound untrusted lifetimes before converting to a TimeSpan.
            double seconds = Math.Min(token.ExpiresIn, 86400);
            refreshAt = started.AddSeconds(seconds - Math.Min(30, seconds / 10));
            cached = token.AccessToken;
            return cached;
        }
        finally { gate.Release(); }
    }

    public void Dispose() => gate.Dispose();
}
