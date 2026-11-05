using System.Text.Json;
using System.Text.Json.Serialization;

namespace Keycloak.Admin.Sdk;

public interface IAccessTokenProvider
{
    ValueTask<string> GetAccessTokenAsync(CancellationToken cancellationToken = default);
}

/// <summary>Optional capability. Invalidation must preserve a newer token installed by another call.</summary>
public interface IRefreshableAccessTokenProvider : IAccessTokenProvider
{
    ValueTask InvalidateAsync(string rejectedToken, CancellationToken cancellationToken = default);
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
public sealed class ClientCredentialsTokenProvider(HttpClient client, Uri server, string authenticationRealm, string clientId,
    Func<CancellationToken, ValueTask<string>> secret, TimeProvider? clock, ClientCredentialsTokenProviderOptions options)
    : IRefreshableAccessTokenProvider, IDisposable
{
    private readonly HttpClient client = client ?? throw new ArgumentNullException(nameof(client));
    private readonly Uri endpoint = AdminUri.Combine(AdminUri.Base(server), AdminUri.Path("/realms/{0}/protocol/openid-connect/token", [authenticationRealm]), []);
    private readonly string clientId = ValidateClientId(clientId);
    private readonly Func<CancellationToken, ValueTask<string>> secret = secret ?? throw new ArgumentNullException(nameof(secret));
    private readonly TimeProvider clock = clock ?? TimeProvider.System;
    private readonly object gate = new();
    private readonly TimeSpan requestTimeout = ValidateOptions(options).RequestTimeout;
    private readonly TimeSpan failureCooldown = options.FailureCooldown;
    private Task<string>? pending;
    private DateTimeOffset retryAt;
    private bool disposed;
    private string? cached;
    private DateTimeOffset refreshAt;

    public ClientCredentialsTokenProvider(HttpClient client, Uri server, string authenticationRealm, string clientId,
        Func<CancellationToken, ValueTask<string>> secret, TimeProvider? clock = null)
        : this(client, server, authenticationRealm, clientId, secret, clock, new ClientCredentialsTokenProviderOptions()) { }

    private static string ValidateClientId(string clientId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);
        return clientId;
    }

    private static ClientCredentialsTokenProviderOptions ValidateOptions(ClientCredentialsTokenProviderOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (options.RequestTimeout <= TimeSpan.Zero || options.RequestTimeout.TotalMilliseconds > uint.MaxValue - 1)
            throw new ArgumentOutOfRangeException(nameof(options), "RequestTimeout must be positive and supported by a timer.");
        if (options.FailureCooldown < TimeSpan.Zero || options.FailureCooldown.TotalMilliseconds > uint.MaxValue - 1)
            throw new ArgumentOutOfRangeException(nameof(options), "FailureCooldown must be nonnegative and supported by a timer.");
        return options;
    }

    public ValueTask<string> GetAccessTokenAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        TaskCompletionSource<string>? acquisition = null;
        Task<string> task;
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            if (cached is not null && clock.GetUtcNow() < refreshAt) return ValueTask.FromResult(cached);
            if (pending is null || (pending.IsCompleted && clock.GetUtcNow() >= retryAt))
            {
                acquisition = new(TaskCreationOptions.RunContinuationsAsynchronously);
                pending = acquisition.Task;
            }
            task = pending;
        }
        if (acquisition is not null) _ = AcquireAsync(acquisition);
        // A cancelled waiter cannot cancel acquisition for other callers.
        return new ValueTask<string>(task.WaitAsync(cancellationToken));
    }

    public ValueTask InvalidateAsync(string rejectedToken, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            if (string.Equals(cached, rejectedToken, StringComparison.Ordinal)) cached = null;
        }
        return ValueTask.CompletedTask;
    }

    private async Task AcquireAsync(TaskCompletionSource<string> acquisition)
    {
        try
        {
            using var timeout = new CancellationTokenSource(requestTimeout, clock);
            var cancellationToken = timeout.Token;
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
            if (!response.IsSuccessStatusCode) throw new KeycloakAdminException(response.StatusCode, "TOKEN POST", KeycloakFailureStage.TokenEndpoint, null);
            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            var token = await JsonSerializer.DeserializeAsync(stream, KeycloakJsonContext.Default.TokenResponse, cancellationToken).ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(token?.AccessToken) || token.ExpiresIn <= 0 || !string.Equals(token.TokenType, "Bearer", StringComparison.OrdinalIgnoreCase))
                throw new KeycloakResponseFormatException(response.StatusCode, new JsonException("Invalid token contract."));
            // Bound untrusted lifetimes before converting to a TimeSpan.
            double seconds = Math.Min(token.ExpiresIn, 86400);
            lock (gate)
            {
                refreshAt = started.AddSeconds(seconds - Math.Min(30, seconds / 10));
                cached = token.AccessToken;
                pending = null;
                acquisition.SetResult(cached);
            }
        }
        catch (Exception error)
        {
            lock (gate)
            {
                // Hold the same failed result briefly, including for late arrivals in a 401 wave.
                retryAt = clock.GetUtcNow().Add(failureCooldown);
                acquisition.SetException(error);
                _ = acquisition.Task.Exception; // Observe even when every waiter has cancelled.
            }
        }
    }

    public void Dispose()
    {
        lock (gate) { disposed = true; cached = null; pending = null; }
    }
}
