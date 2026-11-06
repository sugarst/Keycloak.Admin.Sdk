using System.Net;
using System.Text.Json;

namespace Keycloak.Admin.Sdk.Protocols;

/// <summary>A device/CIBA polling lease. Treat Identifier as a credential and keep it in the user's server-side session.</summary>
public sealed class OAuthPollingLease
{
    public string Identifier { get; }
    public DateTimeOffset ExpiresAt { get; }
    public TimeSpan Interval { get; }
    private OAuthPollingLease(string identifier, DateTimeOffset expiresAt, TimeSpan interval)
    { Identifier = identifier; ExpiresAt = expiresAt; Interval = interval; }

    public static OAuthPollingLease FromDeviceResponse(ProtocolResponse response, TimeProvider? clock = null)
        => Parse(response, "device_code", clock ?? TimeProvider.System);
    /// <summary>Optionally cap the returned lifetime to the caller's requested_expiry; 26.8.1 may return a longer realm-policy lifetime.</summary>
    public static OAuthPollingLease FromCibaResponse(ProtocolResponse response, TimeProvider? clock = null, TimeSpan? maximumLifetime = null)
        => Parse(response, "auth_req_id", clock ?? TimeProvider.System, maximumLifetime);
    private static OAuthPollingLease Parse(ProtocolResponse response, string property, TimeProvider clock, TimeSpan? maximumLifetime = null)
    {
        JsonElement json = response.Json ?? throw new InvalidDataException("Polling response is empty.");
        string? id = json.GetProperty(property).GetString();
        int expires = json.GetProperty("expires_in").GetInt32();
        int interval = json.TryGetProperty("interval", out var value) ? value.GetInt32() : 5;
        if (string.IsNullOrWhiteSpace(id) || expires is <= 0 or > 86400 || interval is <= 0 or > 86400)
            throw new InvalidDataException("Invalid polling lease.");
        if (maximumLifetime is { } maximum && (maximum <= TimeSpan.Zero || maximum > TimeSpan.FromDays(1))) throw new ArgumentOutOfRangeException(nameof(maximumLifetime));
        var lifetime = TimeSpan.FromSeconds(expires);
        if (maximumLifetime is { } limit && limit < lifetime) lifetime = limit;
        return new(id, clock.GetUtcNow().Add(lifetime), TimeSpan.FromSeconds(interval));
    }
}

public sealed partial class OidcClient
{
    /// <summary>RFC 8628 polling. Pending waits, slow_down adds five seconds permanently; denial and network errors stop polling.</summary>
    public Task<ProtocolResponse> PollDeviceAsync(OAuthClientAuthentication client, OAuthPollingLease lease,
        TimeProvider? clock = null, CancellationToken cancellationToken = default)
        => PollAsync(lease, token => RedeemDeviceCodeAsync(client, lease.Identifier, token), clock ?? TimeProvider.System, cancellationToken);

    /// <summary>CIBA poll mode. Ping notifications use CibaPingNotificationValidator before redemption. Keycloak 26.8.1 does not support push mode.</summary>
    public Task<ProtocolResponse> PollBackchannelAsync(OAuthClientAuthentication client, OAuthPollingLease lease,
        TimeProvider? clock = null, CancellationToken cancellationToken = default)
        => PollAsync(lease, token => RedeemBackchannelAuthenticationAsync(client, lease.Identifier, token), clock ?? TimeProvider.System, cancellationToken);

    private static async Task<ProtocolResponse> PollAsync(OAuthPollingLease lease, Func<CancellationToken, Task<ProtocolResponse>> redeem, TimeProvider clock, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(lease);
        TimeSpan interval = lease.Interval;
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            TimeSpan remaining = lease.ExpiresAt - clock.GetUtcNow();
            if (remaining <= interval) throw new KeycloakProtocolException(HttpStatusCode.BadRequest, "Oidc.Poll", OAuthError.ExpiredToken);
            await Task.Delay(interval, clock, ct).ConfigureAwait(false);
            // A delayed scheduler must never send an expired credential.
            if (clock.GetUtcNow() >= lease.ExpiresAt) throw new KeycloakProtocolException(HttpStatusCode.BadRequest, "Oidc.Poll", OAuthError.ExpiredToken);
            try { return await redeem(ct).ConfigureAwait(false); }
            catch (KeycloakProtocolException e) when (e.StatusCode == HttpStatusCode.BadRequest && e.Error == OAuthError.AuthorizationPending) { }
            catch (KeycloakProtocolException e) when (e.StatusCode == HttpStatusCode.BadRequest && e.Error == OAuthError.SlowDown)
            { interval += TimeSpan.FromSeconds(5); }
        }
    }
}
