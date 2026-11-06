using System.Globalization;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Keycloak.Admin.Sdk.Protocols;

/// <summary>Pinned 26.8.1 CIBA request options. The server supports poll/ping; push delivery and user_code are not available upstream.</summary>
public sealed class CibaAuthenticationRequest
{
    public string? LoginHint { get; init; }
    public string? IdTokenHint { get; init; }
    public string? LoginHintToken { get; init; }
    public string? BindingMessage { get; init; }
    public string? AcrValues { get; init; }
    public string? ClientNotificationToken { get; init; }
    public int? RequestedExpirySeconds { get; init; }
    public string? SignedRequest { get; init; }
    internal Dictionary<string, string> Form()
    {
        var hints = new[] { LoginHint, IdTokenHint, LoginHintToken };
        if (SignedRequest is not null)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(SignedRequest);
            if (hints.Any(h => h is not null) || BindingMessage is not null || AcrValues is not null || ClientNotificationToken is not null || RequestedExpirySeconds is not null)
                throw new ArgumentException("A signed CIBA request must contain its own parameters.");
            return new() { ["request"] = SignedRequest };
        }
        if (hints.Count(h => h is not null) != 1) throw new ArgumentException("Select exactly one CIBA user hint.");
        var form = new Dictionary<string, string>();
        foreach (var pair in new KeyValuePair<string, string?>[] { new("login_hint", LoginHint), new("id_token_hint", IdTokenHint), new("login_hint_token", LoginHintToken),
            new("binding_message", BindingMessage), new("acr_values", AcrValues), new("client_notification_token", ClientNotificationToken) })
            if (pair.Value is not null) { ArgumentException.ThrowIfNullOrWhiteSpace(pair.Value); form.Add(pair.Key, pair.Value); }
        if (RequestedExpirySeconds is not null)
        {
            if (RequestedExpirySeconds is <= 0 or > 86400) throw new ArgumentOutOfRangeException(nameof(RequestedExpirySeconds));
            form.Add("requested_expiry", RequestedExpirySeconds.Value.ToString(CultureInfo.InvariantCulture));
        }
        return form;
    }
}

public enum CibaAuthenticationResult { Approved, Denied, Cancelled }
public sealed partial class OidcClient
{
    public Task<ProtocolResponse> RequestBackchannelAuthenticationAsync(OAuthClientAuthentication client, CibaAuthenticationRequest request, string? scope = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.SignedRequest is not null && scope is not null) throw new ArgumentException("Scope belongs inside a signed CIBA request.", nameof(scope));
        return FormAsync(client, "protocol/openid-connect/ext/ciba/auth", request.Form(), scope, "Oidc.Ciba", cancellationToken);
    }
    /// <summary>Authentication-device callback. Call only after independently authenticating the user and obtaining consent on the trusted device.
    /// Use the authentication-channel bearer credential, never an administrator token or auth_req_id.</summary>
    public Task<ProtocolResponse> CompleteBackchannelAuthenticationAsync(string authenticationChannelCredential, CibaAuthenticationResult result, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(authenticationChannelCredential);
        string status = result switch { CibaAuthenticationResult.Approved => "SUCCEED", CibaAuthenticationResult.Denied => "UNAUTHORIZED", CibaAuthenticationResult.Cancelled => "CANCELLED", _ => throw new ArgumentOutOfRangeException(nameof(result)) };
        var body = new JsonObject { ["status"] = status };
        return transport.SendAsync(HttpMethod.Post, "protocol/openid-connect/ext/ciba/auth/callback", "Oidc.CibaCallback", "KeycloakSdk.Protocols.OidcCiba",
            new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json"), authenticationChannelCredential, null, null, cancellationToken);
    }
}

/// <summary>Authenticates CIBA ping notifications and binds them to one request, expiry and atomic replay store.
/// Notifications contain no user credentials; after a valid ping, redeem the original request using its client authentication.</summary>
public sealed class CibaPingNotificationValidator
{
    public static string CreateNotificationToken() => Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
    private readonly ProtocolTransport transport;
    private readonly OAuthPollingLease lease;
    private readonly string secret;
    private readonly ISecurityTokenReplayStore replay;
    private readonly TimeProvider clock;
    public CibaPingNotificationValidator(ProtocolTransport transport, OAuthPollingLease lease, string clientNotificationToken, ISecurityTokenReplayStore replayStore, TimeProvider? clock = null)
    {
        this.transport = transport ?? throw new ArgumentNullException(nameof(transport)); this.lease = lease ?? throw new ArgumentNullException(nameof(lease));
        ArgumentNullException.ThrowIfNull(clientNotificationToken);
        if (clientNotificationToken.Length is < 22 or > 1024 || clientNotificationToken.Any(c => c is < '!' or > '~')) throw new ArgumentException("Use a bounded, cryptographically random notification secret.", nameof(clientNotificationToken));
        secret = clientNotificationToken; replay = replayStore ?? throw new ArgumentNullException(nameof(replayStore)); this.clock = clock ?? TimeProvider.System;
    }
    public async Task ValidateAsync(string authorization, JsonElement notification, CancellationToken cancellationToken = default)
    {
        await transport.EnsureEnabledAsync("KeycloakSdk.Protocols.OidcCiba", cancellationToken).ConfigureAwait(false);
        if (clock.GetUtcNow() >= lease.ExpiresAt || !AuthenticationHeaderValue.TryParse(authorization, out var header) || !header.Scheme.Equals("Bearer", StringComparison.OrdinalIgnoreCase)
            || header.Parameter is null || !OidcLoginTransaction.FixedEquals(secret, header.Parameter)
            || notification.ValueKind != JsonValueKind.Object || !notification.TryGetProperty("auth_req_id", out var id) || id.ValueKind != JsonValueKind.String
            || !OidcLoginTransaction.FixedEquals(lease.Identifier, id.GetString()!) || notification.EnumerateObject().GroupBy(p => p.Name, StringComparer.Ordinal).Any(g => g.Count() != 1))
            throw new InvalidDataException("Invalid or expired CIBA ping notification.");
        string key = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes("ciba-ping\n" + transport.Issuer.AbsoluteUri + "\n" + lease.Identifier + "\n" + secret)));
        if (!await replay.TryUseAsync(key, lease.ExpiresAt, cancellationToken).ConfigureAwait(false)) throw new InvalidDataException("Replayed CIBA ping notification.");
    }
}
