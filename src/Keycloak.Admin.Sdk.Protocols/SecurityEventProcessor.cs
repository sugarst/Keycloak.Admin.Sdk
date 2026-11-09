using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace Keycloak.Admin.Sdk.Protocols;

/// <summary>The host must atomically persist its business effect and an issuer/audience-scoped deduplication receipt.
/// A duplicate must complete successfully without repeating the effect. Throw on storage failure so delivery can retry.
/// Retain receipts until at least RetainUntil. Use a durable shared transaction/store in multi-process receivers.</summary>
public interface ISecurityEventInbox
{
    ValueTask ApplyOnceAsync(SecurityEventDelivery delivery, CancellationToken cancellationToken);
}

/// <summary>A verified delivery. ReceiptKey includes the pinned issuer and audience; tokens and arbitrary user-supplied IDs never become storage paths.</summary>
public sealed class SecurityEventDelivery
{
    public VerifiedSecurityEventToken Token { get; }
    public string ReceiptKey { get; }
    public DateTimeOffset RetainUntil { get; }
    internal SecurityEventDelivery(VerifiedSecurityEventToken token, string key, DateTimeOffset retainUntil)
    { Token = token; ReceiptKey = key; RetainUntil = retainUntil; }
}

/// <summary>Shared SSF push/poll processing: verify first, atomically apply and deduplicate second, acknowledge only after completion.
/// Business handlers own subject-namespace mapping and CAEP/RISC effects; a signed event never grants authority over unrelated local accounts.</summary>
public sealed class SecurityEventProcessor
{
    private readonly ProtocolTransport transport;
    private readonly SecurityEventTokenValidator validator;
    private readonly ISecurityEventInbox inbox;
    private readonly string audience;
    private readonly TimeProvider clock;
    private readonly TimeSpan maximumAge;
    public SecurityEventProcessor(ProtocolTransport transport, string audience, IEnumerable<string> allowedEventTypes, ISecurityEventInbox inbox,
        TimeSpan? maximumAge = null, TimeProvider? clock = null, IEnumerable<string>? allowedAlgorithms = null)
    {
        this.transport = transport ?? throw new ArgumentNullException(nameof(transport)); this.inbox = inbox ?? throw new ArgumentNullException(nameof(inbox));
        this.audience = audience; this.clock = clock ?? TimeProvider.System; this.maximumAge = maximumAge ?? TimeSpan.FromMinutes(5);
        // No receipt is reserved here: failure before the host transaction commits must allow a later delivery to succeed.
        validator = new(new OidcClient(transport), audience, allowedEventTypes, new DeferredReplayStore(), this.maximumAge, this.clock, allowedAlgorithms);
    }

    /// <summary>For push, return HTTP success only after this task completes. Transport errors/storage failures must remain retryable.
    /// expectedId binds a poll response map key to the signed jti before invoking the inbox.</summary>
    public async Task<VerifiedSecurityEventToken> ProcessAsync(string credential, string? expectedId = null, CancellationToken cancellationToken = default)
    {
        await transport.EnsureEnabledAsync("KeycloakSdk.Protocols.Signals", cancellationToken).ConfigureAwait(false);
        var verified = await validator.ValidateAsync(credential, cancellationToken).ConfigureAwait(false);
        if (expectedId is not null && expectedId != verified.Id) throw new InvalidDataException("SSF poll identifier differs from the signed event identifier.");
        string key = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.UTF8.GetBytes("ssf-inbox\n" + transport.Issuer.AbsoluteUri + "\n" + audience + "\n" + verified.Id)));
        cancellationToken.ThrowIfCancellationRequested();
        await transport.EnsureEnabledAsync("KeycloakSdk.Protocols.Signals", cancellationToken).ConfigureAwait(false);
        await inbox.ApplyOnceAsync(new(verified, key, clock.GetUtcNow().Add(maximumAge).AddSeconds(30)), cancellationToken).ConfigureAwait(false);
        return verified;
    }

    /// <summary>Returns acknowledgements only when every SET was verified and durably processed. On failure, retry the unacknowledged batch.
    /// Feed these IDs into the next poll's ack field and process that poll's new SETs as well.</summary>
    public async Task<IReadOnlyList<string>> ProcessPollResponseAsync(ProtocolResponse response, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(response);
        var body = response.Json;
        if (body is not { ValueKind: JsonValueKind.Object } json || !json.TryGetProperty("sets", out var sets) || sets.ValueKind != JsonValueKind.Object)
            throw new InvalidDataException("An SSF poll response with a SET map is required.");
        var entries = sets.EnumerateObject().ToArray();
        if (entries.Length > 1000 || entries.Any(e => e.Value.ValueKind != JsonValueKind.String) || entries.Select(e => e.Name).Distinct(StringComparer.Ordinal).Count() != entries.Length)
            throw new InvalidDataException("Invalid or oversized SSF poll SET map.");
        var acknowledged = new List<string>(entries.Length);
        foreach (var entry in entries)
        {
            await ProcessAsync(entry.Value.GetString()!, entry.Name, cancellationToken).ConfigureAwait(false);
            acknowledged.Add(entry.Name);
        }
        return acknowledged.AsReadOnly();
    }
    private sealed class DeferredReplayStore : ISecurityTokenReplayStore
    {
        public ValueTask<bool> TryUseAsync(string key, DateTimeOffset expiresAt, CancellationToken cancellationToken)
        { cancellationToken.ThrowIfCancellationRequested(); return ValueTask.FromResult(true); }
    }
}
