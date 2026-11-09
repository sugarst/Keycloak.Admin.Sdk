using System.Security.Cryptography;
using System.Text;

namespace Keycloak.Admin.Sdk.Hosting;

/// <summary>Cluster implementations must atomically persist logout markers before acknowledging a notification.
/// Issuer and session/subject namespaces must remain separate. Store failures must fail authentication closed.</summary>
public interface IKeycloakLogoutStore
{
    ValueTask RevokeAsync(string issuer, string eventId, string? sessionId, string? subject, DateTimeOffset issuedAt, DateTimeOffset retainUntil, CancellationToken cancellationToken);
    ValueTask<bool> IsRevokedAsync(string issuer, string sessionId, string subject, DateTimeOffset authenticatedAt, CancellationToken cancellationToken);
}

/// <summary>Bounded, single-process logout storage for development. Use durable shared storage on multiple instances.
/// A repeated verified event is idempotent; revocation and event receipt are committed under one lock.</summary>
public sealed class InMemoryKeycloakLogoutStore(int capacity = 10000, TimeProvider? clock = null) : IKeycloakLogoutStore
{
    private readonly int capacity = capacity > 0 ? capacity : throw new ArgumentOutOfRangeException(nameof(capacity));
    private readonly TimeProvider clock = clock ?? TimeProvider.System;
    private readonly object sync = new();
    private readonly Dictionary<string, (DateTimeOffset IssuedAt, DateTimeOffset RetainUntil)> markers = new(StringComparer.Ordinal);
    private static string Key(string issuer, string kind, string identifier) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(issuer + "\n" + kind + "\n" + identifier)));
    public ValueTask RevokeAsync(string issuer, string eventId, string? sessionId, string? subject, DateTimeOffset issuedAt, DateTimeOffset retainUntil, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested(); ArgumentException.ThrowIfNullOrWhiteSpace(issuer); ArgumentException.ThrowIfNullOrWhiteSpace(eventId);
        if (string.IsNullOrWhiteSpace(sessionId) && string.IsNullOrWhiteSpace(subject)) throw new ArgumentException("A session or subject is required.");
        if (string.IsNullOrWhiteSpace(sessionId)) sessionId = null;
        if (retainUntil <= clock.GetUtcNow()) throw new ArgumentOutOfRangeException(nameof(retainUntil));
        // sid takes precedence; a session logout must not terminate every session owned by sub.
        string marker = Key(issuer, sessionId is null ? "sub" : "sid", sessionId ?? subject!);
        lock (sync)
        {
            Prune();
            if (!markers.ContainsKey(marker) && markers.Count >= capacity) throw new InvalidOperationException("Logout store capacity exhausted.");
            if (markers.TryGetValue(marker, out var previous))
            { issuedAt = previous.IssuedAt > issuedAt ? previous.IssuedAt : issuedAt; retainUntil = previous.RetainUntil > retainUntil ? previous.RetainUntil : retainUntil; }
            markers[marker] = (issuedAt, retainUntil);
        }
        return ValueTask.CompletedTask;
    }
    public ValueTask<bool> IsRevokedAsync(string issuer, string sessionId, string subject, DateTimeOffset authenticatedAt, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (sync)
        {
            Prune();
            return ValueTask.FromResult(markers.ContainsKey(Key(issuer, "sid", sessionId))
                || (markers.TryGetValue(Key(issuer, "sub", subject), out var marker) && authenticatedAt <= marker.IssuedAt));
        }
    }
    private void Prune()
    { foreach (string key in markers.Where(p => p.Value.RetainUntil <= clock.GetUtcNow()).Select(p => p.Key).ToArray()) markers.Remove(key); }
}
