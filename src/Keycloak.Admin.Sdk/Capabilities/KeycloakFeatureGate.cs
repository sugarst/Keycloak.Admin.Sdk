using System.Collections.Frozen;

namespace Keycloak.Admin.Sdk.Capabilities;

/// <summary>A host gate may only restrict requests already allowed by the immutable capability policy.</summary>
public interface IKeycloakFeatureGate
{
    ValueTask<bool> IsEnabledAsync(string featureId, CancellationToken cancellationToken = default);
}

/// <summary>AOT-safe flags. Replace validates and atomically swaps a complete immutable snapshot. Missing flags are false.</summary>
public sealed class KeycloakFeatureSnapshotGate : IKeycloakFeatureGate
{
    private FrozenDictionary<string, bool> snapshot;
    public KeycloakFeatureSnapshotGate(IEnumerable<KeyValuePair<string, bool>> flags) => snapshot = Freeze(flags);
    public void Replace(IEnumerable<KeyValuePair<string, bool>> flags) => Interlocked.Exchange(ref snapshot, Freeze(flags));
    private static FrozenDictionary<string, bool> Freeze(IEnumerable<KeyValuePair<string, bool>> flags)
    {
        ArgumentNullException.ThrowIfNull(flags);
        var entries = new Dictionary<string, bool>(StringComparer.Ordinal);
        foreach (var (id, enabled) in flags)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(id);
            entries.Add(id, enabled);
        }
        return entries.ToFrozenDictionary(StringComparer.Ordinal);
    }
    public ValueTask<bool> IsEnabledAsync(string featureId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentException.ThrowIfNullOrWhiteSpace(featureId);
        return ValueTask.FromResult(Volatile.Read(ref snapshot).GetValueOrDefault(featureId));
    }
    internal FrozenDictionary<string, bool> Capture() => Volatile.Read(ref snapshot);
}

/// <summary>Checks capabilities, then the master flag and endpoint flag once per logical request.</summary>
public sealed class KeycloakFeatureGatePolicy : IKeycloakAdminRequestPolicy
{
    public const string AdminApiFeature = "KeycloakSdk.AdminApi";
    private readonly KeycloakCapabilityPolicy capabilities;
    private readonly IKeycloakFeatureGate gate;
    public KeycloakFeatureGatePolicy(KeycloakCapabilityPolicy capabilities, IKeycloakFeatureGate gate)
    {
        this.capabilities = capabilities ?? throw new ArgumentNullException(nameof(capabilities));
        this.gate = gate ?? throw new ArgumentNullException(nameof(gate));
    }
    public async ValueTask<KeycloakCapabilityDecision> EvaluateAsync(HttpMethod method, Uri target, string? operation = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var decision = capabilities.Evaluate(method, target, operation);
        if (!decision.IsAllowed) return decision;
        // Keep both flag reads on one generation when the lightweight snapshot is replaced concurrently.
        var snapshot = (gate as KeycloakFeatureSnapshotGate)?.Capture();
        async ValueTask<bool> Enabled(string id)
        {
            cancellationToken.ThrowIfCancellationRequested();
            bool enabled = snapshot is not null ? snapshot.GetValueOrDefault(id) : await gate.IsEnabledAsync(id, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            return enabled;
        }
        if (!await Enabled(AdminApiFeature).ConfigureAwait(false)) return decision.DisableByHost();
        string feature = decision.Capability!.FeatureId;
        if (feature != AdminApiFeature && !await Enabled(feature).ConfigureAwait(false)) return decision.DisableByHost();
        return decision;
    }
    public async ValueTask EnsureAllowedAsync(HttpMethod method, Uri target, string? operation, CancellationToken cancellationToken)
    {
        var decision = await EvaluateAsync(method, target, operation, cancellationToken).ConfigureAwait(false);
        if (!decision.IsAllowed) throw new KeycloakCapabilityDeniedException(decision);
    }
}
