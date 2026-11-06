namespace Keycloak.Admin.Sdk.Capabilities;

public enum KeycloakFeatureStage { Stable, Preview, Experimental, Deprecated, Removed }
public enum KeycloakImplementationStatus { NotImplemented, Implemented }
public enum KeycloakSupportStatus { NotSupported, Supported, Compatibility }
[Flags]
public enum KeycloakVerification { None = 0, Contract = 1, Managed = 2, NativeAot = 4 }
public enum KeycloakAdminRoute { FgapV2Stable, FgapV1Compatibility }
public enum KeycloakRuntimeProfile { Portable, Managed, NativeAot }
public enum KeycloakCapabilityReason
{
    Allowed, UnknownVersion, VersionMismatch, UnknownEndpoint, EndpointMismatch, WrongServer,
    RouteUnavailable, RouteMismatch, StageNotAllowed, NotSupported, NotImplemented,
    InsufficientVerification, ServerFeatureUnknown, ServerFeatureDisabled, DisabledByHost, RuntimeMismatch
}

/// <summary>A recorded verification run for one route, runtime and (for Native AOT) RID.</summary>
public sealed class KeycloakVerificationProfile
{
    public string Id { get; }
    public KeycloakAdminRoute Route { get; }
    public KeycloakRuntimeProfile Runtime { get; }
    public string? RuntimeIdentifier { get; }
    public KeycloakVerification Verification { get; }
    public string SourceFingerprint { get; }
    public string Evidence { get; }
    public string EvidenceSha256 { get; }
    internal KeycloakVerificationProfile(string id, KeycloakAdminRoute route, KeycloakRuntimeProfile runtime,
        string? runtimeIdentifier, KeycloakVerification verification, string sourceFingerprint, string evidence, string evidenceSha256)
    {
        Id = id; Route = route; Runtime = runtime; RuntimeIdentifier = runtimeIdentifier; Verification = verification;
        SourceFingerprint = sourceFingerprint; Evidence = evidence; EvidenceSha256 = evidenceSha256;
    }
}

public sealed class KeycloakEndpointCapability
{
    public string Operation { get; }
    public string Method { get; }
    public string Path { get; }
    public string FeatureId { get; }
    public KeycloakFeatureStage Stage { get; }
    public KeycloakImplementationStatus Implementation { get; }
    public KeycloakSupportStatus Support { get; }
    public KeycloakVerification Verification { get; }
    public IReadOnlyList<string> RequiredServerFeatures { get; }
    public IReadOnlyList<KeycloakAdminRoute> Routes { get; }
    public string Evidence { get; }
    public IReadOnlyList<KeycloakVerificationProfile> SupportProfiles { get; }
    internal KeycloakEndpointCapability(string operation, string method, string path, string featureId, KeycloakFeatureStage stage,
        KeycloakImplementationStatus implementation, KeycloakSupportStatus support, KeycloakVerification verification, string[] features, string evidence, KeycloakAdminRoute[] routes,
        KeycloakVerificationProfile[]? supportProfiles = null)
    {
        Operation = operation; Method = method; Path = path; FeatureId = featureId; Stage = stage;
        Implementation = implementation; Support = support; Verification = verification;
        RequiredServerFeatures = Array.AsReadOnly(features); Evidence = evidence;
        Routes = Array.AsReadOnly(routes);
        SupportProfiles = Array.AsReadOnly(supportProfiles ?? []);
    }
}

public sealed class KeycloakReleaseCapabilities
{
    public string ServerVersion { get; }
    public string SourceCommit { get; }
    public IReadOnlyList<KeycloakEndpointCapability> Endpoints { get; }
    public IReadOnlyList<KeycloakVerificationProfile> VerificationProfiles { get; }
    public int SchemaVersion { get; }
    internal KeycloakReleaseCapabilities(string version, string commit, KeycloakEndpointCapability[] endpoints,
        KeycloakVerificationProfile[]? verificationProfiles = null, int schemaVersion = 1)
    {
        ServerVersion = version; SourceCommit = commit; Endpoints = Array.AsReadOnly(endpoints);
        VerificationProfiles = Array.AsReadOnly(verificationProfiles ?? []); SchemaVersion = schemaVersion;
    }
}

public sealed class KeycloakCapabilityDecision
{
    public bool IsAllowed => Reason == KeycloakCapabilityReason.Allowed;
    public KeycloakCapabilityReason Reason { get; }
    public string ServerVersion { get; }
    public KeycloakAdminRoute Route { get; }
    public KeycloakEndpointCapability? Capability { get; }
    internal KeycloakCapabilityDecision(KeycloakCapabilityReason reason, string version, KeycloakAdminRoute route, KeycloakEndpointCapability? capability)
    { Reason = reason; ServerVersion = version; Route = route; Capability = capability; }

    /// <summary>Host adapters may restrict an allowed decision, but cannot override a catalog denial.</summary>
    public KeycloakCapabilityDecision DisableByHost() => IsAllowed
        ? new(KeycloakCapabilityReason.DisabledByHost, ServerVersion, Route, Capability) : this;
}

public sealed class KeycloakCapabilityDeniedException(KeycloakCapabilityDecision decision)
    : InvalidOperationException("Keycloak support policy denied request: " + decision.Reason)
{
    public KeycloakCapabilityDecision Decision { get; } = decision;
}
