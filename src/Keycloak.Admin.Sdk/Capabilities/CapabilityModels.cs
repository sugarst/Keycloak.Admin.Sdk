namespace Keycloak.Admin.Sdk.Capabilities;

public enum KeycloakFeatureStage { Stable, Preview, Experimental, Deprecated, Removed }
public enum KeycloakImplementationStatus { NotImplemented, Implemented }
public enum KeycloakSupportStatus { NotSupported, Supported, Compatibility }
[Flags]
public enum KeycloakVerification { None = 0, Contract = 1, Managed = 2, NativeAot = 4 }
public enum KeycloakAdminRoute { FgapV2Stable, FgapV1Compatibility }
public enum KeycloakCapabilityReason
{
    Allowed, UnknownVersion, VersionMismatch, UnknownEndpoint, EndpointMismatch, WrongServer,
    RouteUnavailable, RouteMismatch, StageNotAllowed, NotSupported, NotImplemented,
    InsufficientVerification, ServerFeatureUnknown, ServerFeatureDisabled, DisabledByHost
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
    internal KeycloakEndpointCapability(string operation, string method, string path, string featureId, KeycloakFeatureStage stage,
        KeycloakImplementationStatus implementation, KeycloakSupportStatus support, KeycloakVerification verification, string[] features, string evidence, KeycloakAdminRoute[] routes)
    {
        Operation = operation; Method = method; Path = path; FeatureId = featureId; Stage = stage;
        Implementation = implementation; Support = support; Verification = verification;
        RequiredServerFeatures = Array.AsReadOnly(features); Evidence = evidence;
        Routes = Array.AsReadOnly(routes);
    }
}

public sealed class KeycloakReleaseCapabilities
{
    public string ServerVersion { get; }
    public string SourceCommit { get; }
    public IReadOnlyList<KeycloakEndpointCapability> Endpoints { get; }
    internal KeycloakReleaseCapabilities(string version, string commit, KeycloakEndpointCapability[] endpoints)
    { ServerVersion = version; SourceCommit = commit; Endpoints = Array.AsReadOnly(endpoints); }
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
