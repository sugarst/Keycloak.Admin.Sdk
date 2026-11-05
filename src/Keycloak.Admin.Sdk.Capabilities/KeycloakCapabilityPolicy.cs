namespace Keycloak.Admin.Sdk.Capabilities;

/// <summary>All gates are conjunctive. Unknown version, endpoint or required server feature denies locally.
/// A policy is bound to a server, one FGAP route and one immutable host configuration.</summary>
public sealed class KeycloakCapabilityPolicy : IKeycloakAdminRequestPolicy
{
    private readonly Uri server;
    private readonly KeycloakSupportConfiguration configuration;
    private readonly KeycloakServerCapabilities actual;
    private readonly KeycloakReleaseCapabilities? release;
    public KeycloakCapabilityPolicy(Uri server, KeycloakSupportConfiguration configuration, KeycloakServerCapabilities actual)
    {
        ArgumentNullException.ThrowIfNull(server);
        if (!server.IsAbsoluteUri || server.Scheme is not ("http" or "https") || server.Query.Length != 0 || server.Fragment.Length != 0 || server.UserInfo.Length != 0) throw new ArgumentException("Invalid server URI.", nameof(server));
        this.server = new Uri(server.AbsoluteUri.TrimEnd('/') + "/");
        this.configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        this.actual = actual ?? throw new ArgumentNullException(nameof(actual));
        release = KeycloakCapabilityCatalog.Find(configuration.ServerVersion);
        if (release is not null && configuration.DisabledCapabilities.Any(id => !release.Endpoints.Any(e => e.FeatureId == id))) throw new ArgumentException("Unknown disabled capability ID.", nameof(configuration));
    }

    public KeycloakCapabilityDecision Evaluate(HttpMethod method, Uri target, string? operation = null)
    {
        ArgumentNullException.ThrowIfNull(method); ArgumentNullException.ThrowIfNull(target);
        KeycloakCapabilityDecision Result(KeycloakCapabilityReason reason, KeycloakEndpointCapability? capability = null) => new(reason, configuration.ServerVersion, configuration.Route, capability);
        if (release is null) return Result(KeycloakCapabilityReason.UnknownVersion);
        if (actual.ServerVersion != release.ServerVersion) return Result(KeycloakCapabilityReason.VersionMismatch);
        if (!target.IsAbsoluteUri || target.GetLeftPart(UriPartial.Authority) != server.GetLeftPart(UriPartial.Authority) || !target.AbsolutePath.StartsWith(server.AbsolutePath, StringComparison.Ordinal)) return Result(KeycloakCapabilityReason.WrongServer);
        string path = "/" + target.AbsolutePath[server.AbsolutePath.Length..].TrimEnd('/');
        KeycloakEndpointCapability? endpoint;
        if (operation is not null)
        {
            endpoint = release.Endpoints.SingleOrDefault(e => e.Operation == operation);
            if (endpoint is null) return Result(KeycloakCapabilityReason.UnknownEndpoint);
            if (endpoint.Method != method.Method || !Matches(endpoint.Path, path)) return Result(KeycloakCapabilityReason.EndpointMismatch, endpoint);
        }
        else endpoint = release.Endpoints.Where(e => e.Method == method.Method && Matches(e.Path, path)).OrderByDescending(e => LiteralCount(e.Path)).FirstOrDefault();
        if (endpoint is null) return Result(KeycloakCapabilityReason.UnknownEndpoint);
        string desired = configuration.Route == KeycloakAdminRoute.FgapV2Stable ? "ADMIN_FINE_GRAINED_AUTHZ_V2" : "ADMIN_FINE_GRAINED_AUTHZ";
        string opposite = configuration.Route == KeycloakAdminRoute.FgapV2Stable ? "ADMIN_FINE_GRAINED_AUTHZ" : "ADMIN_FINE_GRAINED_AUTHZ_V2";
        if (!actual.Features.TryGetValue(desired, out bool selected) || !actual.Features.TryGetValue(opposite, out bool other)) return Result(KeycloakCapabilityReason.RouteUnavailable, endpoint);
        if (!selected || other) return Result(KeycloakCapabilityReason.RouteMismatch, endpoint);
        return EvaluateEndpoint(endpoint);
    }

    internal KeycloakCapabilityDecision EvaluateEndpoint(KeycloakEndpointCapability endpoint)
    {
        KeycloakCapabilityReason reason;
        if ((endpoint.Stage == KeycloakFeatureStage.Preview && !configuration.AllowPreview) || (endpoint.Stage == KeycloakFeatureStage.Experimental && !configuration.AllowExperimental) || endpoint.Stage == KeycloakFeatureStage.Removed) reason = KeycloakCapabilityReason.StageNotAllowed;
        else if (endpoint.Support == KeycloakSupportStatus.NotSupported) reason = KeycloakCapabilityReason.NotSupported;
        else if (!endpoint.Routes.Contains(configuration.Route)) reason = KeycloakCapabilityReason.RouteUnavailable;
        else if (endpoint.Implementation != KeycloakImplementationStatus.Implemented) reason = KeycloakCapabilityReason.NotImplemented;
        else if (endpoint.Verification != (KeycloakVerification.Contract | KeycloakVerification.Managed | KeycloakVerification.NativeAot)) reason = KeycloakCapabilityReason.InsufficientVerification;
        else if (configuration.DisabledCapabilities.Contains("KeycloakSdk.AdminApi") || configuration.DisabledCapabilities.Contains(endpoint.FeatureId)) reason = KeycloakCapabilityReason.DisabledByHost;
        else
        {
            reason = KeycloakCapabilityReason.Allowed;
            foreach (string feature in endpoint.RequiredServerFeatures)
            {
                if (!actual.Features.TryGetValue(feature, out bool enabled)) { reason = KeycloakCapabilityReason.ServerFeatureUnknown; break; }
                if (!enabled) { reason = KeycloakCapabilityReason.ServerFeatureDisabled; break; }
            }
        }
        return new(reason, configuration.ServerVersion, configuration.Route, endpoint);
    }

    public ValueTask EnsureAllowedAsync(HttpMethod method, Uri target, string? operation, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var decision = Evaluate(method, target, operation);
        if (!decision.IsAllowed) throw new KeycloakCapabilityDeniedException(decision);
        return ValueTask.CompletedTask;
    }
    private static int LiteralCount(string path) => path.Split('/').Where(p => !p.StartsWith('{')).Sum(p => p.Length);
    private static bool Matches(string template, string path)
    {
        var expected = template.TrimEnd('/').Split('/'); var actualPath = path.Split('/');
        if (expected.Length != actualPath.Length) return false;
        for (int i = 0; i < expected.Length; i++)
        {
            if (expected[i].StartsWith('{')) { if (actualPath[i].Length == 0) return false; }
            else if (expected[i] != actualPath[i]) return false;
        }
        return true;
    }
}
