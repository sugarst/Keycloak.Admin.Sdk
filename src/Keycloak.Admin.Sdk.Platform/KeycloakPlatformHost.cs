using Keycloak.Admin.Sdk.Capabilities;
using Keycloak.Admin.Sdk.Protocols;

namespace Keycloak.Admin.Sdk.Platform;

/// <summary>Reads authenticated serverinfo once, then shares one gate and one capability snapshot across both chains.
/// Caller owns HttpClient, token provider and all user/session isolation. Managed host integration.</summary>
public sealed class KeycloakPlatformHost
{
    private readonly Uri server;
    private readonly ApplicationSupportConfiguration? protocolSupport;

    private KeycloakPlatformHost(KeycloakAdminClient admin, KeycloakServerCapabilities serverCapabilities,
        IKeycloakFeatureGate gate, KeycloakFeatureFlagCatalog catalog, Uri server, ApplicationSupportConfiguration? protocolSupport)
    {
        Admin = admin; ServerCapabilities = serverCapabilities; Gate = gate; Catalog = catalog;
        this.server = server; this.protocolSupport = protocolSupport;
    }

    public KeycloakAdminClient Admin { get; }
    public KeycloakServerCapabilities ServerCapabilities { get; }
    public IKeycloakFeatureGate Gate { get; }
    public KeycloakFeatureFlagCatalog Catalog { get; }

    public static async Task<KeycloakPlatformHost> CreateAsync(HttpClient http, Uri server, IAccessTokenProvider tokens,
        KeycloakPlatformOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(server);
        ArgumentNullException.ThrowIfNull(tokens);
        ArgumentNullException.ThrowIfNull(options);
        if (options.Support is null) throw new ArgumentException("Support configuration is required.", nameof(options));
        var catalog = options.Catalog ?? new KeycloakFeatureFlagCatalog();
        if (options.FeatureManager is not null && options.Flags is not null)
            throw new ArgumentException("Choose FeatureManager or Flags, not both.", nameof(options));
        IKeycloakFeatureGate gate;
        if (options.FeatureManager is { } manager)
        {
            var names = new List<KeyValuePair<string, bool>>();
            await foreach (string id in manager.GetFeatureNamesAsync(cancellationToken).ConfigureAwait(false))
                if (catalog.IsKnown(id)) names.Add(new(id, false));
            // Other application flags are allowed; every SDK flag must be explicitly configured.
            catalog.EnsureComplete(names);
            gate = new KeycloakMicrosoftFeatureGate(manager, catalog);
        }
        else
        {
            if (options.Flags is null) throw new ArgumentException("Feature flags are required.", nameof(options));
            gate = KeycloakPlatformGate.Create(options.Flags, catalog);
        }
        var bootstrap = new KeycloakAdminClient(http, server, tokens);
        var info = await bootstrap.ServerInfoAdmin.GetInfoAsync(cancellationToken).ConfigureAwait(false);
        var capabilities = KeycloakServerCapabilities.FromServerInfo(info.Content);
        IKeycloakAdminRequestPolicy policy = new KeycloakFeatureGatePolicy(
            new KeycloakCapabilityPolicy(server, options.Support, capabilities), gate);
        await policy.EnsureAllowedAsync(HttpMethod.Get,
            new Uri(new Uri(server.AbsoluteUri.TrimEnd('/') + "/"), "admin/serverinfo"),
            "ServerInfoAdmin.GetInfoAsync", cancellationToken).ConfigureAwait(false);
        var admin = new KeycloakAdminClient(http, server, tokens, new KeycloakAdminClientOptions
        {
            RequestPolicy = policy, EnableUnauthorizedRecovery = options.EnableUnauthorizedRecovery
        });
        return new KeycloakPlatformHost(admin, capabilities, gate, catalog, server, options.ProtocolSupport);
    }

    public ProtocolTransport CreateProtocolTransport(HttpClient http, string realm,
        ApplicationSupportConfiguration? configuration = null, DpopProofKey? proofKey = null, bool mutualTls = false)
    {
        ArgumentNullException.ThrowIfNull(http);
        var support = configuration ?? protocolSupport
            ?? throw new ArgumentException("Application support configuration is required.", nameof(configuration));
        return ProtocolTransport.CreateSupported(http, server, realm, ServerCapabilities, support, Gate, proofKey, mutualTls);
    }
}
