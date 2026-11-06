using System.Collections.Frozen;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text.Json;
using Keycloak.Admin.Sdk.Capabilities;

namespace Keycloak.Admin.Sdk.Protocols;

/// <summary>Explicit application runtime and per-capability non-stable opt-ins. The default policy admits Stable only.</summary>
public sealed class ApplicationSupportConfiguration
{
    public KeycloakRuntimeProfile Runtime { get; }
    public string? RuntimeIdentifier { get; }
    public IReadOnlySet<string> PreviewCapabilities { get; }
    public IReadOnlySet<string> ExperimentalCapabilities { get; }
    public IReadOnlySet<string> DeprecatedCapabilities { get; }
    public ApplicationSupportConfiguration(KeycloakRuntimeProfile runtime, string? runtimeIdentifier = null,
        IEnumerable<string>? previewCapabilities = null, IEnumerable<string>? experimentalCapabilities = null, IEnumerable<string>? deprecatedCapabilities = null)
    {
        if (runtime is not (KeycloakRuntimeProfile.Managed or KeycloakRuntimeProfile.NativeAot)) throw new ArgumentOutOfRangeException(nameof(runtime));
        if (runtime == KeycloakRuntimeProfile.Managed && runtimeIdentifier is not null) throw new ArgumentException("Managed support does not select a native RID.", nameof(runtimeIdentifier));
        if (runtimeIdentifier is not null && (runtimeIdentifier.Length == 0 || runtimeIdentifier.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '-')))
            throw new ArgumentException("Invalid native runtime identifier.", nameof(runtimeIdentifier));
        Runtime = runtime; RuntimeIdentifier = runtime == KeycloakRuntimeProfile.Managed ? null : runtimeIdentifier ?? RuntimeInformation.RuntimeIdentifier;
        PreviewCapabilities = Set(previewCapabilities); ExperimentalCapabilities = Set(experimentalCapabilities); DeprecatedCapabilities = Set(deprecatedCapabilities);
    }
    private static FrozenSet<string> Set(IEnumerable<string>? ids)
    {
        string[] values = (ids ?? []).ToArray();
        if (values.Any(string.IsNullOrWhiteSpace) || values.Distinct(StringComparer.Ordinal).Count() != values.Length) throw new ArgumentException("Application capability IDs must be nonempty and unique.");
        return values.ToFrozenSet(StringComparer.Ordinal);
    }
}

public sealed class ApplicationCapabilityDeniedException(KeycloakCapabilityReason reason)
    : InvalidOperationException("Application support policy denied request: " + reason)
{
    public KeycloakCapabilityReason Reason { get; } = reason;
}

internal sealed class ApplicationSupportPolicy
{
    private readonly KeycloakServerCapabilities server;
    private readonly ApplicationSupportConfiguration config;
    private readonly JsonElement catalog;
    private readonly bool native;
    private readonly string rid;
    private readonly string buildFingerprint;
    internal ApplicationSupportPolicy(KeycloakServerCapabilities server, ApplicationSupportConfiguration config)
        : this(server, config, Load(), !RuntimeFeature.IsDynamicCodeSupported, RuntimeInformation.RuntimeIdentifier, ApplicationBuildStamp.InputFingerprint) { }
    internal ApplicationSupportPolicy(KeycloakServerCapabilities server, ApplicationSupportConfiguration config, JsonElement catalog, bool native, string rid, string buildFingerprint)
    {
        this.server = server ?? throw new ArgumentNullException(nameof(server)); this.config = config ?? throw new ArgumentNullException(nameof(config));
        this.catalog = catalog.Clone(); this.native = native; this.rid = rid; this.buildFingerprint = buildFingerprint;
    }
    private static JsonElement Load()
    {
        using var stream = typeof(ApplicationSupportPolicy).Assembly.GetManifestResourceStream("Keycloak.Admin.Sdk.Protocols.PlatformCapabilities.json")!;
        using var json = JsonDocument.Parse(stream); return json.RootElement.Clone();
    }
    internal void EnsureAllowed(string feature, string path = "")
    {
        void Require(bool condition, KeycloakCapabilityReason reason) { if (!condition) throw new ApplicationCapabilityDeniedException(reason); }
        Require(server.ServerVersion == KeycloakTarget.Version && catalog.GetProperty("serverVersion").GetString() == KeycloakTarget.Version
            && catalog.GetProperty("sourceCommit").GetString() == KeycloakTarget.SourceCommit, KeycloakCapabilityReason.VersionMismatch);
        Require(config.Runtime == (native ? KeycloakRuntimeProfile.NativeAot : KeycloakRuntimeProfile.Managed)
            && (!native || config.RuntimeIdentifier == rid), KeycloakCapabilityReason.RuntimeMismatch);
        string id = feature switch
        {
            "KeycloakSdk.Protocols.Oidc" => "oidc", "KeycloakSdk.Protocols.Account" => "account", "KeycloakSdk.Protocols.Scim" => "scim",
            "KeycloakSdk.Protocols.OidcStandardExchange" => "oidc-standard-exchange", "KeycloakSdk.Protocols.OidcLegacyExchange" => "oidc-legacy-exchange",
            "KeycloakSdk.Protocols.OidcDelegation" => "oidc-delegation", "KeycloakSdk.Protocols.OidcJwtGrant" => "oidc-jwt-grant",
            "KeycloakSdk.Protocols.OidcDevice" => "oidc-device", "KeycloakSdk.Protocols.OidcCiba" => "oidc-ciba", "KeycloakSdk.Protocols.OidcPar" => "oidc-par",
            "KeycloakSdk.Protocols.OidcResources" => "oidc-resources", "KeycloakSdk.Protocols.OidcParameterizedScopes" => "oidc-parameterized-scopes",
            "KeycloakSdk.Protocols.OidcIdentityAssertion" => "oidc-identity-assertion", "KeycloakSdk.Protocols.OidcClientMetadata" => "oidc-client-metadata",
            "KeycloakSdk.Protocols.OidcRequestObjects" => "oidc-request-objects", "KeycloakSdk.Protocols.OidcSignedResponses" => "oidc-signed-responses",
            "KeycloakSdk.Protocols.OidcBrowserCompatibility" => "oidc-browser-compatibility",
            "KeycloakSdk.Protocols.OidcAssurance" => "oidc-assurance",
            "KeycloakSdk.Protocols.IdentityBrokeringLegacy" => "identity-brokering-legacy",
            "KeycloakSdk.Protocols.BrowserOidc" or "KeycloakSdk.Protocols.BrowserOidcAssurance" => "browser-oidc", "KeycloakSdk.Protocols.Saml" or "KeycloakSdk.Protocols.SamlStepUp" => "saml", "KeycloakSdk.Protocols.Authentication" => "authentication",
            "KeycloakSdk.Protocols.FederatedClientAuth" => "federated-client-auth",
            "KeycloakSdk.Protocols.SpiffeClientAuth" => "spiffe-client-auth",
            "KeycloakSdk.Protocols.IdentityBrokerLogin" => "identity-broker-login", "KeycloakSdk.Protocols.IdentityLinking" => "identity-linking",
            "KeycloakSdk.Protocols.ClientRegistration" => "registration", "KeycloakSdk.Protocols.Uma" => "uma", "KeycloakSdk.Protocols.AuthZen" => "authzen",
            "KeycloakSdk.Protocols.ClientAdminV2" => "client-admin-v2", "KeycloakSdk.Protocols.IdentityBrokering" => "identity-brokering",
            "KeycloakSdk.Protocols.OpenApi" => "runtime-openapi",
            "KeycloakSdk.Protocols.Dpop" => "dpop", "KeycloakSdk.Protocols.MutualTls" => "mutual-tls",
            "KeycloakSdk.Protocols.Wallet" => "wallet", "KeycloakSdk.Protocols.WalletPreAuthorized" => "wallet-pre-authorized",
            "KeycloakSdk.Protocols.WalletOffers" => "wallet-offers", "KeycloakSdk.Protocols.WalletMdoc" => "wallet-mdoc",
            "KeycloakSdk.Protocols.WalletPresentation" => "wallet-presentation", "KeycloakSdk.Protocols.WalletAttestation" => "wallet-attestation",
            "KeycloakSdk.Protocols.AuthenticationWebAuthn" => "authentication-webauthn", "KeycloakSdk.Protocols.AuthenticationPasskeys" => "authentication-passkeys",
            "KeycloakSdk.Protocols.AuthenticationKerberos" => "authentication-kerberos", "KeycloakSdk.Protocols.AuthenticationRecoveryCodes" => "authentication-recovery-codes",
            "KeycloakSdk.Protocols.AuthenticationUpdateEmail" => "authentication-update-email", "KeycloakSdk.Protocols.AuthenticationTransientUsers" => "authentication-transient-users",
            "KeycloakSdk.Protocols.AuthenticationLegacyLogoutAllSessions" => "authentication-legacy-logout", "KeycloakSdk.Protocols.AuthenticationLegacyConditionalPasskeyUi" => "authentication-legacy-passkey-ui",
            "KeycloakSdk.Protocols.AuthenticationInstagram" => "authentication-instagram", "KeycloakSdk.Protocols.AuthenticationTwitter" => "authentication-twitter",
            "KeycloakSdk.Protocols.Signals" => "signals", "KeycloakSdk.Protocols.Docker" => "docker-registry", _ => ""
        };
        var capability = catalog.GetProperty("applicationCapabilities").EnumerateArray().FirstOrDefault(c => c.GetProperty("id").GetString() == id);
        Require(capability.ValueKind == JsonValueKind.Object, KeycloakCapabilityReason.UnknownEndpoint);
        Require(capability.GetProperty("implementation").GetString() == "Implemented", KeycloakCapabilityReason.NotImplemented);
        Require(capability.GetProperty("support").GetString() == "Supported", KeycloakCapabilityReason.NotSupported);
        bool registrationCompatibility = path.StartsWith("clients-registrations/default", StringComparison.Ordinal)
            || path.StartsWith("clients-registrations/saml2-entity-descriptor", StringComparison.Ordinal) || path.StartsWith("clients-registrations/install", StringComparison.Ordinal);
        Require(!registrationCompatibility || config.DeprecatedCapabilities.Contains("registration"), KeycloakCapabilityReason.StageNotAllowed);
        var profiles = catalog.GetProperty("verificationProfiles").EnumerateArray().Where(p => p.GetProperty("sourceFingerprint").GetString() == buildFingerprint
            && p.GetProperty("runtime").GetString() == (native ? "native-aot" : "managed")
            && (!native || p.GetProperty("runtimeIdentifier").GetString() == rid)
            && capability.GetProperty("verificationProfiles").EnumerateArray().Any(v => v.GetString() == p.GetProperty("id").GetString())).ToArray();
        Require(profiles.Length != 0, KeycloakCapabilityReason.InsufficientVerification);
        // Profiles may describe mutually exclusive server configurations; one applicable profile is sufficient.
        KeycloakCapabilityReason failure = KeycloakCapabilityReason.InsufficientVerification;
        foreach (var profile in profiles)
        {
            var requiredFeatures = profile.GetProperty("capabilities").EnumerateArray().Single(c => c.GetProperty("id").GetString() == id).GetProperty("requiredServerFeatures").EnumerateArray();
            KeycloakCapabilityReason reason = KeycloakCapabilityReason.Allowed;
            foreach (var requiredFeature in requiredFeatures)
            {
                string required = requiredFeature.GetString()!;
                var metadata = catalog.GetProperty("features").EnumerateArray().Single(f => f.GetProperty("id").GetString() == required);
                string? stage = metadata.GetProperty("stage").GetString();
                if ((stage == "Preview" && !config.PreviewCapabilities.Contains(id)) || (stage == "Experimental" && !config.ExperimentalCapabilities.Contains(id))
                    || (metadata.GetProperty("deprecated").GetBoolean() && !config.DeprecatedCapabilities.Contains(id))) reason = KeycloakCapabilityReason.StageNotAllowed;
                else if (!server.Features.ContainsKey(required)) reason = KeycloakCapabilityReason.ServerFeatureUnknown;
                else if (!server.Features.GetValueOrDefault(required)) reason = KeycloakCapabilityReason.ServerFeatureDisabled;
                if (reason != KeycloakCapabilityReason.Allowed) break;
            }
            if (reason == KeycloakCapabilityReason.Allowed) return;
            failure = reason;
        }
        throw new ApplicationCapabilityDeniedException(failure);
    }
}
