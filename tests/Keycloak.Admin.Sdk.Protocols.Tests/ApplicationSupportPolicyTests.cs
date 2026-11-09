using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Capabilities;
using Keycloak.Admin.Sdk.Protocols;
using Microsoft.VisualStudio.TestTools.UnitTesting;

[TestClass]
public sealed class ApplicationSupportPolicyTests
{
    [TestMethod]
    public void PolicyRequiresActualRuntimeEvidenceStageAndEnabledServerFeatures()
    {
        var catalog = Catalog();
        var config = new ApplicationSupportConfiguration(KeycloakRuntimeProfile.Managed, experimentalCapabilities: ["authzen"]);
        var allowed = Policy(catalog, config);
        allowed.EnsureAllowed("KeycloakSdk.Protocols.AuthZen");
        Assert.AreEqual(KeycloakRuntimeProfile.Managed, config.Runtime); Assert.IsNull(config.RuntimeIdentifier);
        Assert.IsTrue(config.ExperimentalCapabilities.Contains("authzen")); Assert.AreEqual(0, config.PreviewCapabilities.Count);
        Denied(Policy(catalog, new(KeycloakRuntimeProfile.Managed)), KeycloakCapabilityReason.StageNotAllowed);
        var preview = catalog.DeepClone(); preview["features"]![0]!["stage"] = "Preview";
        Denied(Policy(preview, config), KeycloakCapabilityReason.StageNotAllowed);
        var previewConfig = new ApplicationSupportConfiguration(KeycloakRuntimeProfile.Managed, previewCapabilities: ["authzen"]);
        Policy(preview, previewConfig).EnsureAllowed("KeycloakSdk.Protocols.AuthZen");
        var stable = catalog.DeepClone(); stable["features"]![0]!["stage"] = "Stable";
        Policy(stable, new(KeycloakRuntimeProfile.Managed)).EnsureAllowed("KeycloakSdk.Protocols.AuthZen");
        stable["features"]![0]!["deprecated"] = true;
        Denied(Policy(stable, new(KeycloakRuntimeProfile.Managed)), KeycloakCapabilityReason.StageNotAllowed);
        var deprecated = new ApplicationSupportConfiguration(KeycloakRuntimeProfile.Managed, deprecatedCapabilities: ["authzen"]);
        Assert.IsTrue(deprecated.DeprecatedCapabilities.Contains("authzen"));
        Policy(stable, deprecated).EnsureAllowed("KeycloakSdk.Protocols.AuthZen");
        Denied(Policy(catalog, config, Server(enabled: false)), KeycloakCapabilityReason.ServerFeatureDisabled);
        Denied(Policy(catalog, config, Server(include: false)), KeycloakCapabilityReason.ServerFeatureUnknown);
        Denied(Policy(catalog, config, Server(version: "future")), KeycloakCapabilityReason.VersionMismatch);
        var wrongVersion = catalog.DeepClone(); wrongVersion["serverVersion"] = "future";
        Denied(Policy(wrongVersion, config), KeycloakCapabilityReason.VersionMismatch);
        wrongVersion = catalog.DeepClone(); wrongVersion["sourceCommit"] = "wrong";
        Denied(Policy(wrongVersion, config), KeycloakCapabilityReason.VersionMismatch);
        var incomplete = catalog.DeepClone(); incomplete["applicationCapabilities"]![0]!["implementation"] = "Partial";
        Denied(Policy(incomplete, config), KeycloakCapabilityReason.NotImplemented);
        incomplete = catalog.DeepClone(); incomplete["applicationCapabilities"]![0]!["support"] = "NotVerified";
        Denied(Policy(incomplete, config), KeycloakCapabilityReason.NotSupported);
        incomplete = catalog.DeepClone(); incomplete["applicationCapabilities"]![0]!["verificationProfiles"] = new JsonArray();
        Denied(Policy(incomplete, config), KeycloakCapabilityReason.InsufficientVerification);
        incomplete = catalog.DeepClone(); incomplete["verificationProfiles"]![0]!["sourceFingerprint"] = "old-build";
        Denied(Policy(incomplete, config), KeycloakCapabilityReason.InsufficientVerification);
        var empty = catalog.DeepClone(); empty["applicationCapabilities"] = new JsonArray();
        Denied(Policy(empty, config), KeycloakCapabilityReason.UnknownEndpoint);
        Assert.AreEqual(KeycloakCapabilityReason.UnknownEndpoint, Assert.Throws<ApplicationCapabilityDeniedException>(() => allowed.EnsureAllowed("unknown")).Reason);
        Denied(new(Server(), config, Element(catalog), true, "linux-musl-x64", "unit-input"), KeycloakCapabilityReason.RuntimeMismatch);
        var native = new ApplicationSupportConfiguration(KeycloakRuntimeProfile.NativeAot, "linux-musl-x64", experimentalCapabilities: ["authzen"]);
        Denied(new(Server(), native, Element(catalog), true, "win-x64", "unit-input"), KeycloakCapabilityReason.RuntimeMismatch);
        Denied(new(Server(), native, Element(catalog), true, "linux-musl-x64", "unit-input"), KeycloakCapabilityReason.InsufficientVerification);
        catalog["verificationProfiles"]![0]!["runtime"] = "native-aot"; catalog["verificationProfiles"]![0]!["runtimeIdentifier"] = "wrong";
        Denied(new(Server(), native, Element(catalog), true, "linux-musl-x64", "unit-input"), KeycloakCapabilityReason.InsufficientVerification);
        catalog["verificationProfiles"]![0]!["runtimeIdentifier"] = "linux-musl-x64";
        new ApplicationSupportPolicy(Server(), native, Element(catalog), true, "linux-musl-x64", "unit-input").EnsureAllowed("KeycloakSdk.Protocols.AuthZen");
        var alternatives = Catalog(); var second = alternatives["verificationProfiles"]![0]!.DeepClone(); second["id"] = "alternate";
        second["capabilities"]![0]!["requiredServerFeatures"] = new JsonArray();
        alternatives["verificationProfiles"]!.AsArray().Add(second); alternatives["applicationCapabilities"]![0]!["verificationProfiles"]!.AsArray().Add((JsonNode)"alternate");
        Policy(alternatives, config, Server(enabled: false)).EnsureAllowed("KeycloakSdk.Protocols.AuthZen");
    }

    [TestMethod]
    public async Task SupportedTransportIsFailClosedBeforeCredentialsAndHostGate()
    {
        using var handler = new Handler(); using var http = new HttpClient(handler);
        var gate = new KeycloakFeatureSnapshotGate(new Dictionary<string, bool> { ["KeycloakSdk.Protocols"] = true, ["KeycloakSdk.Protocols.Oidc"] = true });
        // A negative control must remain invalid after OIDC is legitimately promoted.
        var transport = ProtocolTransport.CreateSupported(http, new("https://identity.invalid/"), "r", Server(version: "26.8.0"), new(KeycloakRuntimeProfile.Managed), gate);
        int credentials = 0;
        var auth = OAuthClientAuthentication.SecretBasic("app", _ => { credentials++; return ValueTask.FromResult("secret"); });
        Assert.AreEqual(KeycloakCapabilityReason.VersionMismatch, (await Assert.ThrowsAsync<ApplicationCapabilityDeniedException>(() => new OidcClient(transport).ClientCredentialsAsync(auth))).Reason);
        Assert.AreEqual(0, credentials); Assert.AreEqual(0, handler.Calls);
        Assert.Throws<ArgumentNullException>(() => ProtocolTransport.CreateSupported(http, new("https://identity.invalid/"), "r", Server(), new(KeycloakRuntimeProfile.Managed), null!));
        Assert.Throws<ArgumentNullException>(() => new ApplicationSupportPolicy(null!, new(KeycloakRuntimeProfile.Managed)));
        Assert.Throws<ArgumentNullException>(() => new ApplicationSupportPolicy(Server(), null!));
    }

    [TestMethod]
    public void ConfigurationRejectsAmbiguousModesAndCapabilityOptIns()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new ApplicationSupportConfiguration(KeycloakRuntimeProfile.Portable));
        Assert.Throws<ArgumentException>(() => new ApplicationSupportConfiguration(KeycloakRuntimeProfile.Managed, "linux-x64"));
        foreach (string rid in new[] { "", "bad/rid" }) Assert.Throws<ArgumentException>(() => new ApplicationSupportConfiguration(KeycloakRuntimeProfile.NativeAot, rid));
        Assert.IsNotNull(new ApplicationSupportConfiguration(KeycloakRuntimeProfile.NativeAot).RuntimeIdentifier);
        Assert.Throws<ArgumentException>(() => new ApplicationSupportConfiguration(KeycloakRuntimeProfile.Managed, previewCapabilities: [" "]));
        Assert.Throws<ArgumentException>(() => new ApplicationSupportConfiguration(KeycloakRuntimeProfile.Managed, experimentalCapabilities: ["authzen", "authzen"]));
    }

    [TestMethod]
    public void ProtocolFeatureNamesResolveToIndependentApplicationCapabilities()
    {
        string[] names = ["Oidc", "Account", "Scim", "ClientRegistration", "Uma", "AuthZen", "ClientAdminV2", "IdentityBrokering", "Wallet", "Signals", "Docker", "Dpop", "MutualTls",
            "OidcStandardExchange", "OidcLegacyExchange", "OidcDelegation", "OidcJwtGrant", "OidcDevice", "OidcCiba", "OidcPar", "OidcResources", "OidcParameterizedScopes", "OidcIdentityAssertion", "OidcClientMetadata",
            "IdentityBrokeringLegacy", "BrowserOidc", "Saml", "Authentication", "FederatedClientAuth", "SpiffeClientAuth", "IdentityBrokerLogin", "IdentityLinking", "OpenApi", "OidcRequestObjects", "OidcSignedResponses", "OidcBrowserCompatibility", "SamlStepUp", "OidcAssurance", "BrowserOidcAssurance", "WalletPreAuthorized", "WalletOffers", "WalletMdoc", "WalletPresentation", "WalletAttestation"];
        string[] ids = ["oidc", "account", "scim", "registration", "uma", "authzen", "client-admin-v2", "identity-brokering", "wallet", "signals", "docker-registry", "dpop", "mutual-tls",
            "oidc-standard-exchange", "oidc-legacy-exchange", "oidc-delegation", "oidc-jwt-grant", "oidc-device", "oidc-ciba", "oidc-par", "oidc-resources", "oidc-parameterized-scopes", "oidc-identity-assertion", "oidc-client-metadata",
            "identity-brokering-legacy", "browser-oidc", "saml", "authentication", "federated-client-auth", "spiffe-client-auth", "identity-broker-login", "identity-linking", "runtime-openapi", "oidc-request-objects", "oidc-signed-responses", "oidc-browser-compatibility", "saml", "oidc-assurance", "browser-oidc", "wallet-pre-authorized", "wallet-offers", "wallet-mdoc", "wallet-presentation", "wallet-attestation"];
        var catalog = Catalog();
        for (int i = 0; i < names.Length; i++)
        {
            catalog["applicationCapabilities"]![0]!["id"] = ids[i];
            catalog["verificationProfiles"]![0]!["capabilities"]![0]!["id"] = ids[i];
            Policy(catalog, new(KeycloakRuntimeProfile.Managed, experimentalCapabilities: [ids[i]])).EnsureAllowed("KeycloakSdk.Protocols." + names[i]);
        }
        string[] authenticationIds = ["webauthn", "passkeys", "kerberos", "recovery-codes", "update-email", "transient-users", "legacy-logout", "legacy-passkey-ui", "instagram", "twitter"];
        var authentication = Enum.GetValues<KeycloakAuthenticationCapability>();
        for (int i = 0; i < authentication.Length; i++)
        {
            string id = "authentication-" + authenticationIds[i];
            catalog["applicationCapabilities"]![0]!["id"] = id; catalog["verificationProfiles"]![0]!["capabilities"]![0]!["id"] = id;
            Policy(catalog, new(KeycloakRuntimeProfile.Managed, experimentalCapabilities: [id])).EnsureAllowed(authentication[i].Feature());
        }
        catalog["applicationCapabilities"]![0]!["id"] = "runtime-openapi";
        catalog["verificationProfiles"]![0]!["capabilities"]![0]!["id"] = "runtime-openapi";
        catalog["verificationProfiles"]![0]!["capabilities"]!.AsArray().Add((JsonNode)new JsonObject { ["id"] = "ignored", ["requiredServerFeatures"] = new JsonArray() });
        Policy(catalog, new(KeycloakRuntimeProfile.Managed, experimentalCapabilities: ["runtime-openapi"])).EnsureAllowed("KeycloakSdk.Protocols.OpenApi");
        catalog["applicationCapabilities"]![0]!["id"] = "registration";
        catalog["verificationProfiles"]![0]!["capabilities"]![0]!["id"] = "registration";
        var modern = Policy(catalog, new(KeycloakRuntimeProfile.Managed, experimentalCapabilities: ["registration"]));
        foreach (string path in new[] { "clients-registrations/default", "clients-registrations/saml2-entity-descriptor", "clients-registrations/install/id" })
            Assert.AreEqual(KeycloakCapabilityReason.StageNotAllowed, Assert.Throws<ApplicationCapabilityDeniedException>(() => modern.EnsureAllowed("KeycloakSdk.Protocols.ClientRegistration", path)).Reason);
        var compatible = Policy(catalog, new(KeycloakRuntimeProfile.Managed, experimentalCapabilities: ["registration"], deprecatedCapabilities: ["registration"]));
        compatible.EnsureAllowed("KeycloakSdk.Protocols.ClientRegistration", "clients-registrations/default");
    }

    [TestMethod]
    public async Task IndependentlyPromotedProofPolicyRunsBeforeTheFinalHostGateAndCredentials()
    {
        var catalog = Catalog(); catalog["features"]![0]!["stage"] = "Stable";
        catalog["applicationCapabilities"] = new JsonArray(); catalog["verificationProfiles"]![0]!["capabilities"] = new JsonArray();
        foreach (string id in new[] { "oidc", "dpop" })
        {
            catalog["applicationCapabilities"]!.AsArray().Add(new JsonObject { ["id"] = id, ["implementation"] = "Implemented", ["support"] = "Supported", ["verificationProfiles"] = new JsonArray("proof") });
            catalog["verificationProfiles"]![0]!["capabilities"]!.AsArray().Add(new JsonObject { ["id"] = id, ["requiredServerFeatures"] = new JsonArray("AUTHZEN") });
        }
        using var handler = new Handler(); using var http = new HttpClient(handler); using var key = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        var flags = new KeycloakFeatureSnapshotGate(new Dictionary<string, bool> { ["KeycloakSdk.Protocols"] = true, ["KeycloakSdk.Protocols.Oidc"] = true, ["KeycloakSdk.Protocols.Dpop"] = true });
        var transport = new ProtocolTransport(http, new("https://identity.invalid/"), "r", flags, DpopProofKey.FromEcdsa(key), Policy(catalog, new(KeycloakRuntimeProfile.Managed)));
        await new OidcClient(transport).ClientCredentialsAsync(OAuthClientAuthentication.Public("c")); Assert.AreEqual(1, handler.Calls);
        await transport.EnsureEnabledAsync("KeycloakSdk.Protocols.Oidc");
        await new ProtocolTransport(http, new("https://identity.invalid/"), "r").EnsureEnabledAsync("KeycloakSdk.Protocols.Account");
        Assert.Throws<ArgumentException>(() => transport.EnsureEnabledAsync(""));
        catalog["applicationCapabilities"]![1]!["support"] = "NotVerified";
        transport = new(http, new("https://identity.invalid/"), "r", flags, DpopProofKey.FromEcdsa(key), Policy(catalog, new(KeycloakRuntimeProfile.Managed)));
        await Assert.ThrowsAsync<ApplicationCapabilityDeniedException>(() => new OidcClient(transport).ClientCredentialsAsync(OAuthClientAuthentication.SecretBasic("c", _ => throw new AssertFailedException("No credential before promotion"))));
        Assert.AreEqual(1, handler.Calls);
    }

    private static void Denied(ApplicationSupportPolicy policy, KeycloakCapabilityReason reason) => Assert.AreEqual(reason,
        Assert.Throws<ApplicationCapabilityDeniedException>(() => policy.EnsureAllowed("KeycloakSdk.Protocols.AuthZen")).Reason);
    private static ApplicationSupportPolicy Policy(JsonNode catalog, ApplicationSupportConfiguration configuration, KeycloakServerCapabilities? server = null)
        => new(server ?? Server(), configuration, Element(catalog), false, "win-x64", "unit-input");
    private static KeycloakServerCapabilities Server(bool enabled = true, bool include = true, string? version = null)
        => KeycloakServerCapabilities.FromServerInfo(System.Text.Encoding.UTF8.GetBytes(new JsonObject { ["systemInfo"] = new JsonObject { ["version"] = version ?? KeycloakTarget.Version },
            ["features"] = include ? new JsonArray(new JsonObject { ["name"] = "AUTHZEN", ["enabled"] = enabled }) : new JsonArray() }.ToJsonString()));
    private static JsonObject Catalog() => new() { ["serverVersion"] = KeycloakTarget.Version, ["sourceCommit"] = KeycloakTarget.SourceCommit,
        ["features"] = new JsonArray(new JsonObject { ["id"] = "AUTHZEN", ["stage"] = "Experimental", ["deprecated"] = false }),
        ["applicationCapabilities"] = new JsonArray(new JsonObject { ["id"] = "authzen", ["implementation"] = "Implemented", ["support"] = "Supported", ["verificationProfiles"] = new JsonArray("proof") }),
        ["verificationProfiles"] = new JsonArray(new JsonObject { ["id"] = "proof", ["runtime"] = "managed", ["runtimeIdentifier"] = null, ["sourceFingerprint"] = "unit-input",
            ["capabilities"] = new JsonArray(new JsonObject { ["id"] = "authzen", ["requiredServerFeatures"] = new JsonArray("AUTHZEN") }) }) };
    private static JsonElement Element(JsonNode node) { using var document = JsonDocument.Parse(node.ToJsonString()); return document.RootElement.Clone(); }
    private sealed class Handler : HttpMessageHandler
    {
        internal int Calls;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        { Calls++; return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)); }
    }
}
