using System.Runtime.CompilerServices;
using System.Text.Json.Nodes;
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Capabilities;
using Keycloak.Admin.Sdk.Protocols;

/// <summary>Run only after candidate promotion. Separate output directories preserve the candidate executable hashes.</summary>
internal static class ProtocolSupportedWorkflows
{
    internal static async Task RunAsync(KeycloakAdminClient admin, HttpClient http, Uri server, string realm, string secret, ReadOnlyMemory<byte> serverInfo,
        bool legacy, Action<bool, string> check, CancellationToken ct)
    {
        var actual = KeycloakServerCapabilities.FromServerInfo(serverInfo); bool native = !RuntimeFeature.IsDynamicCodeSupported;
        var runtime = native ? KeycloakRuntimeProfile.NativeAot : KeycloakRuntimeProfile.Managed;
        var flags = new KeycloakFeatureSnapshotGate(new Dictionary<string, bool> { ["KeycloakSdk.Protocols"] = true, ["KeycloakSdk.Protocols.Oidc"] = true,
            ["KeycloakSdk.Protocols.OidcIdentityAssertion"] = true, ["KeycloakSdk.Protocols.OidcClientMetadata"] = true, ["KeycloakSdk.Protocols.OidcJwtGrant"] = true,
            ["KeycloakSdk.Protocols.OidcStandardExchange"] = true, ["KeycloakSdk.Protocols.OidcLegacyExchange"] = true,
            ["KeycloakSdk.Protocols.IdentityBrokeringLegacy"] = true });
        var stable = new ApplicationSupportConfiguration(runtime);
        ProtocolTransport Supported(ApplicationSupportConfiguration config, KeycloakServerCapabilities? capabilities = null)
            => ProtocolTransport.CreateSupported(http, server, realm, capabilities ?? actual, config, flags);
        var transport = Supported(stable); var oidc = new OidcClient(transport);
        await admin.Clients.CreateClientAsync(realm, new() { ClientId = "supported-app", Protocol = "openid-connect", Enabled = true, PublicClient = false, Secret = secret,
            ServiceAccountsEnabled = true, ProtocolMappers = [new() { Name = "own-audience", Protocol = "openid-connect", ProtocolMapper = "oidc-audience-mapper",
                Config = new() { ["included.client.audience"] = "supported-app", ["access.token.claim"] = "true" } }] }, cancellationToken: ct);
        var client = (await admin.Clients.GetClientsAsync(realm, clientId: "supported-app", cancellationToken: ct)).Body!.Single();
        var user = (await admin.Client.GetServiceAccountUserAsync(realm, client.Id!, ct)).Body!;
        int credentialReads = 0;
        var authentication = OAuthClientAuthentication.SecretBasic("supported-app", _ => { credentialReads++; return ValueTask.FromResult(secret); });
        var grant = await oidc.ClientCredentialsAsync(authentication, cancellationToken: ct);
        check(credentialReads == 1 && (await new KeycloakAccessTokenValidator(oidc, "supported-app").ValidateAsync(grant.Json!.Value.GetProperty("access_token").GetString()!, ct)).Subject == user.Id,
            "The supported factory admits a promoted Stable capability against the real server and verifies the actual service-account identity");
        async Task Denial(Func<Task> request, KeycloakCapabilityReason reason)
        {
            int sent = RecordingHandler.SentCount, reads = credentialReads; bool denied = false;
            try { await request(); } catch (ApplicationCapabilityDeniedException e) when (e.Reason == reason) { denied = true; }
            if (!denied || sent != RecordingHandler.SentCount || reads != credentialReads) throw new InvalidDataException("Supported factory denial was not enforced before credentials and HTTP: " + reason);
        }
        string optInId = legacy ? "oidc-legacy-exchange" : "oidc-identity-assertion";
        string gatedFeature = legacy ? "KeycloakSdk.Protocols.OidcLegacyExchange" : "KeycloakSdk.Protocols.OidcIdentityAssertion";
        await Denial(() => transport.EnsureEnabledAsync(gatedFeature, ct).AsTask(), KeycloakCapabilityReason.StageNotAllowed);
        var opted = new ApplicationSupportConfiguration(runtime, previewCapabilities: legacy ? [optInId] : [], experimentalCapabilities: legacy ? [] : [optInId], deprecatedCapabilities: legacy ? [optInId, "identity-brokering-legacy"] : []);
        await Supported(opted).EnsureEnabledAsync(gatedFeature, ct);
        check(true, "A promoted non-Stable capability remains closed by default and opens only for its explicit per-capability stage opt-in");
        if (!legacy)
        {
            await transport.EnsureEnabledAsync("KeycloakSdk.Protocols.OidcJwtGrant", ct);
            await Denial(() => Supported(opted).EnsureEnabledAsync("KeycloakSdk.Protocols.OidcClientMetadata", ct).AsTask(), KeycloakCapabilityReason.StageNotAllowed);
            check(true, "Stable JWT grant stays available while an identity-assertion opt-in cannot implicitly open the separate experimental client-metadata capability");
            var missing = JsonNode.Parse(serverInfo.Span)!.AsObject();
            foreach (var feature in missing["features"]!.AsArray().Where(f => f!["name"]!.GetValue<string>() == "TOKEN_EXCHANGE_STANDARD_V2")) feature!["enabled"] = false;
            var missingCapabilities = KeycloakServerCapabilities.FromServerInfo(System.Text.Encoding.UTF8.GetBytes(missing.ToJsonString()));
            await Denial(() => Supported(stable, missingCapabilities).EnsureEnabledAsync("KeycloakSdk.Protocols.OidcStandardExchange", ct).AsTask(), KeycloakCapabilityReason.ServerFeatureDisabled);
            check(true, "A compiled promoted profile cannot override a disabled required feature in the actual server snapshot");
        }
        var wrongVersion = JsonNode.Parse(serverInfo.Span)!.AsObject(); wrongVersion["systemInfo"]!["version"] = "0.0.0";
        await Denial(() => new OidcClient(Supported(stable, KeycloakServerCapabilities.FromServerInfo(System.Text.Encoding.UTF8.GetBytes(wrongVersion.ToJsonString())))).ClientCredentialsAsync(authentication, cancellationToken: ct), KeycloakCapabilityReason.VersionMismatch);
        var wrongRuntime = new ApplicationSupportConfiguration(native ? KeycloakRuntimeProfile.Managed : KeycloakRuntimeProfile.NativeAot);
        await Denial(() => new OidcClient(Supported(wrongRuntime)).ClientCredentialsAsync(authentication, cancellationToken: ct), KeycloakCapabilityReason.RuntimeMismatch);
        if (native) await Denial(() => new OidcClient(Supported(new(runtime, "win-x64"))).ClientCredentialsAsync(authentication, cancellationToken: ct), KeycloakCapabilityReason.RuntimeMismatch);
        check(true, "Supported factory rejects a wrong server version runtime or native RID before invoking the credential provider or HTTP");
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel(); int beforeCancellation = credentialReads, sentBeforeCancellation = RecordingHandler.SentCount;
        try { await oidc.ClientCredentialsAsync(authentication, cancellationToken: cancelled.Token); throw new InvalidDataException("Cancellation was ignored."); } catch (OperationCanceledException) { }
        check(credentialReads == beforeCancellation && RecordingHandler.SentCount == sentBeforeCancellation, "Cancellation stops a supported request before reading credentials or sending HTTP");
        flags.Replace([]); int before = RecordingHandler.SentCount, readsBefore = credentialReads;
        try { await oidc.ClientCredentialsAsync(authentication, cancellationToken: ct); throw new InvalidDataException("Host shutdown was ignored."); }
        catch (InvalidOperationException e) when (e.Message.StartsWith("Protocol disabled by host:", StringComparison.Ordinal)) { }
        check(before == RecordingHandler.SentCount && readsBefore == credentialReads, "Final host shutdown overrides an otherwise valid promoted Stable profile before credentials or HTTP");
    }
}
