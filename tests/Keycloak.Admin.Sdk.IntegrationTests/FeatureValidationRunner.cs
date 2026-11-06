using System.Net;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Capabilities;
#if KEYCLOAK_FEATURE_MANAGEMENT
using Keycloak.Admin.Sdk.FeatureManagement;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.FeatureManagement;
#endif

internal static class FeatureValidationRunner
{
    public static async Task RunAsync(HttpClient http, Uri server, IAccessTokenProvider tokens, string id, bool guarded, CancellationToken cancellationToken)
    {
        string root = Directory.GetCurrentDirectory();
        if (FeatureValidationBuildStamp.InputFingerprint != LiveEvidence.ValidationFingerprint(root))
            throw new InvalidDataException("Validation executable was built from different inputs; rebuild before running.");
        if (guarded && FeatureValidationBuildStamp.CatalogSha256 != Convert.ToHexStringLower(SHA256.HashData(await File.ReadAllBytesAsync(Path.Combine(root, "contracts/capabilities.json"), cancellationToken))))
            throw new InvalidDataException("Validation executable contains a different capability catalog; rebuild before guarded acceptance.");
        var plan = FeatureValidationPlan.Load(root, id);
        if (plan.Id != "client-types" || !plan.Operations.ToHashSet(StringComparer.Ordinal).SetEquals(new[] { "ClientTypes.GetClientTypesAsync", "ClientTypes.UpdateClientTypesAsync" }))
            throw new NotSupportedException("No reviewed business workflow for this validation plan.");
        string routeId = Environment.GetEnvironmentVariable("KEYCLOAK_ADMIN_API_ROUTE") ?? "fgap-v2-stable";
        var route = KeycloakRoute.Load(root, routeId);
        bool native = !RuntimeFeature.IsDynamicCodeSupported;
        string mode = native ? "native-aot" : "managed";
        string? rid = native ? RuntimeInformation.RuntimeIdentifier : null;
        string resultPath = plan.ResultPath(root, routeId, mode, rid, guarded);
        Directory.CreateDirectory(Path.GetDirectoryName(resultPath)!); File.Delete(resultPath);
        var wire = new KeycloakAdminClient(http, server, tokens);
        var info = await wire.ServerInfoAdmin.GetInfoAsync(cancellationToken);
        using (var parsed = System.Text.Json.JsonDocument.Parse(info.Content)) route.ValidateServer(parsed.RootElement, plan.ServerFeatures.ToHashSet(StringComparer.Ordinal));
        var support = new KeycloakSupportConfiguration(KeycloakTarget.Version, native ? KeycloakRuntimeProfile.NativeAot : KeycloakRuntimeProfile.Managed,
            route.FgapVersion == 1 ? KeycloakAdminRoute.FgapV1Compatibility : KeycloakAdminRoute.FgapV2Stable, rid,
            plan.Stage == KeycloakFeatureStage.Preview ? [plan.FeatureId] : [], plan.Stage == KeycloakFeatureStage.Experimental ? [plan.FeatureId] : []);
        IKeycloakFeatureGate gate;
#if KEYCLOAK_FEATURE_MANAGEMENT
        using var flags = (ConfigurationRoot)new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["feature_management:feature_flags:0:id"] = KeycloakFeatureGatePolicy.AdminApiFeature,
            ["feature_management:feature_flags:0:enabled"] = "true",
            ["feature_management:feature_flags:1:id"] = plan.FeatureId,
            ["feature_management:feature_flags:1:enabled"] = "false"
        }).Build();
        var services = new ServiceCollection(); services.AddSingleton<IConfiguration>(flags); services.AddFeatureManagement();
        using var provider = services.BuildServiceProvider();
        gate = new KeycloakMicrosoftFeatureGate(provider.GetRequiredService<IVariantFeatureManager>());
        void Enable(bool value) { flags["feature_management:feature_flags:1:enabled"] = value ? "true" : "false"; flags.Reload(); }
        string gateName = "microsoft-feature-management";
#else
        var snapshot = new KeycloakFeatureSnapshotGate(new Dictionary<string, bool> { [KeycloakFeatureGatePolicy.AdminApiFeature] = true });
        gate = snapshot;
        void Enable(bool value) => snapshot.Replace(new Dictionary<string, bool> { [KeycloakFeatureGatePolicy.AdminApiFeature] = true, [plan.FeatureId] = value });
        string gateName = "snapshot";
#endif
        var sdk = guarded ? await KeycloakSupportedClient.CreateAsync(http, server, tokens, support, gate, cancellationToken: cancellationToken) : wire;
        string realm = "sdk-feature-" + Guid.NewGuid().ToString("N");
        var proofs = new JsonArray();
        bool flagDenial = false;
        async Task Denied(Func<Task> call)
        {
            int before = RecordingHandler.SentCount;
            try { await call(); }
            catch (KeycloakCapabilityDeniedException error) when (error.Decision.Reason == KeycloakCapabilityReason.DisabledByHost)
            {
                if (before != RecordingHandler.SentCount) throw new InvalidOperationException("Disabled feature reached transport.");
                return;
            }
            throw new InvalidOperationException("Feature gate did not deny the validation operation.");
        }
        try
        {
            await wire.RealmsAdmin.ImportRealmAsync(AdminJsonContent(new RealmRepresentation { Realm = realm, Enabled = true }), cancellationToken);
            if (guarded) await Denied(async () => await sdk.ClientTypes.GetClientTypesAsync(realm, cancellationToken));
            Enable(true);
            var initial = await sdk.ClientTypes.GetClientTypesAsync(realm, cancellationToken);
            if (initial.Body?.ClientTypes is not { Count: 0 }) throw new InvalidOperationException("Isolated realm must initially have no custom client types.");
            string name = "sdk-validated-type";
            var update = await sdk.ClientTypes.UpdateClientTypesAsync(realm, new ClientTypesRepresentation
            { ClientTypes = [new ClientTypeRepresentation { Name = name, Provider = "default", Config = new() }] }, cancellationToken);
            var persisted = await sdk.ClientTypes.GetClientTypesAsync(realm, cancellationToken);
            if (persisted.Body?.ClientTypes is not { Count: 1 } types || types[0].Name != name || types[0].Provider != "default")
                throw new InvalidOperationException("Client type update was not persisted.");
            await sdk.ClientTypes.UpdateClientTypesAsync(realm, new ClientTypesRepresentation { ClientTypes = [] }, cancellationToken);
            var removed = await sdk.ClientTypes.GetClientTypesAsync(realm, cancellationToken);
            if (removed.Body?.ClientTypes is not { Count: 0 }) throw new InvalidOperationException("Replacing client types did not remove the stored type.");
            if (guarded)
            {
                Enable(false);
                await Denied(async () => await sdk.ClientTypes.UpdateClientTypesAsync(realm, new ClientTypesRepresentation { ClientTypes = [] }, cancellationToken));
                flagDenial = true;
            }
            void Proof(string operation, int status, string proof)
            {
                var endpoint = KeycloakCapabilityCatalog.Current.Endpoints.Single(e => e.Operation == operation);
                proofs.Add((JsonNode)new JsonObject { ["operation"] = operation, ["method"] = endpoint.Method, ["path"] = endpoint.Path, ["status"] = status, ["proof"] = proof });
            }
            Proof("ClientTypes.GetClientTypesAsync", (int)persisted.StatusCode, "Isolated realm reads empty, persisted custom provider/type, then empty after replacement.");
            Proof("ClientTypes.UpdateClientTypesAsync", (int)update.StatusCode, "Custom client type and provider persist; a subsequent empty replacement removes the stored type.");
        }
        finally
        {
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            try { await wire.RealmAdmin.DeleteRealmAsync(realm, cleanup.Token); }
            catch (KeycloakAdminException error) when (error.StatusCode == HttpStatusCode.NotFound) { }
        }
        string executable = native ? Environment.ProcessPath! : Path.Combine(AppContext.BaseDirectory, "Keycloak.Admin.Sdk.IntegrationTests.dll");
        if (FeatureValidationBuildStamp.InputFingerprint != LiveEvidence.ValidationFingerprint(root)) throw new InvalidDataException("Validation inputs changed during the run.");
        var report = new JsonObject
        {
            ["schemaVersion"] = 1, ["plan"] = id, ["featureId"] = plan.FeatureId, ["stage"] = plan.Stage.ToString(),
            ["serverVersion"] = KeycloakTarget.Version, ["keycloakSourceCommit"] = KeycloakTarget.SourceCommit,
            ["validationFingerprint"] = FeatureValidationBuildStamp.InputFingerprint,
            ["catalogSha256"] = FeatureValidationBuildStamp.CatalogSha256,
            ["mode"] = mode, ["runtimeIdentifier"] = rid, ["nativePublished"] = native, ["route"] = routeId,
            ["phase"] = guarded ? "guarded" : "candidate", ["completed"] = true,
            ["executableSha256"] = Convert.ToHexStringLower(SHA256.HashData(await File.ReadAllBytesAsync(executable, cancellationToken))),
            ["serverInfo"] = JsonNode.Parse(info.Content.Span), ["gate"] = guarded ? gateName : "test-only-wire",
            ["flagDenialVerified"] = flagDenial, ["operations"] = proofs, ["finishedUtc"] = DateTimeOffset.UtcNow.ToString("O")
        };
        await File.WriteAllTextAsync(resultPath, LiveJson.String(report), cancellationToken);
        Console.WriteLine($"PASS feature validation: {id}/{routeId}/{mode}/{report["phase"]}; {proofs.Count} business-proven operations; evidence {resultPath}");
    }

    private static HttpContent AdminJsonContent(RealmRepresentation realm)
        => new StringContent(System.Text.Json.JsonSerializer.Serialize(realm, KeycloakJsonContext.Default.RealmRepresentation), System.Text.Encoding.UTF8, "application/json");
}
