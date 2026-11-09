using System.Text.Json;
using Keycloak.Admin.Sdk;
using Microsoft.VisualStudio.TestTools.UnitTesting;

[assembly: Parallelize(Scope = ExecutionScope.MethodLevel)]

[TestClass]
public sealed class ContractTests
{
    [TestMethod] public void RuntimeCapabilityConfiguration() => RuntimeCapabilityContracts.Configuration();
    [TestMethod] public void RuntimeCapabilityMatrix() => RuntimeCapabilityContracts.RuntimeMatrix();
    [TestMethod] public void RuntimeCapabilityCatalogValidation() => RuntimeCapabilityContracts.CatalogValidation();
    [TestMethod] public Task RuntimeIndependentFeatureGates() => RuntimeCapabilityContracts.GatesAsync();
    [TestMethod] public Task RawClientInterfaceOverloads() => InterfaceContracts.RawTransportsAsync();
    [TestMethod] public Task TransientReadResilience() => ResilienceContracts.ReadsAsync();
    [TestMethod] public Task ResilienceBypassesWritesAndTokenPost() => ResilienceContracts.BypassAsync();
    [TestMethod] public Task ResilienceAnd401RecoveryAreBounded() => ResilienceContracts.AuthenticationAsync();
    [TestMethod] public Task ResilienceTimeoutsAndCancellation() => ResilienceContracts.TimeoutsAsync();
    [TestMethod] public Task ReadCircuitAndNamedClientIsolation() => ResilienceContracts.CircuitAsync();
    [TestMethod] public Task StreamResilienceBeforeDeliveryOnly() => ResilienceContracts.StreamsAsync();
    [TestMethod] public void ResilienceConfigurationValidation() => ResilienceContracts.Validation();
    [TestMethod] public void PlatformFlagCatalogIsCompleteAndFailClosed() => PlatformContracts.Catalog();
    [TestMethod] public Task PlatformGateReplacesSnapshotsAtomically() => PlatformContracts.GateAsync();
    [TestMethod] public Task PlatformHostSharesOneBootstrapAndGate() => PlatformContracts.HostAsync();
    [TestMethod] public Task PlatformHostSwitchesCannotPromoteCatalog() => PlatformContracts.DecisionsAsync();
    [TestMethod, DoNotParallelize] public Task MicrosoftFeatureManagementAndOptionalTelemetry() => PlatformTelemetryContracts.RunAsync();
    [TestMethod] public void VersionCapabilityCatalog() => CapabilityContracts.Catalog();
    [TestMethod] public void SupportConfigurationAndOverrides() => CapabilityContracts.Configuration();
    [TestMethod] public void ConjunctiveSupportDecisions() => CapabilityContracts.Decisions();
    [TestMethod] public Task PolicyBlocksAllTransportsBeforeAuthentication() => CapabilityContracts.Transport();
    [TestMethod] public Task ServerCapabilitiesBootstrap() => CapabilityContracts.Bootstrap();
    [TestMethod] public Task DependencyInjectionLifetimesAndIsolation() => DependencyInjectionContracts.RunAsync();
    [TestMethod] public Task StructuredHttpErrors() => RecoveryContracts.ErrorsAsync();
    [TestMethod] public Task UnauthorizedReplayPolicy() => RecoveryContracts.ReplayAsync();
    [TestMethod] public Task StreamingRecoveryAndOwnership() => RecoveryContracts.StreamAsync();
    [TestMethod] public Task ConditionalInvalidationAndSharedAcquisition() => RecoveryContracts.ConcurrencyAsync();
    [TestMethod] public Task AcquisitionFailuresTimeoutAndLifetime() => RecoveryContracts.FailuresAsync();
    [TestMethod] public Task SamlExampleIsJsonString() => AlignmentContracts.SamlExampleStringAsync();
    [TestMethod] public Task CertificateUploadAcceptsMultipart() => AlignmentContracts.CertificateUploadHasBodyAsync();
    [TestMethod]
    public void AllPublishedModelsRoundTrip() => ModelMatrix.Run();

    [TestMethod] public Task UriValidationAndMissingMetadata() => RuntimeContracts.UriAndMetadataAsync();
    [TestMethod] public Task ConstructorValidationAndCancelledContent() => RuntimeContracts.ConstructorAndTransportAsync();
    [TestMethod] public Task TokenFailureContractsAndRecovery() => RuntimeContracts.TokenFailuresAndRecoveryAsync();
    [TestMethod] public Task StreamingFailuresAndResponseMetadata() => RuntimeContracts.StreamFailuresAndOwnershipAsync();
    [TestMethod]
    public void JsonReflectionIsDisabled() => Assert.IsFalse(JsonSerializer.IsReflectionEnabledByDefault);

    [TestMethod]
    public async Task GeneratedEndpointRoutesAndSerialization()
    {
        await ContractSuite.AllEndpointsAsync();
        // VSTest may run from bin/. Resolve evidence independently of its working directory.
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "Keycloak.Admin.Sdk.slnx")))
            directory = directory.Parent;
        Assert.IsNotNull(directory, "Could not locate the repository for routing evidence.");
        string artifacts = Path.Combine(directory.FullName, "artifacts");
        Directory.CreateDirectory(artifacts);
        await File.WriteAllLinesAsync(Path.Combine(artifacts, "routing-verified.tsv"),
            AdminEndpointCatalog.All.Select(endpoint => endpoint.Method + "\t" + endpoint.Path));
    }

    [TestMethod]
    public Task HttpAndJsonSemantics() => ContractSuite.SemanticsAsync();

    [TestMethod]
    public Task TokenCacheConcurrencyAndExpiry() => ContractSuite.TokenCacheAsync();

    [TestMethod]
    public Task StreamingResponseOwnership() => ContractSuite.StreamOwnershipAsync();

    [TestMethod] public Task ScheduledWorkflowsAreArrays() => AlignmentContracts.WorkflowArraysAsync();
    [TestMethod] public Task PolicyProviderQueryContract() => AlignmentContracts.PolicyQueriesAsync();
    [TestMethod] public Task PermissionProviderQueryContract() => AlignmentContracts.PermissionQueriesAsync();
    [TestMethod] public Task IdentityProviderImportMediaContract() => AlignmentContracts.IdentityProviderMediaAsync();
    [TestMethod] public Task LocalizationImportMediaContract() => AlignmentContracts.LocalizationMediaAsync();
    [TestMethod] public Task SmtpTestMediaContract() => AlignmentContracts.SmtpMediaAsync();
}
