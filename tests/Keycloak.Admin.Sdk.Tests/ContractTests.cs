using System.Text.Json;
using Keycloak.Admin.Sdk;
using Microsoft.VisualStudio.TestTools.UnitTesting;

[assembly: Parallelize(Scope = ExecutionScope.MethodLevel)]

[TestClass]
public sealed class ContractTests
{
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
