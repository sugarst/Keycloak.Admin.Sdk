using Microsoft.VisualStudio.TestTools.UnitTesting;

[assembly: Parallelize(Scope = ExecutionScope.MethodLevel)]

[TestClass]
public sealed class PlatformTests
{
    [TestMethod] public void PlatformFlagCatalogIsCompleteAndFailClosed() => PlatformContracts.Catalog();
    [TestMethod] public Task PlatformGateReplacesSnapshotsAtomically() => PlatformContracts.GateAsync();
    [TestMethod] public Task PlatformHostSharesOneBootstrapAndGate() => PlatformContracts.HostAsync();
    [TestMethod] public Task PlatformHostSwitchesCannotPromoteCatalog() => PlatformContracts.DecisionsAsync();
    [TestMethod, DoNotParallelize] public Task MicrosoftFeatureManagementAndOptionalTelemetry() => PlatformTelemetryContracts.RunAsync();
}
