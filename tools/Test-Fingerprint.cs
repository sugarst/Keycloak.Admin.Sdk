#!/usr/bin/env -S dotnet --
#:property TargetFramework=net10.0
#:property PublishAot=false
#:include Shared/ScriptSupport.cs
#:include Shared/TargetBaseline.cs
#:include Shared/IntegrationBuild.cs
#:include ../tests/Keycloak.Admin.Sdk.IntegrationTests/LiveEvidence.cs

return await ScriptHost.ExecuteAsync(args, "dotnet run --file tools/Test-Fingerprint.cs", [], async ct =>
{
    string root = ScriptHost.RepositoryRoot(); var target = TargetBaseline.Load(root);
    await IntegrationBuild.PrepareAsync(root, true, "artifacts/aot/integration", ct);
    string managedOutput = "tests/Keycloak.Admin.Sdk.IntegrationTests/bin/Release/net10.0";
    await IntegrationBuild.PrepareAsync(root, false, managedOutput, ct);
    var managed = await ScriptHost.RunCheckedAsync(root, "dotnet", [managedOutput + "/Keycloak.Admin.Sdk.IntegrationTests.dll", "--fingerprint"], ct, capture: true);
    var native = await ScriptHost.RunCheckedAsync(root, "docker", ["run", "--rm", "-v", root + ":/workspace", "-w", "/workspace", target.NativeRuntimeImage, "/workspace/artifacts/aot/integration/Keycloak.Admin.Sdk.IntegrationTests", "--fingerprint"], ct, capture: true);
    string expected = LiveEvidence.Fingerprint(root);
    if (managed.StandardOutput.Trim().Split('\n')[^1].Trim() != expected || native.StandardOutput.Trim() != expected) throw new InvalidOperationException("Managed and Native AOT source fingerprints differ.");
    Console.WriteLine("PASS source fingerprint: orchestration, managed executable and Linux Native AOT agree: " + expected);
});
