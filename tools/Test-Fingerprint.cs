#!/usr/bin/env -S dotnet --
#:property TargetFramework=net10.0
#:property PublishAot=false
#:include ScriptSupport.cs
#:include TargetBaseline.cs
#:include ../tests/Keycloak.Admin.Sdk.IntegrationTests/LiveEvidence.cs

return await ScriptHost.ExecuteAsync(args, "dotnet run --file tools/Test-Fingerprint.cs", [], async ct =>
{
    string root = ScriptHost.RepositoryRoot(); var target = TargetBaseline.Load(root);
    await ScriptHost.RunCheckedAsync(root, "docker", ["build", .. target.DockerBuildArgs, "-f", "tests/Keycloak.Admin.Sdk.AotSmoke/Dockerfile", "--target", "integration-export", "--output", "type=local,dest=artifacts/aot/integration", "."], ct);
    var managed = await ScriptHost.RunCheckedAsync(root, "dotnet", ["run", "--project", "tests/Keycloak.Admin.Sdk.IntegrationTests", "-c", "Release", "--", "--fingerprint"], ct, capture: true);
    var native = await ScriptHost.RunCheckedAsync(root, "docker", ["run", "--rm", "-v", root + ":/workspace", "-w", "/workspace", target.NativeRuntimeImage, "/workspace/artifacts/aot/integration/Keycloak.Admin.Sdk.IntegrationTests", "--fingerprint"], ct, capture: true);
    string expected = LiveEvidence.Fingerprint(root);
    if (managed.StandardOutput.Trim().Split('\n')[^1].Trim() != expected || native.StandardOutput.Trim() != expected) throw new InvalidOperationException("Managed and Native AOT source fingerprints differ.");
    Console.WriteLine("PASS source fingerprint: orchestration, managed executable and Linux Native AOT agree: " + expected);
});
