#!/usr/bin/env -S dotnet --
#:property TargetFramework=net10.0
#:property PublishAot=false
#:include ScriptSupport.cs
#:include TargetBaseline.cs

using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Xml.Linq;

return await ScriptHost.ExecuteAsync(args,
    "dotnet run --file tools/Verify.cs -- [--skip-native-publish | --native-container]", ["--skip-native-publish", "--native-container"], async ct =>
{
    string root = ScriptHost.RepositoryRoot();
    await ScriptHost.RunCheckedAsync(root, "dotnet", ["run", "--file", "tools/Check-Baseline.cs"], ct);
    await ScriptHost.RunCheckedAsync(root, "dotnet", ["run", "--file", "tools/Check-Baseline.cs", "--", "--self-test"], ct);
    if (args.Length > 1) throw new ArgumentException("Choose only one native verification option.");
    var legacyYaml = ScriptHost.RepositoryFiles(root).Where(file => Path.GetExtension(file).Equals(".yml", StringComparison.OrdinalIgnoreCase)).ToArray();
    if (legacyYaml.Length != 0)
        throw new InvalidDataException("Use .yaml for repository YAML files:\n" + string.Join('\n', legacyYaml.Select(file => Path.GetRelativePath(root, file))));
    foreach (string script in new[] { "Release.cs", "Upgrade.cs", "Test-Workflow.cs", "Generate-ValidationList.cs", "Test-Integration.cs", "Update-Contracts.cs", "Update-Verification.cs", "Audit-Contracts.cs", "Generate-TestMatrix.cs", "Check-Coverage.cs", "Generate-LiveRoutes.cs", "Check-AdminRoutes.cs", "Check-FullAcceptance.cs", "Test-AcceptanceGate.cs", "Test-AllAdminRoutes.cs", "Generate-CapabilityCatalog.cs" })
        await ScriptHost.RunCheckedAsync(root, "dotnet", ["build", "tools/" + script], ct);
    await ScriptHost.RunCheckedAsync(root, "dotnet", ["build", "local/keycloak/Service.cs"], ct);
    await ScriptHost.RunCheckedAsync(root, "dotnet", ["build", "Keycloak.Admin.Sdk.slnx", "-c", "Release"], ct);
    await ScriptHost.RunCheckedAsync(root, "dotnet", ["run", "--file", "tools/Generate-TestMatrix.cs", "--", "--check"], ct);
    await ScriptHost.RunCheckedAsync(root, "dotnet", ["run", "--file", "tools/Generate-LiveRoutes.cs", "--", "--check"], ct);
    await ScriptHost.RunCheckedAsync(root, "dotnet", ["run", "--file", "tools/Check-AdminRoutes.cs"], ct);
    await ScriptHost.RunCheckedAsync(root, "dotnet", ["run", "--file", "tools/Generate-CapabilityCatalog.cs", "--", "--check"], ct);
    await ScriptHost.RunCheckedAsync(root, "dotnet", ["run", "--file", "tools/Check-Coverage.cs", "--", "--self-test"], ct);
    // A fresh directory makes stale TRX/coverage evidence impossible to reuse accidentally.
    string testResults = "artifacts/test-results/verify-" + Guid.NewGuid().ToString("N");
    await ScriptHost.RunCheckedAsync(root, "dotnet", ["test", "tests/Keycloak.Admin.Sdk.Tests", "-c", "Release", "--no-build",
        "--logger", "trx;LogFileName=contracts.trx", "--results-directory", testResults, "--collect", "XPlat Code Coverage"], ct);
    await ScriptHost.RunCheckedAsync(root, "dotnet", ["run", "--file", "tools/Check-Coverage.cs", "--", "--results=" + testResults], ct);
    await File.WriteAllTextAsync(Path.Combine(root, "artifacts/test-results/latest.txt"), testResults, ct);
    var target = TargetBaseline.Load(root);
    string feed = Path.Combine(root, "artifacts", "packages", target.PackageVersion);
    var dependencies = new Dictionary<string, string[]>
    {
        ["Keycloak.Admin.Sdk"] = ["Microsoft.Extensions.Http"],
        ["Keycloak.Admin.Sdk.FeatureManagement"] = ["Keycloak.Admin.Sdk", "Microsoft.FeatureManagement", "Microsoft.FeatureManagement.Telemetry.ApplicationInsights"]
    };
    foreach (var (id, expected) in dependencies)
    {
        await ScriptHost.RunCheckedAsync(root, "dotnet", ["pack", "src/" + id, "-c", "Release", "--no-build", "-o", feed], ct);
        using var package = ZipFile.OpenRead(Path.Combine(feed, $"{id}.{target.PackageVersion}.nupkg"));
        await using var content = package.Entries.Single(e => e.FullName.EndsWith(".nuspec", StringComparison.Ordinal)).Open();
        var manifest = await XDocument.LoadAsync(content, LoadOptions.None, ct);
        var actual = manifest.Descendants().Where(e => e.Name.LocalName == "dependency").Select(e => (string)e.Attribute("id")!);
        if (!expected.ToHashSet(StringComparer.OrdinalIgnoreCase).SetEquals(actual))
            throw new InvalidDataException($"Unexpected dependencies in {id}: {string.Join(", ", actual)}");
    }
    if (Directory.GetFiles(feed, "*.nupkg").Length != dependencies.Count)
        throw new InvalidDataException($"Expected exactly two SDK packages in {feed}.");
    if (args.Contains("--native-container"))
        await ScriptHost.RunCheckedAsync(root, "docker", ["build", .. target.DockerBuildArgs, "--build-context", "sdkpackages=" + feed, "-f", "tests/Keycloak.Admin.Sdk.AotSmoke/Dockerfile", "--target", "export",
            "--output", "type=local,dest=artifacts/aot/linux-musl-x64", "."], ct);
    else if (!args.Contains("--skip-native-publish"))
    {
        string rid = RuntimeInformation.RuntimeIdentifier;
        string output = "artifacts/aot/" + rid;
        await ScriptHost.RunCheckedAsync(root, "dotnet", ["publish", "tests/Keycloak.Admin.Sdk.AotSmoke", "-c", "Release", "-r", rid, "-p:SdkPackageFeed=" + feed, "-p:RestorePackagesPath=" + Path.Combine(root, testResults, "packages"), "-o", output], ct);
        string executable = Path.Combine(root, output, "Keycloak.Admin.Sdk.AotSmoke" + (OperatingSystem.IsWindows() ? ".exe" : ""));
        await ScriptHost.RunCheckedAsync(root, executable, [], ct);
    }
});
