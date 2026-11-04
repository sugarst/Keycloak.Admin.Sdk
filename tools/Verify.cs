#!/usr/bin/env -S dotnet --
#:property TargetFramework=net10.0
#:property PublishAot=false
#:include ScriptSupport.cs

using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Xml.Linq;

return await ScriptHost.ExecuteAsync(args,
    "dotnet run --file tools/Verify.cs -- [--skip-native-publish | --native-container]", ["--skip-native-publish", "--native-container"], async ct =>
{
    string root = ScriptHost.RepositoryRoot();
    if (args.Length > 1) throw new ArgumentException("Choose only one native verification option.");
    var legacyYaml = ScriptHost.RepositoryFiles(root).Where(file => Path.GetExtension(file).Equals(".yml", StringComparison.OrdinalIgnoreCase)).ToArray();
    if (legacyYaml.Length != 0)
        throw new InvalidDataException("Use .yaml for repository YAML files:\n" + string.Join('\n', legacyYaml.Select(file => Path.GetRelativePath(root, file))));
    foreach (string script in new[] { "Test-Integration.cs", "Update-Contracts.cs", "Update-Verification.cs", "Audit-Contracts.cs", "Generate-TestMatrix.cs", "Check-Coverage.cs" })
        await ScriptHost.RunCheckedAsync(root, "dotnet", ["build", "tools/" + script], ct);
    await ScriptHost.RunCheckedAsync(root, "dotnet", ["build", "local/keycloak/Service.cs"], ct);
    await ScriptHost.RunCheckedAsync(root, "dotnet", ["build", "Keycloak.Admin.Sdk.slnx", "-c", "Release"], ct);
    await ScriptHost.RunCheckedAsync(root, "dotnet", ["run", "--file", "tools/Generate-TestMatrix.cs", "--", "--check"], ct);
    await ScriptHost.RunCheckedAsync(root, "dotnet", ["run", "--file", "tools/Check-Coverage.cs", "--", "--self-test"], ct);
    // A fresh directory makes stale TRX/coverage evidence impossible to reuse accidentally.
    string testResults = "artifacts/test-results/verify-" + Guid.NewGuid().ToString("N");
    await ScriptHost.RunCheckedAsync(root, "dotnet", ["test", "tests/Keycloak.Admin.Sdk.Tests", "-c", "Release", "--no-build",
        "--logger", "trx;LogFileName=contracts.trx", "--results-directory", testResults, "--collect", "XPlat Code Coverage"], ct);
    await ScriptHost.RunCheckedAsync(root, "dotnet", ["run", "--file", "tools/Check-Coverage.cs", "--", "--results=" + testResults], ct);
    await File.WriteAllTextAsync(Path.Combine(root, "artifacts/test-results/latest.txt"), testResults, ct);
    await ScriptHost.RunCheckedAsync(root, "dotnet", ["pack", "src/Keycloak.Admin.Sdk", "-c", "Release", "--no-build", "-o", "artifacts/packages"], ct);
    string package = Directory.EnumerateFiles(Path.Combine(root, "artifacts/packages"), "Keycloak.Admin.Sdk.*.nupkg")
        .OrderByDescending(File.GetLastWriteTimeUtc).First();
    using (var archive = ZipFile.OpenRead(package))
    {
        await using var content = archive.Entries.Single(entry => entry.FullName.EndsWith(".nuspec", StringComparison.Ordinal)).Open();
        var manifest = await XDocument.LoadAsync(content, LoadOptions.None, ct);
        if (manifest.Descendants().Any(element => element.Name.LocalName == "dependency"))
            throw new InvalidDataException("SDK package must not have runtime NuGet dependencies.");
    }
    if (args.Contains("--native-container"))
        await ScriptHost.RunCheckedAsync(root, "docker", ["build", "-f", "tests/Keycloak.Admin.Sdk.AotSmoke/Dockerfile", "--target", "export",
            "--output", "type=local,dest=artifacts/aot/linux-musl-x64", "."], ct);
    else if (!args.Contains("--skip-native-publish"))
    {
        string rid = RuntimeInformation.RuntimeIdentifier;
        string output = "artifacts/aot/" + rid;
        await ScriptHost.RunCheckedAsync(root, "dotnet", ["publish", "tests/Keycloak.Admin.Sdk.AotSmoke", "-c", "Release", "-r", rid, "-o", output], ct);
        string executable = Path.Combine(root, output, "Keycloak.Admin.Sdk.AotSmoke" + (OperatingSystem.IsWindows() ? ".exe" : ""));
        await ScriptHost.RunCheckedAsync(root, executable, [], ct);
    }
});
