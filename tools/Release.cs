#!/usr/bin/env -S dotnet --
#:property TargetFramework=net10.0
#:property PublishAot=false
#:include ScriptSupport.cs
#:include TargetBaseline.cs
#:include ../tests/Keycloak.Admin.Sdk.IntegrationTests/LiveEvidence.cs
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Security.Cryptography;

return await ScriptHost.ExecuteAsync(args, "dotnet run --file tools/Release.cs -- [--bootstrap] (full acceptance; no publishing)", ["--bootstrap"], async ct =>
{
    string root = ScriptHost.RepositoryRoot(); var target = TargetBaseline.Load(root);
    var finalEnvironment = new Dictionary<string, string?> { ["KC_TEST_RELEASE_BOOTSTRAP"] = null };
    async Task Run(string script, params string[] options) => await ScriptHost.RunCheckedAsync(root, "dotnet", ["run", "--file", "tools/" + script, .. options.Length > 0 ? (string[])["--", .. options] : []], ct, environment: finalEnvironment);
    await Run("Check-Baseline.cs");
    await Run("Update-Contracts.cs");
    await Run("Test-Workflow.cs");
    await Run("Audit-Contracts.cs", "--online");
    await Run("Test-Fingerprint.cs");
    using (var catalog = JsonDocument.Parse(File.ReadAllText(Path.Combine(root, "contracts/capabilities.json"))))
    {
        bool provisional = catalog.RootElement.GetProperty("endpoints").EnumerateArray().Any(e => e.GetProperty("stage").GetString() is "Stable" or "Deprecated" && e.GetProperty("verification").GetString() != "Contract, Managed, NativeAot");
        if (provisional || args.Contains("--bootstrap"))
        {
            // Test-only wire acceptance establishes evidence before the support policy can allow a new target.
            // It is never sufficient for the final release gate; the guarded clients run again afterwards.
            await Run("Test-AllAdminRoutes.cs", "--bootstrap");
            await Run("Generate-CapabilityCatalog.cs", "--promote");
        }
    }
    await Run("Verify.cs", "--native-container");
    await Run("Test-AllAdminRoutes.cs", "--update-docs");
    await Run("Test-AcceptanceGate.cs", "--v1");
    await Run("Test-AcceptanceGate.cs", "--v2");
    await Run("Generate-ValidationList.cs");
    await Run("Check-FullAcceptance.cs");
    string fingerprint = LiveEvidence.Fingerprint(root);
    string output = ScriptHost.Within(root, "artifacts/releases/" + target.PackageVersion + "/" + fingerprint);
    Directory.CreateDirectory(output);
    var packages = new JsonArray();
    foreach (string id in new[] { "Keycloak.Admin.Sdk", "Keycloak.Admin.Sdk.Capabilities", "Keycloak.Admin.Sdk.DependencyInjection", "Keycloak.Admin.Sdk.FeatureManagement", "Keycloak.Admin.Sdk.FeatureManagement.ApplicationInsights" })
    {
        string filename = id + "." + target.PackageVersion + ".nupkg";
        string source = Path.Combine(root, "artifacts/packages", filename);
        if (!File.Exists(source)) throw new FileNotFoundException("Missing current-target package: " + filename);
        File.Copy(source, Path.Combine(output, filename), true);
        packages.Add(new JsonObject { ["file"] = filename, ["sha256"] = Convert.ToHexStringLower(SHA256.HashData(await File.ReadAllBytesAsync(source, ct))) });
    }
    foreach (string file in Directory.EnumerateFiles(Path.Combine(root, "docs/contracts/full-live-evidence"))) File.Copy(file, Path.Combine(output, Path.GetFileName(file)), true);
    foreach (string file in new[] { "contracts/baseline.json", "docs/contracts/test-coverage.md", "docs/contracts/full-live-acceptance.tsv", "docs/contracts/full-live-acceptance.md", "artifacts/test-matrix-summary.json" }) File.Copy(Path.Combine(root, file), Path.Combine(output, Path.GetFileName(file)), true);
    var manifest = new JsonObject { ["schemaVersion"] = 1, ["keycloakVersion"] = target.Version, ["packageVersion"] = target.PackageVersion, ["sourceCommit"] = target.Commit,
        ["sourceFingerprint"] = fingerprint, ["finishedUtc"] = DateTimeOffset.UtcNow.ToString("O"), ["packages"] = packages,
        ["acceptance"] = "managed + linux-musl-x64 Native AOT; FGAP v1 compatibility + v2 stable; final guarded clients", ["published"] = false };
    await File.WriteAllTextAsync(Path.Combine(output, "release-manifest.json"), manifest.ToJsonString(new JsonSerializerOptions { WriteIndented = true }), ct);
    Console.WriteLine("PASS release candidate: " + output + "; all gates passed; no Git or NuGet publication performed.");
});
