#!/usr/bin/env -S dotnet --
#:property TargetFramework=net10.0
#:property PublishAot=false
#:include Shared/ScriptSupport.cs
#:include Shared/TargetBaseline.cs
#:include CapabilityEvidence.cs
#:include FeatureAcceptance.cs
#:include ApplicationAcceptance.cs
#:include ../tests/Keycloak.Admin.Sdk.IntegrationTests/LiveEvidence.cs
#:include ../tests/Keycloak.Admin.Sdk.IntegrationTests/FeatureValidationPlan.cs
#:include ../tests/Keycloak.Admin.Sdk.IntegrationTests/KeycloakRouteSupport.cs
#:project ../src/Keycloak.Admin.Sdk/Keycloak.Admin.Sdk.csproj
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Security.Cryptography;

return await ScriptHost.ExecuteAsync(args, "dotnet run --file tools/Release.cs -- [--bootstrap] (full acceptance; no publishing)", ["--bootstrap"], async ct =>
{
    string root = ScriptHost.RepositoryRoot(); var target = TargetBaseline.Load(root);
    string sdkCommit = (await ScriptHost.RunCheckedAsync(root, "git", ["rev-parse", "HEAD"], ct, capture: true)).StandardOutput.Trim();
    bool sdkWorkingTreeDirty = !string.IsNullOrWhiteSpace((await ScriptHost.RunCheckedAsync(root, "git", ["status", "--porcelain", "--untracked-files=normal"], ct, capture: true)).StandardOutput);
    string initialFingerprint = LiveEvidence.Fingerprint(root);
    var finalEnvironment = new Dictionary<string, string?> { ["KC_TEST_RELEASE_BOOTSTRAP"] = null };
    async Task Run(string script, params string[] options) => await ScriptHost.RunCheckedAsync(root, "dotnet", ["run", "--file", "tools/" + script, .. options.Length > 0 ? (string[])["--", .. options] : []], ct, environment: finalEnvironment);
    await Run("Check-Baseline.cs");
    await Run("Generate-PlatformMatrix.cs", "--require-complete");
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
    await Run("Test-SupportedFeatures.cs");
    string fingerprint = LiveEvidence.Fingerprint(root);
    string output = ScriptHost.Within(root, "artifacts/releases/" + target.PackageVersion + "/" + fingerprint);
    Directory.CreateDirectory(output);
    var packages = new JsonArray();
    foreach (string id in new[] { "Keycloak.Admin.Sdk", "Keycloak.Admin.Sdk.Platform", "Keycloak.Admin.Sdk.Protocols", "Keycloak.Admin.Sdk.Hosting" })
    {
        string filename = id + "." + target.PackageVersion + ".nupkg";
        string source = Path.Combine(root, "artifacts/packages", target.PackageVersion, filename);
        if (!File.Exists(source)) throw new FileNotFoundException("Missing current-target package: " + filename);
        File.Copy(source, Path.Combine(output, filename), true);
        packages.Add(new JsonObject { ["id"] = id, ["file"] = filename, ["sha256"] = Convert.ToHexStringLower(SHA256.HashData(await File.ReadAllBytesAsync(source, ct))) });
    }
    foreach (string file in Directory.EnumerateFiles(Path.Combine(root, "docs/contracts/full-live-evidence"))) File.Copy(file, Path.Combine(output, Path.GetFileName(file)), true);
    foreach (string file in new[] { "contracts/baseline.json", "contracts/capabilities.json", "docs/contracts/test-coverage.md", "docs/contracts/full-live-acceptance.tsv", "docs/contracts/full-live-acceptance.md", "artifacts/test-matrix-summary.json" }) File.Copy(Path.Combine(root, file), Path.Combine(output, Path.GetFileName(file)), true);
    using var supportCatalog = JsonDocument.Parse(File.ReadAllText(Path.Combine(root, "contracts/capabilities.json")));
    foreach (var profile in supportCatalog.RootElement.GetProperty("verificationProfiles").EnumerateArray())
    {
        string relative = profile.GetProperty("evidence").GetString()!;
        string source = ScriptHost.Within(root, relative), destination = ScriptHost.Within(output, relative);
        if (CapabilityEvidence.Digest(source) != profile.GetProperty("evidenceSha256").GetString()) throw new InvalidDataException("Archived capability evidence hash mismatch.");
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!); File.Copy(source, destination, true);
    }
    foreach (var item in FeatureAcceptance.Supported(root).DistinctBy(i => (i.Plan.Id, i.Route, i.Mode, i.Rid)))
    {
        string path = item.Plan.ResultPath(root, item.Route, item.Mode, item.Rid, true);
        string destination = Path.Combine(output, "feature-acceptance", item.Plan.Id, Path.GetFileName(path));
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!); File.Copy(path, destination, true);
    }
    foreach (string relative in new[] { "contracts/platform-capabilities.json", "contracts/platform-coverage-rules.json", "contracts/application-validation-plans.json",
        "contracts/application-legacy-validation-plans.json", "contracts/application-verification-profiles.json", "docs/contracts/platform-capability-matrix.md",
        "docs/contracts/protocol-coverage.md", "docs/contracts/platform-coverage.md", "docs/contracts/hosting-coverage.md", "tests/module-coverage-policy.json", "docs/contracts/application-protocol-workflows.md", "docs/contracts/application-protocol-legacy-workflows.md",
        "docs/authentication-integration.md", "docs/wallet-integration.md" })
    {
        string destination = ScriptHost.Within(output, relative); Directory.CreateDirectory(Path.GetDirectoryName(destination)!); File.Copy(ScriptHost.Within(root, relative), destination, true);
    }
    var applicationProfiles = ApplicationAcceptance.CurrentProfiles(root);
    foreach (var profile in applicationProfiles)
    {
        string relative = profile!["evidence"]!.GetValue<string>();
        string source = ScriptHost.Within(root, relative), destination = ScriptHost.Within(output, relative);
        if (ApplicationAcceptance.Digest(source) != profile["evidenceSha256"]!.GetValue<string>()) throw new InvalidDataException("Archived application evidence hash mismatch.");
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!); File.Copy(source, destination, true);
    }
    var acceptanceRuns = new JsonArray();
    foreach (string route in new[] { "fgap-v2-stable", "fgap-v1-compat" })
        foreach (string mode in new[] { "managed", "native-aot" })
        {
            using var evidence = JsonDocument.Parse(File.ReadAllText(Path.Combine(output, route + "-" + mode + ".json")));
            var run = evidence.RootElement;
            acceptanceRuns.Add(new JsonObject { ["route"] = route, ["mode"] = mode,
                ["accepted"] = run.GetProperty("accepted").GetInt32(), ["expected"] = run.GetProperty("expected").GetInt32(),
                ["excluded"] = run.GetProperty("excluded").GetInt32() });
        }
    var manifest = new JsonObject { ["schemaVersion"] = 2, ["status"] = "local-candidate",
        ["keycloakVersion"] = target.Version, ["keycloakSourceCommit"] = target.Commit, ["packageVersion"] = target.PackageVersion,
        ["sdkCommit"] = sdkCommit, ["sdkWorkingTreeDirty"] = sdkWorkingTreeDirty || initialFingerprint != fingerprint,
        ["dotnetSdk"] = target.Sdk, ["sourceFingerprint"] = fingerprint, ["finishedUtc"] = DateTimeOffset.UtcNow.ToString("O"),
        ["packages"] = packages, ["allGatesPassed"] = true,
        ["capabilityCatalogSha256"] = CapabilityEvidence.Digest(Path.Combine(root, "contracts/capabilities.json")),
        ["verificationProfiles"] = JsonNode.Parse(supportCatalog.RootElement.GetProperty("verificationProfiles").GetRawText()),
        ["applicationCatalogSha256"] = ApplicationAcceptance.Digest(Path.Combine(root, "contracts/platform-capabilities.json")),
        ["applicationValidationFingerprint"] = LiveEvidence.ValidationFingerprint(root), ["applicationVerificationProfiles"] = applicationProfiles,
        ["acceptance"] = "managed + linux-musl-x64 Native AOT; FGAP v1 compatibility + v2 stable; final guarded clients",
        ["acceptanceRuns"] = acceptanceRuns, ["published"] = false };
    string json = manifest.ToJsonString(new JsonSerializerOptions { WriteIndented = true }) + "\n";
    await File.WriteAllTextAsync(Path.Combine(output, "release-manifest.json"), json, ct);
    string record = ScriptHost.Within(root, "docs/releases/" + target.PackageVersion + "/" + fingerprint + ".json");
    Directory.CreateDirectory(Path.GetDirectoryName(record)!);
    await File.WriteAllTextAsync(record, json, ct);
    Console.WriteLine("PASS release candidate: " + output + "; all gates passed; tracked record: " + record + "; no Git or NuGet publication performed.");
});
