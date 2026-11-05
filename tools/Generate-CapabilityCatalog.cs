#!/usr/bin/env -S dotnet --
#:property TargetFramework=net10.0
#:property PublishAot=false
#:include ScriptSupport.cs
#:project ../src/Keycloak.Admin.Sdk/Keycloak.Admin.Sdk.csproj
using System.Text.Json;
using System.Text.Json.Nodes;
using Keycloak.Admin.Sdk;

return await ScriptHost.ExecuteAsync(args, "dotnet run --file tools/Generate-CapabilityCatalog.cs -- [--check]", ["--check"], async ct =>
{
    string root = ScriptHost.RepositoryRoot();
    var live = File.ReadAllLines(Path.Combine(root, "docs/contracts/full-live-acceptance.tsv")).Skip(1).Select(l => l.Split('\t')).ToDictionary(f => f[0] + " " + f[1]);
    using var baseline = ScriptHost.Baseline(root);
    if (baseline.RootElement.GetProperty("keycloakVersion").GetString() != "26.8.1") throw new InvalidDataException("Add a reviewed version snapshot; never overwrite 26.8.1 for a new release.");
    if (live.Count != AdminEndpointCatalog.All.Count) throw new InvalidDataException("Incomplete acceptance inventory.");
    var entries = new JsonArray();
    foreach (var endpoint in AdminEndpointCatalog.All)
    {
        string path = endpoint.Path;
        (string Id, string Stage, string Server) feature = path.Contains("/ssf/", StringComparison.Ordinal) ? ("KeycloakSdk.Ssf", "Experimental", "SSF")
            : path.Contains("/vc/", StringComparison.Ordinal) ? ("KeycloakSdk.Oid4vcVci", "Preview", "OID4VC_VCI")
            : path.EndsWith("/client-types", StringComparison.Ordinal) ? ("KeycloakSdk.ClientTypes", "Experimental", "CLIENT_TYPES")
            : path.EndsWith("/management/permissions", StringComparison.Ordinal) || path.EndsWith("/users-management-permissions", StringComparison.Ordinal) ? ("KeycloakSdk.FgapV1", "Deprecated", "ADMIN_FINE_GRAINED_AUTHZ")
            : path.Contains("/authz/", StringComparison.Ordinal) ? ("KeycloakSdk.Authorization", "Stable", "AUTHORIZATION")
            : path.Contains("/organizations", StringComparison.Ordinal) ? ("KeycloakSdk.Organizations", "Stable", "ORGANIZATION")
            : path.Contains("/workflows", StringComparison.Ordinal) ? ("KeycloakSdk.Workflows", "Stable", "WORKFLOWS")
            : path.Contains("/ui-ext", StringComparison.Ordinal) ? ("KeycloakSdk.AdminUi", "Stable", "ADMIN_V2")
            : path.Contains("/client-policies/", StringComparison.Ordinal) ? ("KeycloakSdk.ClientPolicies", "Stable", "CLIENT_POLICIES")
            : path.EndsWith("/impersonation", StringComparison.Ordinal) ? ("KeycloakSdk.Impersonation", "Stable", "IMPERSONATION")
            : ("KeycloakSdk.AdminApi", "Stable", "ADMIN_API");
        var proof = live[endpoint.Method + " " + path];
        bool verified = proof[4].StartsWith("PASS ", StringComparison.Ordinal) && proof[5].StartsWith("PASS ", StringComparison.Ordinal);
        bool stable = feature.Stage == "Stable" || feature.Stage == "Deprecated";
        if (verified != stable) throw new InvalidDataException("Review capability evidence: " + path);
        if (feature.Stage == "Stable" && (!proof[2].StartsWith("PASS ", StringComparison.Ordinal) || !proof[3].StartsWith("PASS ", StringComparison.Ordinal))) throw new InvalidDataException("Stable capability requires both routes and both execution modes: " + path);
        entries.Add(new JsonObject { ["operation"] = endpoint.Operation, ["method"] = endpoint.Method, ["path"] = path, ["featureId"] = feature.Id,
            ["stage"] = feature.Stage, ["implementation"] = "Implemented", ["support"] = !verified ? "NotSupported" : feature.Stage == "Deprecated" ? "Compatibility" : "Supported",
            ["routes"] = feature.Stage == "Deprecated" ? new JsonArray("FgapV1Compatibility") : new JsonArray("FgapV2Stable", "FgapV1Compatibility"),
            ["verification"] = verified ? "Contract, Managed, NativeAot" : "Contract", ["requiredServerFeatures"] = new JsonArray(new[] { "ADMIN_API", feature.Server }.Distinct().Select(s => (JsonNode?)JsonValue.Create(s)).ToArray()),
            ["evidence"] = verified ? "docs/contracts/full-live-acceptance.tsv#" + endpoint.Method + " " + path : "contracts/admin-api-test-matrix.json; no real acceptance" });
    }
    var manifest = new JsonObject { ["schemaVersion"] = 1, ["serverVersion"] = baseline.RootElement.GetProperty("keycloakVersion").GetString(), ["sourceCommit"] = baseline.RootElement.GetProperty("commit").GetString(), ["endpoints"] = entries };
    string output = manifest.ToJsonString(new JsonSerializerOptions { WriteIndented = true }).Replace("\r\n", "\n", StringComparison.Ordinal) + "\n";
    string file = Path.Combine(root, "contracts/capabilities/26.8.1.json");
    if (args.Contains("--check")) { if (File.ReadAllText(file).Replace("\r\n", "\n", StringComparison.Ordinal) != output) throw new InvalidDataException("Capability snapshot is stale."); }
    else { Directory.CreateDirectory(Path.GetDirectoryName(file)!); await File.WriteAllTextAsync(file, output, ct); }
    Console.WriteLine("Capability snapshot: " + entries.Count + " operations; release metadata and verification status remain independent.");
});
