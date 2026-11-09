#!/usr/bin/env -S dotnet --
#:property TargetFramework=net10.0
#:property PublishAot=false
#:include Shared/ScriptSupport.cs
#:include Shared/TargetBaseline.cs
#:include CapabilityEvidence.cs
#:include FeatureAcceptance.cs
#:include ../tests/Keycloak.Admin.Sdk.IntegrationTests/LiveEvidence.cs
#:include ../tests/Keycloak.Admin.Sdk.IntegrationTests/FeatureValidationPlan.cs
#:include ../tests/Keycloak.Admin.Sdk.IntegrationTests/KeycloakRouteSupport.cs
#:project ../src/Keycloak.Admin.Sdk/Keycloak.Admin.Sdk.csproj
using System.Text.Json.Nodes;

return await ScriptHost.ExecuteAsync(args, "dotnet run --file tools/Check-FeatureAcceptance.cs -- --evidence=<path> [--promote|--guarded] | --supported",
    ["--promote", "--guarded", "--supported", .. args.Where(a => a.StartsWith("--evidence=", StringComparison.Ordinal))], async ct =>
{
    string root = ScriptHost.RepositoryRoot();
    if (args.Contains("--supported"))
    {
        if (args.Length != 1) throw new ArgumentException("--supported cannot be combined with other options.");
        foreach (var item in FeatureAcceptance.Supported(root).DistinctBy(i => (i.Plan.Id, i.Route, i.Mode, i.Rid)))
        {
            string path = item.Plan.ResultPath(root, item.Route, item.Mode, item.Rid, true);
            FeatureAcceptance.Validate(root, JsonNode.Parse(await File.ReadAllTextAsync(path, ct))!.AsObject(), true);
        }
        Console.WriteLine("PASS guarded feature evidence for every supported non-stable runtime/route."); return;
    }
    if (args.Contains("--promote") && args.Contains("--guarded")) throw new ArgumentException("Promote candidate evidence first, then run guarded validation.");
    string evidence = Path.GetFullPath(args.Single(a => a.StartsWith("--evidence=", StringComparison.Ordinal))[11..], root);
    var report = JsonNode.Parse(await File.ReadAllTextAsync(evidence, ct))!.AsObject();
    var plan = FeatureAcceptance.Validate(root, report, args.Contains("--guarded"));
    if (args.Contains("--promote")) FeatureAcceptance.Promote(root, evidence);
    Console.WriteLine("PASS feature acceptance: " + plan.Id + "; " + (args.Contains("--promote") ? "selected runtime/route promoted; guarded rerun required" : "evidence verified"));
});
