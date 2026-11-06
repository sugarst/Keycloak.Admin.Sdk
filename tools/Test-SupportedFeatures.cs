#!/usr/bin/env -S dotnet --
#:property TargetFramework=net10.0
#:property PublishAot=false
#:include ScriptSupport.cs
#:include TargetBaseline.cs
#:include CapabilityEvidence.cs
#:include FeatureAcceptance.cs
#:include ../tests/Keycloak.Admin.Sdk.IntegrationTests/LiveEvidence.cs
#:include ../tests/Keycloak.Admin.Sdk.IntegrationTests/FeatureValidationPlan.cs
#:include ../tests/Keycloak.Admin.Sdk.IntegrationTests/KeycloakRouteSupport.cs
#:project ../src/Keycloak.Admin.Sdk/Keycloak.Admin.Sdk.csproj

return await ScriptHost.ExecuteAsync(args, "dotnet run --file tools/Test-SupportedFeatures.cs (isolated guarded acceptance for supported non-stable profiles)", [], async ct =>
{
    string root = ScriptHost.RepositoryRoot();
    foreach (var item in FeatureAcceptance.Supported(root).DistinctBy(i => (i.Plan.Id, i.Route, i.Mode, i.Rid)))
    {
        if (item.Mode == "native-aot" && item.Rid != "linux-musl-x64") throw new NotSupportedException("Provide an acceptance runner for the declared Native AOT RID: " + item.Rid);
        await ScriptHost.RunCheckedAsync(root, "dotnet", ["run", "--file", "tools/Test-Feature.cs", "--", "--feature=" + item.Plan.Id, "--guarded",
            .. item.Route == "fgap-v1-compat" ? new[] { "--v1" } : [], .. item.Mode == "native-aot" ? new[] { "--native-aot" } : []], ct);
    }
    await ScriptHost.RunCheckedAsync(root, "dotnet", ["run", "--file", "tools/Check-FeatureAcceptance.cs", "--", "--supported"], ct);
});
