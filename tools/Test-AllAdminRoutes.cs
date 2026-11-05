#!/usr/bin/env -S dotnet --
#:property TargetFramework=net10.0
#:property PublishAot=false
#:include ScriptSupport.cs
#:include TargetBaseline.cs

return await ScriptHost.ExecuteAsync(args, "dotnet run --file tools/Test-AllAdminRoutes.cs -- [--update-docs|--bootstrap]", ["--update-docs", "--bootstrap"], async ct =>
{
    string root = ScriptHost.RepositoryRoot();
    if (args.Length > 1) throw new ArgumentException("Bootstrap evidence cannot be published as final evidence.");
    var stable = new Dictionary<string, string?> { ["KEYCLOAK_ADMIN_API_ROUTE"] = "fgap-v2-stable" };
    try
    {
        foreach (string route in new[] { "fgap-v1-compat", "fgap-v2-stable" })
        {
            var environment = new Dictionary<string, string?> { ["KEYCLOAK_ADMIN_API_ROUTE"] = route, ["KC_TEST_RELEASE_BOOTSTRAP"] = args.Contains("--bootstrap") ? "1" : null };
            foreach (string command in new[] { "test-full", "test-full-native" })
                await ScriptHost.RunCheckedAsync(root, "dotnet", ["run", "--file", "local/keycloak/Service.cs", "--", command], ct, environment: environment);
        }
        await ScriptHost.RunCheckedAsync(root, "dotnet", ["run", "--file", "tools/Check-FullAcceptance.cs", "--", .. args], ct);
    }
    finally
    {
        // Restore the ordinary stable-v2 service (without the X509 acceptance override).
        await ScriptHost.RunCheckedAsync(root, "dotnet", ["run", "--file", "local/keycloak/Service.cs", "--", "up"], CancellationToken.None, environment: stable);
    }
});
