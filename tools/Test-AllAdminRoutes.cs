#!/usr/bin/env -S dotnet --
#:property TargetFramework=net10.0
#:property PublishAot=false
#:include ScriptSupport.cs

return await ScriptHost.ExecuteAsync(args, "dotnet run --file tools/Test-AllAdminRoutes.cs -- [--update-docs]", ["--update-docs"], async ct =>
{
    string root = ScriptHost.RepositoryRoot();
    var stable = new Dictionary<string, string?> { ["KEYCLOAK_ADMIN_API_ROUTE"] = "fgap-v2-stable" };
    try
    {
        foreach (string route in new[] { "fgap-v1-compat", "fgap-v2-stable" })
        {
            var environment = new Dictionary<string, string?> { ["KEYCLOAK_ADMIN_API_ROUTE"] = route };
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
