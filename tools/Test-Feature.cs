#!/usr/bin/env -S dotnet --
#:property TargetFramework=net10.0
#:property PublishAot=false
#:include ScriptSupport.cs
#:include TargetBaseline.cs
#:include ../tests/Keycloak.Admin.Sdk.IntegrationTests/FeatureValidationPlan.cs
#:project ../src/Keycloak.Admin.Sdk/Keycloak.Admin.Sdk.csproj
using System.Diagnostics;
using System.Security.Cryptography;

return await ScriptHost.ExecuteAsync(args, "dotnet run --file tools/Test-Feature.cs -- --feature=client-types [--native-aot] [--v1] [--guarded]",
    ["--native-aot", "--v1", "--guarded", .. args.Where(a => a.StartsWith("--feature=", StringComparison.Ordinal))], async ct =>
{
    string root = ScriptHost.RepositoryRoot(); var target = TargetBaseline.Load(root);
    string id = args.Single(a => a.StartsWith("--feature=", StringComparison.Ordinal))[10..];
    var plan = FeatureValidationPlan.Load(root, id);
    bool native = args.Contains("--native-aot"); int version = args.Contains("--v1") ? 1 : 2;
    string route = version == 1 ? "fgap-v1-compat" : "fgap-v2-stable";
    File.Delete(plan.ResultPath(root, route, native ? "native-aot" : "managed", native ? "linux-musl-x64" : null, args.Contains("--guarded")));
    string nativeOutput = "artifacts/aot/feature-integration";
    if (native)
        await ScriptHost.RunCheckedAsync(root, "docker", ["build", .. target.DockerBuildArgs, "-f", "tests/Keycloak.Admin.Sdk.AotSmoke/Dockerfile", "--target", "integration-export", "--output", "type=local,dest=" + nativeOutput, "."], ct);
    var image = await ScriptHost.RunAsync(root, "docker", ["image", "inspect", target.ServerImage], ct, capture: true);
    if (image.ExitCode != 0) await ScriptHost.RunCheckedAsync(root, "docker", ["pull", target.ServerImage], ct);
    string container = "keycloak-sdk-feature-" + Guid.NewGuid().ToString("N"), child = container + "-native";
    string password = Convert.ToHexString(RandomNumberGenerator.GetBytes(24)) + "aA1!";
    var env = new Dictionary<string, string?> { ["KC_BOOTSTRAP_ADMIN_USERNAME"] = "admin", ["KC_BOOTSTRAP_ADMIN_PASSWORD"] = password };
    bool childAttempted = false, succeeded = false;
    try
    {
        string features = string.Join(',', new[] { "admin-fine-grained-authz:v" + version }.Concat(plan.ServerFeatures.Where(f => f != "ADMIN_API").Select(f => f.ToLowerInvariant().Replace('_', '-'))));
        await ScriptHost.RunCheckedAsync(root, "docker", ["run", "--pull=never", "--detach", "--rm", "--name", container, "-p", "127.0.0.1::8080",
            "-e", "KC_BOOTSTRAP_ADMIN_USERNAME", "-e", "KC_BOOTSTRAP_ADMIN_PASSWORD", target.ServerImage, "start-dev", "--features=" + features], ct, capture: true, environment: env);
        var binding = await ScriptHost.RunCheckedAsync(root, "docker", ["port", container, "8080/tcp"], ct, capture: true);
        string address = binding.StandardOutput.Trim();
        if (!address.StartsWith("127.0.0.1:", StringComparison.Ordinal) || !int.TryParse(address[10..], out int port)) throw new InvalidDataException("Expected a loopback-only feature test port.");
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(2) };
        var server = new Uri("http://127.0.0.1:" + port + "/"); var elapsed = Stopwatch.StartNew(); bool ready = false;
        while (elapsed.Elapsed < TimeSpan.FromMinutes(2))
        {
            try { using var response = await http.GetAsync(new Uri(server, "realms/master/.well-known/openid-configuration"), ct); if (response.IsSuccessStatusCode) { ready = true; break; } }
            catch (HttpRequestException) { }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { }
            await Task.Delay(TimeSpan.FromSeconds(1), ct);
        }
        if (!ready) throw new TimeoutException("Isolated feature server did not become ready.");
        var test = new Dictionary<string, string?> { ["KC_TEST_URL"] = native ? "http://127.0.0.1:8080/" : server.AbsoluteUri, ["KC_TEST_PASSWORD"] = password,
            ["KC_TEST_FEATURE"] = id, ["KC_TEST_FEATURE_GUARDED"] = args.Contains("--guarded") ? "1" : "0", ["KEYCLOAK_ADMIN_API_ROUTE"] = route, ["KC_TEST_FULL_ADMIN"] = null };
        if (native)
        {
            childAttempted = true;
            await ScriptHost.RunCheckedAsync(root, "docker", ["run", "--rm", "--name", child, "--network", "container:" + container, "-v", root + ":/workspace", "-w", "/workspace",
                "-e", "KC_TEST_URL", "-e", "KC_TEST_PASSWORD", "-e", "KC_TEST_FEATURE", "-e", "KC_TEST_FEATURE_GUARDED", "-e", "KEYCLOAK_ADMIN_API_ROUTE",
                target.NativeRuntimeImage, "/workspace/" + nativeOutput + "/Keycloak.Admin.Sdk.IntegrationTests"], ct, environment: test);
        }
        else await ScriptHost.RunCheckedAsync(root, "dotnet", ["run", "--project", "tests/Keycloak.Admin.Sdk.IntegrationTests", "-c", "Release"], ct, environment: test);
        succeeded = true;
    }
    finally
    {
        var failures = new List<string>();
        foreach (string owned in childAttempted ? new[] { child, container } : [container])
        {
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            try
            {
                var result = await ScriptHost.RunAsync(root, "docker", ["rm", "--force", owned], cleanup.Token, capture: true);
                if (result.ExitCode != 0 && !result.StandardError.Contains("No such container", StringComparison.OrdinalIgnoreCase)) failures.Add(owned);
            }
            catch (Exception error) { failures.Add(error.Message); }
        }
        if (failures.Count != 0)
        {
            if (succeeded) throw new IOException("Feature container cleanup failed: " + string.Join(", ", failures));
            Console.Error.WriteLine("Feature container cleanup failed: " + string.Join(", ", failures));
        }
    }
});
