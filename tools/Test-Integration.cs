#!/usr/bin/env -S dotnet --
#:property TargetFramework=net10.0
#:property PublishAot=false
#:include Shared/ScriptSupport.cs
#:include Shared/TargetBaseline.cs
#:include Shared/IntegrationBuild.cs
#:include ../tests/Keycloak.Admin.Sdk.IntegrationTests/LiveEvidence.cs

using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;

return await ScriptHost.ExecuteAsync(args,
    "dotnet run --file tools/Test-Integration.cs -- [--native-aot] [--no-build-native] [--upgrade-regressions]",
    ["--native-aot", "--no-build-native", "--upgrade-regressions"], async ct =>
{
    string root = ScriptHost.RepositoryRoot();
    bool native = args.Contains("--native-aot");
    bool skipBuild = args.Contains("--no-build-native");
    bool upgradeRegressions = args.Contains("--upgrade-regressions");
    if (skipBuild && !native) throw new ArgumentException("--no-build-native requires --native-aot.");
    if (native && !skipBuild)
        await IntegrationBuild.PrepareAsync(root, true, "artifacts/aot/integration", ct);
    if (native && !File.Exists(Path.Combine(root, "artifacts/aot/integration/Keycloak.Admin.Sdk.IntegrationTests")))
        throw new FileNotFoundException("Build the Native AOT integration executable before using --no-build-native.");

    string image = TargetBaseline.Load(root).ServerImage;
    var inspected = await ScriptHost.RunAsync(root, "docker", ["image", "inspect", image, "--format", "{{json .}}"], ct, capture: true);
    if (inspected.ExitCode != 0)
    {
        if (upgradeRegressions) throw new InvalidOperationException("The upgrade regressions require the pinned Keycloak image locally: " + image);
        await ScriptHost.RunCheckedAsync(root, "docker", ["pull", image], ct);
        inspected = await ScriptHost.RunCheckedAsync(root, "docker", ["image", "inspect", image, "--format", "{{json .}}"], ct, capture: true);
    }
    string imageId;
    using (var localImage = JsonDocument.Parse(inspected.StandardOutput))
    {
        if (!localImage.RootElement.GetProperty("RepoDigests").EnumerateArray().Any(d => d.GetString() == image))
            throw new InvalidDataException("The local Keycloak image does not match the target digest.");
        imageId = localImage.RootElement.GetProperty("Id").GetString()!;
    }
    Console.WriteLine($"Using verified local image {image} ({imageId}).");
    string container = "keycloak-sdk-test-" + Guid.NewGuid().ToString("N");
    string nativeContainer = container + "-native";
    string password = Convert.ToHexString(RandomNumberGenerator.GetBytes(24)) + "aA1!";
    var bootstrap = new Dictionary<string, string?> { ["KC_BOOTSTRAP_ADMIN_USERNAME"] = "admin", ["KC_BOOTSTRAP_ADMIN_PASSWORD"] = password };
    // This name belongs exclusively to this invocation, including failed Docker starts.
    bool attempted = false;
    bool attemptedNative = false;
    bool succeeded = false;
    try
    {
        attempted = true;
        var runArguments = new List<string> { "run", "--pull=never", "--detach", "--rm", "--name", container,
            "-p", "127.0.0.1::8080", "-e", "KC_BOOTSTRAP_ADMIN_USERNAME", "-e", "KC_BOOTSTRAP_ADMIN_PASSWORD",
        };
        if (OperatingSystem.IsLinux()) runArguments.AddRange(["--add-host", "host.docker.internal:host-gateway"]);
        runArguments.AddRange([imageId, "start-dev", "--features=admin-fine-grained-authz:v2,workflows"]);
        await ScriptHost.RunCheckedAsync(root, "docker", runArguments, ct, capture: true, environment: bootstrap);
        var binding = await ScriptHost.RunCheckedAsync(root, "docker", ["port", container, "8080/tcp"], ct, capture: true);
        string address = binding.StandardOutput.Trim();
        if (!address.StartsWith("127.0.0.1:", StringComparison.Ordinal) || !int.TryParse(address[10..], NumberStyles.None, CultureInfo.InvariantCulture, out int port))
            throw new InvalidDataException("Docker did not return a loopback test port.");
        var server = new Uri($"http://127.0.0.1:{port}/");
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(2) };
        var elapsed = Stopwatch.StartNew();
        bool ready = false;
        while (elapsed.Elapsed < TimeSpan.FromSeconds(90))
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var response = await http.GetAsync(new Uri(server, "realms/master/.well-known/openid-configuration"), ct);
                if (response.IsSuccessStatusCode) { ready = true; break; }
            }
            catch (HttpRequestException) { }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { }
            await Task.Delay(TimeSpan.FromSeconds(1), ct);
        }
        if (!ready)
        {
            await ScriptHost.RunAsync(root, "docker", ["logs", container], ct);
            throw new TimeoutException("Keycloak startup timed out.");
        }
        var testEnvironment = new Dictionary<string, string?> { ["KC_TEST_PASSWORD"] = password, ["KC_TEST_URL"] = server.AbsoluteUri,
            ["KC_TEST_CALLBACK_HOST"] = "host.docker.internal", ["KC_TEST_UPGRADE_REGRESSIONS"] = upgradeRegressions ? "1" : null };
        if (native)
        {
            testEnvironment["KC_TEST_URL"] = "http://127.0.0.1:8080/";
            testEnvironment["KC_TEST_CALLBACK_HOST"] = "127.0.0.1";
            attemptedNative = true;
            await ScriptHost.RunCheckedAsync(root, "docker", ["run", "--rm", "--name", nativeContainer, "--network", "container:" + container,
                "-v", root + ":/workspace", "-w", "/workspace", "-e", "KC_TEST_PASSWORD", "-e", "KC_TEST_URL", "-e", "KC_TEST_CALLBACK_HOST", "-e", "KC_TEST_UPGRADE_REGRESSIONS",
                TargetBaseline.Load(root).NativeRuntimeImage, "/workspace/artifacts/aot/integration/Keycloak.Admin.Sdk.IntegrationTests"], ct, environment: testEnvironment);
        }
        else
            await ScriptHost.RunCheckedAsync(root, "dotnet", ["run", "--project", "tests/Keycloak.Admin.Sdk.IntegrationTests", "-c", "Release"], ct, environment: testEnvironment);
        succeeded = true;
    }
    catch
    {
        if (attempted)
        {
            using var logs = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            await ScriptHost.RunAsync(root, "docker", ["logs", "--tail", "80", container], logs.Token);
        }
        throw;
    }
    finally
    {
        if (attempted)
        {
            // Cleanup is independent of Ctrl+C so this invocation's ephemeral container is removed.
            var failures = new List<string>();
            foreach (string owned in attemptedNative ? new[] { nativeContainer, container } : [container])
            {
                try
                {
                    using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(30));
                    var removed = await ScriptHost.RunAsync(root, "docker", ["rm", "--force", owned], cleanup.Token, capture: true);
                    if (removed.ExitCode != 0 && !removed.StandardError.Contains("No such container", StringComparison.OrdinalIgnoreCase)) failures.Add(owned);
                }
                catch (Exception error) { failures.Add(owned + ": " + error.Message); }
            }
            if (failures.Count > 0)
            {
                string message = "Could not remove this run's test containers: " + string.Join(", ", failures);
                if (succeeded) throw new InvalidOperationException(message);
                Console.Error.WriteLine(message);
            }
        }
    }
});
