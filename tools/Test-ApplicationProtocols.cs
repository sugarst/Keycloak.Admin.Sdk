#!/usr/bin/env -S dotnet --
#:property TargetFramework=net10.0
#:property PublishAot=false
#:include Shared/ScriptSupport.cs
#:include Shared/TargetBaseline.cs
#:include ProtocolTlsFixture.cs
#:include ProtocolKerberosFixture.cs
using System.Diagnostics;
using System.Security.Cryptography;

return await ScriptHost.ExecuteAsync(args, "dotnet run --file tools/Test-ApplicationProtocols.cs -- [--native-aot] [--hosting-only|--oidc-only|--assurance-only|--saml-only|--wallet-only|--authentication-only|--legacy|--support-only]", ["--native-aot", "--hosting-only", "--oidc-only", "--assurance-only", "--saml-only", "--wallet-only", "--authentication-only", "--legacy", "--support-only"], async ct =>
{
    string root = ScriptHost.RepositoryRoot(); var target = TargetBaseline.Load(root); bool native = args.Contains("--native-aot");
    if (native && (args.Contains("--hosting-only") || args.Contains("--saml-only"))) throw new ArgumentException("Hosting diagnostics require the Managed runtime.");
    bool legacy = args.Contains("--legacy");
    bool supportOnly = args.Contains("--support-only");
    if (args.Count(a => a is "--legacy" or "--support-only" or "--hosting-only" or "--oidc-only" or "--assurance-only" or "--saml-only" or "--wallet-only" or "--authentication-only") > 1) throw new ArgumentException("Choose one diagnostic or server profile.");
    if (legacy && args.Contains("--hosting-only")) throw new ArgumentException("Legacy compatibility is a separate server profile.");
    if (supportOnly && args.Contains("--hosting-only")) throw new ArgumentException("Choose a single diagnostic workflow.");
    Directory.CreateDirectory(Path.Combine(root, "artifacts/application-protocols"));
    if (!supportOnly) File.Delete(Path.Combine(root, "artifacts/application-protocols", (native ? "native-aot" : "managed") + (legacy ? "-legacy" : "") + ".json"));
    string output = supportOnly ? "artifacts/aot/application-support" : "artifacts/aot/application-protocols";
    string managedOutput = supportOnly ? "artifacts/application-support/managed" : "tests/Keycloak.Admin.Sdk.IntegrationTests/bin/Release/net10.0";
    if (native) await ScriptHost.RunCheckedAsync(root, "docker", ["build", .. target.DockerBuildArgs, "-f", "tests/Keycloak.Admin.Sdk.AotSmoke/Dockerfile",
        "--target", "integration-export", "--output", "type=local,dest=" + output, "."], ct);
    else await ScriptHost.RunCheckedAsync(root, "dotnet", ["build", "tests/Keycloak.Admin.Sdk.IntegrationTests", "-c", "Release", "--disable-build-servers", .. (supportOnly ? new[] { "-o", managedOutput } : [])], ct);
    string container = "keycloak-sdk-protocols-" + Guid.NewGuid().ToString("N"), child = container + "-native";
    string password = Convert.ToHexString(RandomNumberGenerator.GetBytes(24)) + "aA1!";
    await using var tls = await ProtocolTlsFixture.CreateAsync(root, ct);
    bool needsKerberos = !legacy && !supportOnly && args.All(a => a is "--native-aot" or "--authentication-only");
    await using var kerberos = needsKerberos ? await ProtocolKerberosFixture.CreateAsync(root, ct) : null;
    Console.WriteLine("Starting isolated Keycloak application profile: " + (legacy ? "legacy" : "standard"));
    var credentials = new Dictionary<string, string?> { ["KC_BOOTSTRAP_ADMIN_USERNAME"] = "admin", ["KC_BOOTSTRAP_ADMIN_PASSWORD"] = password };
    bool childAttempted = false, succeeded = false;
    try
    {
        await ScriptHost.RunCheckedAsync(root, "docker", ["run", "--detach", "--name", container, "-p", "127.0.0.1::8080", "-p", "127.0.0.1::9000", "-v", tls.DirectoryPath + ":/tls:ro",
            "--add-host", "api.twitter.com:127.0.0.1", "--add-host", "api.instagram.com:127.0.0.1", "--add-host", "graph.instagram.com:127.0.0.1",
            .. (kerberos is null ? Array.Empty<string>() : ["-v", kerberos.DirectoryPath + ":/kerberos:ro", "-e", "JAVA_OPTS_APPEND=-Djava.security.krb5.conf=/kerberos/krb5.conf"]), "-e", "KC_BOOTSTRAP_ADMIN_USERNAME",
            "-e", "KC_BOOTSTRAP_ADMIN_PASSWORD", target.ServerImage, "start-dev", legacy ? "--features=token-exchange:v1,admin-fine-grained-authz:v1,identity-brokering-api:v1" : "--features=token-exchange-delegation,parameterized-scopes,resource-indicators,jwt-authorization-grant,identity-assertion-jwt,cimd,authzen,client-admin-api:v2,openapi,docker,dpop,identity-brokering-api:v2,ssf,spiffe,oid4vc-vci,oid4vc-vci-preauth-code,oid4vc-vci-rest-credential-offer,oid4vc-mdoc,oid4vc-vp,client-auth-abca,transient-users,logout-all-sessions:v1,passkeys-conditional-ui-authenticator,instagram-broker", .. (legacy ? Array.Empty<string>() : ["--openapi-enabled=true"]),
            "--spi-ciba-auth-channel--ciba-http-auth-channel--http-authentication-channel-uri=http://127.0.0.1:18081/authenticate",
            "--spi-ssf-transmitter--default--allow-insecure-push-targets=true",
            "--spi-ssf-transmitter--default--outbox-drainer-interval=1s",
            "--https-certificate-file=/tls/server.pem", "--https-certificate-key-file=/tls/server.key", "--https-client-auth=request", "--truststore-paths=/tls/ca.pem", "--http-management-scheme=http"], ct, environment: credentials);
        if (kerberos is not null) await kerberos.StartAsync(container, ct);
        var binding = await ScriptHost.RunCheckedAsync(root, "docker", ["port", container, "8080/tcp"], ct, capture: true);
        string address = binding.StandardOutput.Trim();
        if (!address.StartsWith("127.0.0.1:", StringComparison.Ordinal) || !int.TryParse(address[10..], out int port)) throw new InvalidDataException("Protocol test must bind only to loopback.");
        var server = new Uri("http://127.0.0.1:" + port + "/");
        var managementBinding = await ScriptHost.RunCheckedAsync(root, "docker", ["port", container, "9000/tcp"], ct, capture: true);
        string managementAddress = managementBinding.StandardOutput.Trim();
        if (!managementAddress.StartsWith("127.0.0.1:", StringComparison.Ordinal) || !int.TryParse(managementAddress[10..], out int managementPort)) throw new InvalidDataException("OpenAPI management must bind only to loopback.");
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(2) };
        var watch = Stopwatch.StartNew(); bool ready = false;
        while (watch.Elapsed < TimeSpan.FromMinutes(2))
        {
            try { using var response = await http.GetAsync(new Uri(server, "realms/master/.well-known/openid-configuration"), ct); if (response.IsSuccessStatusCode) { ready = true; break; } }
            catch (HttpRequestException) { }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { }
            await Task.Delay(TimeSpan.FromSeconds(1), ct);
        }
        if (!ready) throw new TimeoutException("Protocol acceptance server did not become ready.");
        var environment = new Dictionary<string, string?> { ["KC_TEST_PROTOCOLS"] = "1", ["KC_TEST_URL"] = "http://127.0.0.1:8080/",
            ["KC_TEST_OPENAPI_URL"] = "http://127.0.0.1:9000/",
            ["KC_TEST_MTLS_DIRECTORY"] = tls.WorkspacePath,
            ["KC_TEST_KERBEROS_IMAGE_ID"] = kerberos?.ImageId,
            ["KC_TEST_PASSWORD"] = password, ["KC_TEST_USERNAME"] = "admin", ["KC_TEST_FEATURE"] = null, ["KC_TEST_FULL_ADMIN"] = null,
            ["KC_TEST_PROTOCOL_PROFILE"] = legacy ? "legacy" : "standard",
            ["KC_TEST_PROTOCOL_COMPONENT"] = supportOnly ? "support" : args.Contains("--hosting-only") ? "hosting" : args.Contains("--oidc-only") ? "oidc" : args.Contains("--saml-only") ? "saml" : args.Contains("--assurance-only") ? "assurance" : args.Contains("--wallet-only") ? "wallet" : args.Contains("--authentication-only") ? "authentication" : null };
        // Both runtimes share the isolated server's loopback network, so callback receivers are reachable without opening host listeners.
        childAttempted = true;
        await ScriptHost.RunCheckedAsync(root, "docker", ["run", "--rm", "--name", child, "--network", "container:" + container, "-v", root + ":/workspace", "-w", "/workspace",
                "-e", "KC_TEST_PROTOCOLS", "-e", "KC_TEST_URL", "-e", "KC_TEST_OPENAPI_URL", "-e", "KC_TEST_PASSWORD", "-e", "KC_TEST_USERNAME", "-e", "KC_TEST_PROTOCOL_COMPONENT", "-e", "KC_TEST_MTLS_DIRECTORY", "-e", "KC_TEST_PROTOCOL_PROFILE", "-e", "KC_TEST_KERBEROS_IMAGE_ID", target.NativeRuntimeImage,
                .. (native ? new[] { "/workspace/" + output + "/Keycloak.Admin.Sdk.IntegrationTests" }
                    : new[] { "dotnet", "/workspace/" + managedOutput + "/Keycloak.Admin.Sdk.IntegrationTests.dll" })], ct, environment: environment);
        succeeded = true;
    }
    finally
    {
        if (!succeeded)
        {
            using var diagnostic = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            try
            {
                var log = await ScriptHost.RunAsync(root, "docker", ["logs", "--tail", "100", container], diagnostic.Token, capture: true);
                foreach (var match in System.Text.RegularExpressions.Regex.Matches(log.StandardOutput + log.StandardError, "(?:type|error)=\\\"[A-Z_a-z]+\\\"")) Console.Error.WriteLine(match);
                if (args.Contains("--wallet-only") || args.Contains("--authentication-only"))
                    foreach (var match in System.Text.RegularExpressions.Regex.Matches(log.StandardOutput + log.StandardError, @"\bat org\.keycloak\.[A-Za-z0-9_.$]+\([A-Za-z0-9_.:]+\)")) Console.Error.WriteLine(match);
                if (args.Contains("--authentication-only"))
                    foreach (string failure in new[] { "Server not found in Kerberos database", "Checksum failed", "Replay", "Defective token", "Clock skew", "No valid credentials", "Cannot locate default realm", "Unsupported key type", "Invalid SPNEGO", "Cannot find key" })
                        if ((log.StandardOutput + log.StandardError).Contains(failure, StringComparison.Ordinal)) Console.Error.WriteLine("Kerberos diagnostic: " + failure);
            }
            catch (Exception error) { Console.Error.WriteLine("Protocol diagnostic unavailable: " + error.GetType().Name); }
        }
        var failures = new List<string>();
        foreach (string owned in childAttempted ? new[] { child, container } : [container])
        {
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            try
            {
                var result = await ScriptHost.RunAsync(root, "docker", ["rm", "--force", owned], cleanup.Token, capture: true);
                if (result.ExitCode != 0 && !result.StandardError.Contains("No such container", StringComparison.OrdinalIgnoreCase)) failures.Add(owned);
            }
            catch (Exception error) { failures.Add(owned + ": " + error.GetType().Name); }
        }
        if (failures.Count != 0)
        {
            if (succeeded) throw new IOException("Protocol acceptance container cleanup failed: " + string.Join(", ", failures));
            Console.Error.WriteLine("Protocol acceptance container cleanup failed: " + string.Join(", ", failures));
        }
    }
});
