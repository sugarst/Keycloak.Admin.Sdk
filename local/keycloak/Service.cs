#!/usr/bin/env -S dotnet --
#:property TargetFramework=net10.0
#:property PublishAot=false
#:include ../../tools/ScriptSupport.cs
#:include ../../tools/TargetBaseline.cs
#:include ../../tests/Keycloak.Admin.Sdk.IntegrationTests/KeycloakRouteSupport.cs

using System.Diagnostics;
using System.Globalization;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

return await ScriptHost.ExecuteAsync(args,
    "dotnet run --file local/keycloak/Service.cs -- [up|check|status|logs|down|test|test-native|test-full|test-full-native|reset --delete-data] (default: up)",
    ["up", "check", "status", "logs", "down", "test", "test-native", "test-full", "test-full-native", "reset", "--delete-data"], async ct =>
{
    string action = args.FirstOrDefault() ?? "up";
    if (action == "reset" ? args.Length != 2 || args[1] != "--delete-data" : args.Length > 1 || action == "--delete-data")
        throw new ArgumentException("reset requires --delete-data; other commands accept no extra arguments.");
    string root = ScriptHost.RepositoryRoot();
    var target = TargetBaseline.Load(root);
    Environment.SetEnvironmentVariable("KEYCLOAK_SERVER_IMAGE", target.ServerImage);
    Environment.SetEnvironmentVariable("KEYCLOAK_TARGET_VERSION", target.Version);
    Environment.SetEnvironmentVariable("POSTGRES_IMAGE", target.PostgresImage);
    string directory = Path.Combine(root, "local/keycloak");
    string envPath = Path.Combine(directory, ".env");
    if (action is "up" or "test" or "test-native" or "test-full" or "test-full-native" or "reset") await InitializeAsync();
    if (!File.Exists(envPath)) throw new FileNotFoundException("Run Service.cs up first to initialize local credentials.");
    var settings = ReadSettings(envPath);
    string? dataTarget = ReadEnvironmentValue(envPath, "KEYCLOAK_DATA_TARGET_VERSION");
    if ((action is "up" or "check" || action.StartsWith("test", StringComparison.Ordinal)) && dataTarget is not null && dataTarget != target.Version)
        throw new InvalidDataException("Local database belongs to target " + dataTarget + "; choose an explicit backup/migration or reset --delete-data before using " + target.Version + ".");
    var route = KeycloakRoute.Load(root, Environment.GetEnvironmentVariable("KEYCLOAK_ADMIN_API_ROUTE") ?? ReadEnvironmentValue(envPath, "KEYCLOAK_ADMIN_API_ROUTE"));
    string declaredFeatures = string.Join(',', route.Features);
    string? manualFeatures = Environment.GetEnvironmentVariable("KEYCLOAK_FEATURES");
    if (manualFeatures is not null && manualFeatures != declaredFeatures) throw new InvalidDataException("KEYCLOAK_FEATURES conflicts with the selected declarative route; choose KEYCLOAK_ADMIN_API_ROUTE instead.");
    Environment.SetEnvironmentVariable("KEYCLOAK_ADMIN_API_ROUTE", route.Id);
    Environment.SetEnvironmentVariable("KEYCLOAK_FEATURES", declaredFeatures);
    if (action is "up" or "reset" || action.StartsWith("test", StringComparison.Ordinal))
    {
        var environmentLines = File.ReadAllLines(envPath).Where(l => !l.StartsWith("KEYCLOAK_ADMIN_API_ROUTE=", StringComparison.Ordinal) && !l.StartsWith("KEYCLOAK_FEATURES=", StringComparison.Ordinal)).ToList();
        environmentLines.Add("KEYCLOAK_ADMIN_API_ROUTE='" + route.Id + "'");
        environmentLines.Add("KEYCLOAK_FEATURES='" + declaredFeatures + "'");
        await File.WriteAllTextAsync(envPath, string.Join('\n', environmentLines) + "\n", ct);
    }
    Console.WriteLine($"Declared route: {route.Id}; FGAP v{route.FgapVersion}; compatibilityOnly={route.CompatibilityOnly}; preview=false; experimental=false.");
    string[] compose = ["compose", "--project-name", "keycloak-admin-sdk-local", "--project-directory", directory, "--env-file", envPath, "-f", Path.Combine(directory, "compose.yaml"),
        .. action.StartsWith("test-full", StringComparison.Ordinal) ? new[] { "-f", Path.Combine(directory, "compose.acceptance.yaml") } : [],
        .. OperatingSystem.IsLinux() ? new[] { "-f", Path.Combine(directory, "compose.linux.yaml") } : []];
    await ComposeAsync(["config", "--quiet"]);
    switch (action)
    {
        case "status": await ComposeAsync(["ps", "--all"]); return;
        case "logs": await ComposeAsync(["logs", "--tail", "100"]); return;
        case "down": await ComposeAsync(["down", "--remove-orphans"]); return;
        case "reset": await ComposeAsync(["down", "--volumes", "--remove-orphans"]); break;
    }
    if (action != "check") await ComposeAsync([.. action.StartsWith("test-full", StringComparison.Ordinal) ? new[] { "--profile", "acceptance" } : [], "up", "--detach", "--wait", "--wait-timeout", "180"]);
    await CheckAsync();
    if (action is "up" or "reset" || action.StartsWith("test", StringComparison.Ordinal))
    {
        var lines = File.ReadAllLines(envPath).Where(l => !l.StartsWith("KEYCLOAK_DATA_TARGET_VERSION=", StringComparison.Ordinal)).ToList();
        lines.Add("KEYCLOAK_DATA_TARGET_VERSION='" + target.Version + "'");
        await File.WriteAllTextAsync(envPath, string.Join('\n', lines) + "\n", ct);
    }
    if (action.StartsWith("test", StringComparison.Ordinal)) await TestAsync(action.EndsWith("native", StringComparison.Ordinal));

    async Task InitializeAsync()
    {
        if (File.Exists(envPath)) return;
        // A lost credential file must not silently generate incompatible credentials for an existing DB.
        var volume = await ScriptHost.RunAsync(root, "docker", ["volume", "inspect", "keycloak-admin-sdk-local_postgres_data"], ct, capture: true);
        if (volume.ExitCode == 0 && action != "reset")
            throw new InvalidOperationException("The local PostgreSQL volume exists but .env is missing. Restore .env, or explicitly use reset --delete-data to recreate this environment.");
        string Pick(string name, string fallback) => Environment.GetEnvironmentVariable(name) ?? fallback;
        string secret() => Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
        var values = new Dictionary<string, string>
        {
            ["POSTGRES_DB"] = Pick("POSTGRES_DB", "keycloak"), ["POSTGRES_USER"] = Pick("POSTGRES_USER", "keycloak"),
            ["POSTGRES_PASSWORD"] = Pick("POSTGRES_PASSWORD", secret()), ["POSTGRES_PORT"] = Pick("POSTGRES_PORT", "15432"),
            ["KEYCLOAK_ADMIN_USERNAME"] = Pick("KEYCLOAK_ADMIN_USERNAME", "admin"), ["KEYCLOAK_ADMIN_PASSWORD"] = Pick("KEYCLOAK_ADMIN_PASSWORD", secret()),
            ["KEYCLOAK_HTTP_PORT"] = Pick("KEYCLOAK_HTTP_PORT", "18080"), ["KEYCLOAK_MANAGEMENT_PORT"] = Pick("KEYCLOAK_MANAGEMENT_PORT", "19000"),
            ["KEYCLOAK_ADMIN_API_ROUTE"] = KeycloakRoute.Load(root).Id,
            ["KEYCLOAK_FEATURES"] = string.Join(',', KeycloakRoute.Load(root).Features)
        };
        // Single-quoted dotenv values preserve literal $ and #. Generated passwords are ASCII hex.
        if (values.Values.Any(v => v.IndexOfAny(['\r', '\n', '\'']) >= 0)) throw new ArgumentException("Local environment values cannot contain newlines or single quotes.");
        string content = "# Local credentials, generated once. Do not commit.\n" + string.Join('\n', values.Select(v => v.Key + "='" + v.Value + "'")) + "\n";
        await using (var file = new FileStream(envPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            await file.WriteAsync(Encoding.UTF8.GetBytes(content), ct);
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(envPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        Console.WriteLine("Created local/keycloak/.env with persistent local credentials (passwords not printed).");
    }
    Task<CommandResult> ComposeAsync(string[] arguments, bool capture = false) =>
        ScriptHost.RunCheckedAsync(root, "docker", [.. compose, .. arguments], ct, capture);

    async Task CheckAsync()
    {
        var running = await ComposeAsync(["ps", "--status", "running", "--quiet", "keycloak"], capture: true);
        if (string.IsNullOrWhiteSpace(running.StandardOutput)) throw new InvalidOperationException("Keycloak is not running. Use Service.cs up.");
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
        var watch = Stopwatch.StartNew();
        bool ready = false;
        while (watch.Elapsed < TimeSpan.FromMinutes(3))
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var health = await http.GetAsync(settings.Health, ct);
                if (health.IsSuccessStatusCode)
                {
                    using var body = JsonDocument.Parse(await health.Content.ReadAsStringAsync(ct));
                    if (body.RootElement.GetProperty("status").GetString() == "UP")
                    {
                        using var discovery = await http.GetAsync(new Uri(settings.Server, "realms/master/.well-known/openid-configuration"), ct);
                        if (discovery.IsSuccessStatusCode) { ready = true; break; }
                    }
                }
            }
            catch (HttpRequestException) { }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { }
            await Task.Delay(TimeSpan.FromSeconds(1), ct);
        }
        if (!ready) throw new TimeoutException("Keycloak readiness timed out. Inspect Service.cs logs.");
        using var grant = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "password", ["client_id"] = "admin-cli", ["username"] = settings.Admin, ["password"] = settings.Password
            });
        using var tokenReply = await http.PostAsync(new Uri(settings.Server, "realms/master/protocol/openid-connect/token"), grant, ct);
        if (!tokenReply.IsSuccessStatusCode) throw new InvalidOperationException($"Admin authentication failed ({(int)tokenReply.StatusCode}); an existing database retains its original credentials.");
        using var token = JsonDocument.Parse(await tokenReply.Content.ReadAsStringAsync(ct));
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(settings.Server, "admin/serverinfo"));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.RootElement.GetProperty("access_token").GetString());
        using var serverReply = await http.SendAsync(request, ct);
        serverReply.EnsureSuccessStatusCode();
        using var info = JsonDocument.Parse(await serverReply.Content.ReadAsStringAsync(ct));
        string? version = info.RootElement.GetProperty("systemInfo").GetProperty("version").GetString();
        if (version != target.Version) throw new InvalidDataException("Expected actual Keycloak server version " + target.Version + ", got " + version);
        route.ValidateServer(info.RootElement);
        var sql = await ComposeAsync(["exec", "-T", "postgres", "psql", "--no-psqlrc", "--username", settings.DbUser, "--dbname", settings.DbName,
            "--tuples-only", "--no-align", "--set", "ON_ERROR_STOP=1", "--command",
            "SELECT current_setting('server_version_num') || '|' || current_setting('data_directory') || '|' || (to_regclass('public.realm') IS NOT NULL)::text;"], capture: true);
        string[] fields = sql.StandardOutput.Trim().Split('|');
        if (fields.Length != 3 || fields[0] != target.PostgresVersionNumber || !fields[1].StartsWith("/var/lib/postgresql/18/", StringComparison.Ordinal) || fields[2] != "true")
            throw new InvalidDataException("Expected PostgreSQL 18.0, versioned PGDATA and an initialized Keycloak realm table.");
        Console.WriteLine($"PASS: Keycloak {target.Version} ready; PostgreSQL {target.PostgresVersionNumber} and persisted Keycloak schema verified; admin login and Admin API succeeded.");
        Console.WriteLine($"Admin console: {settings.Server}admin/  (user: {settings.Admin}; password: local/keycloak/.env)");
        Console.WriteLine($"Readiness: {settings.Health}");
    }

    async Task TestAsync(bool native)
    {
        var environment = new Dictionary<string, string?>
        {
            ["KC_TEST_URL"] = settings.Server.AbsoluteUri, ["KC_TEST_USERNAME"] = settings.Admin,
            ["KC_TEST_PASSWORD"] = settings.Password, ["KC_TEST_CALLBACK_HOST"] = "host.docker.internal"
        };
        environment["KC_TEST_FULL_ADMIN"] = action.StartsWith("test-full", StringComparison.Ordinal) ? "1" : null;
        environment["KC_TEST_LDAP_HOST"] = "127.0.0.1";
        environment["KC_TEST_LDAP_PORT"] = "1389";
        environment["KC_TEST_LDAP_PASSWORD"] = Environment.GetEnvironmentVariable("POSTGRES_PASSWORD") ?? ReadEnvironmentValue(envPath, "POSTGRES_PASSWORD")!;
        environment["KC_TEST_PG_HOST"] = "127.0.0.1";
        environment["KC_TEST_PG_PORT"] = Environment.GetEnvironmentVariable("POSTGRES_PORT") ?? ReadEnvironmentValue(envPath, "POSTGRES_PORT") ?? "15432";
        environment["KC_TEST_PG_USER"] = settings.DbUser;
        environment["KC_TEST_PG_DATABASE"] = settings.DbName;
        environment["KC_TEST_PG_PASSWORD"] = environment["KC_TEST_LDAP_PASSWORD"];
        environment["KEYCLOAK_ADMIN_API_ROUTE"] = route.Id;
        if (!native)
        {
            await ScriptHost.RunCheckedAsync(root, "dotnet", ["run", "--project", "tests/Keycloak.Admin.Sdk.IntegrationTests", "-c", "Release"], ct, environment: environment);
            return;
        }
        await ScriptHost.RunCheckedAsync(root, "docker", ["build", .. target.DockerBuildArgs, "-f", "tests/Keycloak.Admin.Sdk.AotSmoke/Dockerfile", "--target", "integration-export",
            "--output", "type=local,dest=artifacts/aot/integration", "."], ct);
        var server = await ComposeAsync(["ps", "--quiet", "keycloak"], capture: true);
        string container = "keycloak-sdk-local-test-" + Guid.NewGuid().ToString("N");
        environment["KC_TEST_URL"] = "http://127.0.0.1:8080/";
        environment["KC_TEST_CALLBACK_HOST"] = "127.0.0.1";
        environment["KC_TEST_LDAP_HOST"] = "ldap";
        environment["KC_TEST_LDAP_PORT"] = "389";
        environment["KC_TEST_PG_HOST"] = "postgres";
        environment["KC_TEST_PG_PORT"] = "5432";
        try
        {
            await ScriptHost.RunCheckedAsync(root, "docker", ["run", "--rm", "--name", container, "--network", "container:" + server.StandardOutput.Trim(),
                "-v", root + ":/workspace", "-w", "/workspace", "-e", "KC_TEST_RELEASE_BOOTSTRAP", "-e", "KC_TEST_URL", "-e", "KC_TEST_USERNAME", "-e", "KC_TEST_PASSWORD", "-e", "KC_TEST_CALLBACK_HOST", "-e", "KC_TEST_FULL_ADMIN", "-e", "KEYCLOAK_ADMIN_API_ROUTE", "-e", "KC_TEST_LDAP_HOST", "-e", "KC_TEST_LDAP_PORT", "-e", "KC_TEST_LDAP_PASSWORD", "-e", "KC_TEST_PG_HOST", "-e", "KC_TEST_PG_PORT", "-e", "KC_TEST_PG_USER", "-e", "KC_TEST_PG_DATABASE", "-e", "KC_TEST_PG_PASSWORD",
                target.NativeRuntimeImage, "/workspace/artifacts/aot/integration/Keycloak.Admin.Sdk.IntegrationTests"], ct, environment: environment);
        }
        finally
        {
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var removed = await ScriptHost.RunAsync(root, "docker", ["rm", "--force", container], cleanup.Token, capture: true);
            if (removed.ExitCode != 0 && !removed.StandardError.Contains("No such container", StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Could not remove this invocation's native test container: " + container);
        }
    }
});

static Settings ReadSettings(string path)
{
    var values = new Dictionary<string, string>(StringComparer.Ordinal);
    foreach (string line in File.ReadAllLines(path))
    {
        string trimmed = line.Trim(); if (trimmed.Length == 0 || trimmed.StartsWith('#')) continue;
        int separator = trimmed.IndexOf('=');
        if (separator < 1) throw new InvalidDataException("Expected KEY=value lines in local/keycloak/.env.");
        string value = trimmed[(separator + 1)..].Trim();
        if (value.Length >= 2 && (value[0] == '\'' && value[^1] == '\'' || value[0] == '"' && value[^1] == '"')) value = value[1..^1];
        values.Add(trimmed[..separator].Trim(), value);
    }
    string Get(string key, string fallback = "") => Environment.GetEnvironmentVariable(key) ?? values.GetValueOrDefault(key, fallback);
    int Port(string key, string fallback)
    {
        if (!int.TryParse(Get(key, fallback), NumberStyles.None, CultureInfo.InvariantCulture, out int value) || value is < 1 or > 65535)
            throw new InvalidDataException("Invalid port setting: " + key);
        return value;
    }
    string dbUser = Get("POSTGRES_USER", "keycloak"), dbName = Get("POSTGRES_DB", "keycloak");
    if (!Regex.IsMatch(dbUser, @"^[A-Za-z_][A-Za-z0-9_]*$") || !Regex.IsMatch(dbName, @"^[A-Za-z_][A-Za-z0-9_]*$")) throw new InvalidDataException("Use simple PostgreSQL database/user identifiers.");
    string password = Get("KEYCLOAK_ADMIN_PASSWORD");
    if (string.IsNullOrWhiteSpace(password) || string.IsNullOrWhiteSpace(Get("POSTGRES_PASSWORD"))) throw new InvalidDataException("Set both passwords in local/keycloak/.env.");
    return new(new Uri($"http://127.0.0.1:{Port("KEYCLOAK_HTTP_PORT", "18080")}/"),
        new Uri($"http://127.0.0.1:{Port("KEYCLOAK_MANAGEMENT_PORT", "19000")}/health/ready"), Get("KEYCLOAK_ADMIN_USERNAME", "admin"), password, dbName, dbUser);
}
static string? ReadEnvironmentValue(string path, string key) => File.ReadLines(path).Select(l => l.Trim()).Where(l => l.StartsWith(key + "=", StringComparison.Ordinal)).Select(l => l[(key.Length + 1)..].Trim().Trim('\'', '"')).LastOrDefault();
sealed record Settings(Uri Server, Uri Health, string Admin, string Password, string DbName, string DbUser);
