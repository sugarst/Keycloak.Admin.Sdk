using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

// Cache binaries only. Every caller still runs its own acceptance and writes fresh evidence.
internal static class IntegrationBuild
{
    internal static async Task PrepareAsync(string root, bool native, string destination, CancellationToken ct)
    {
        string mode = native ? "linux-musl-x64" : "managed-" + RuntimeInformation.RuntimeIdentifier;
        string Fingerprint() => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(
            LiveEvidence.Fingerprint(root) + "\n" + (native ? File.ReadAllText(Path.Combine(root, ".dockerignore")) : ""))));
        string executable = "Keycloak.Admin.Sdk.IntegrationTests" + (native ? "" : ".dll");
        string cached = await IntegrationBuildCache.GetAsync(root, mode, Fingerprint, executable, async (output, token) =>
        {
            if (native)
                await ScriptHost.RunCheckedAsync(root, "docker", ["build", .. TargetBaseline.Load(root).DockerBuildArgs,
                    "-f", "tests/Keycloak.Admin.Sdk.AotSmoke/Dockerfile", "--target", "integration-export",
                    "--output", "type=local,dest=" + output, "."], token);
            else
                await ScriptHost.RunCheckedAsync(root, "dotnet", ["build", "tests/Keycloak.Admin.Sdk.IntegrationTests", "-c", "Release", "-o", output], token);
        }, ct);

        // Preserve the existing public output paths used by evidence promotion and diagnostic commands.
        string target = ScriptHost.Within(root, destination);
        foreach (string source in Directory.EnumerateFiles(cached, "*", SearchOption.AllDirectories))
        {
            ct.ThrowIfCancellationRequested();
            string file = ScriptHost.Within(target, Path.GetRelativePath(cached, source));
            Directory.CreateDirectory(Path.GetDirectoryName(file)!);
            if (!File.Exists(file) || IntegrationBuildCache.Digest(file) != IntegrationBuildCache.Digest(source))
                File.Copy(source, file, true);
            if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(file, File.GetUnixFileMode(source));
        }
    }
}

internal static class IntegrationBuildCache
{
    internal static async Task<string> GetAsync(string root, string mode, Func<string> fingerprint, string executable,
        Func<string, CancellationToken, Task> build, CancellationToken ct)
    {
        string directory = ScriptHost.Within(root, "artifacts/integration-builds/" + mode);
        Directory.CreateDirectory(directory);
        // Serialize builders of the same runtime, including separate CLI invocations.
        await using var lease = await LockAsync(Path.Combine(directory, "build.lock"), ct);
        string input = fingerprint(), manifest = Path.Combine(directory, "manifest.json");
        var cached = Read(manifest);
        if (cached is not null && cached.Fingerprint == input && Guid.TryParseExact(cached.Output, "N", out _))
        {
            string output = ScriptHost.Within(directory, cached.Output);
            if (Valid(output, executable, cached.Files))
            {
                Console.WriteLine("CACHE HIT integration build: " + mode);
                return output;
            }
        }

        Console.WriteLine("CACHE MISS integration build: " + mode);
        // Failed or cancelled builds never replace a successful cache entry or mix with its files.
        string relative = Guid.NewGuid().ToString("N"), fresh = ScriptHost.Within(directory, relative);
        Directory.CreateDirectory(fresh);
        await build(fresh, ct);
        ct.ThrowIfCancellationRequested();
        if (fingerprint() != input) throw new InvalidDataException("Integration build inputs changed during compilation; retry with a stable working tree.");
        var files = Files(fresh);
        if (!files.ContainsKey(executable)) throw new FileNotFoundException("Integration build did not produce " + executable);
        string temporary = manifest + ".tmp";
        var json = new JsonObject { ["Fingerprint"] = input, ["Output"] = relative,
            ["Files"] = new JsonObject(files.Select(p => KeyValuePair.Create<string, JsonNode?>(p.Key, JsonValue.Create(p.Value)))) };
        await File.WriteAllTextAsync(temporary, json.ToJsonString(), ct);
        File.Move(temporary, manifest, true);
        return fresh;
    }

    internal static string Digest(string file)
    {
        using var stream = File.OpenRead(file);
        return Convert.ToHexStringLower(SHA256.HashData(stream));
    }

    private static Dictionary<string, string> Files(string directory) => Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories)
        .ToDictionary(p => Path.GetRelativePath(directory, p).Replace('\\', '/'), Digest, StringComparer.Ordinal);

    private static bool Valid(string output, string executable, Dictionary<string, string>? expected)
    {
        if (expected is null || !expected.ContainsKey(executable) || !Directory.Exists(output)) return false;
        try
        {
            var actual = Files(output);
            return actual.Count == expected.Count && actual.All(p => expected.TryGetValue(p.Key, out var hash) && p.Value == hash);
        }
        catch (IOException) { return false; }
    }

    private static Entry? Read(string path)
    {
        try
        {
            using var json = JsonDocument.Parse(File.ReadAllText(path));
            var entry = json.RootElement;
            if (entry.ValueKind != JsonValueKind.Object
                || !entry.TryGetProperty("Fingerprint", out var fingerprint) || fingerprint.ValueKind != JsonValueKind.String
                || !entry.TryGetProperty("Output", out var output) || output.ValueKind != JsonValueKind.String
                || !entry.TryGetProperty("Files", out var files) || files.ValueKind != JsonValueKind.Object) return null;
            var hashes = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var file in files.EnumerateObject())
                if (file.Value.ValueKind != JsonValueKind.String || !hashes.TryAdd(file.Name, file.Value.GetString()!)) return null;
            return new(fingerprint.GetString()!, output.GetString()!, hashes);
        }
        catch (IOException) { return null; }
        catch (JsonException) { return null; }
    }

    private static async Task<FileStream> LockAsync(string path, CancellationToken ct)
    {
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            try { return new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None); }
            catch (IOException) { await Task.Delay(100, ct); }
        }
    }

    private sealed record Entry(string Fingerprint, string Output, Dictionary<string, string> Files);
}
