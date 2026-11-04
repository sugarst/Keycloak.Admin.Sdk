#!/usr/bin/env -S dotnet --
#:property TargetFramework=net10.0
#:property PublishAot=false
#:include ScriptSupport.cs

using System.Formats.Tar;
using System.IO.Compression;
using System.Security.Cryptography;

return await ScriptHost.ExecuteAsync(args, "dotnet run --file tools/Update-Contracts.cs", [], async ct =>
{
    string root = ScriptHost.RepositoryRoot();
    string cache = Path.Combine(root, ".cache/keycloak");
    Directory.CreateDirectory(cache);
    using var baseline = ScriptHost.Baseline(root);
    var metadata = baseline.RootElement;
    string archive = Path.Combine(cache, "source.tar.gz");
    if (!File.Exists(archive))
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromMinutes(5) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("Keycloak.Admin.Sdk-contract-updater/1.0");
        using var response = await http.GetAsync("https://api.github.com/repos/keycloak/keycloak/tarball/" + metadata.GetProperty("keycloakVersion").GetString(), HttpCompletionOption.ResponseHeadersRead, ct);
        response.EnsureSuccessStatusCode();
        string partial = archive + ".partial";
        try
        {
            await using (var destination = File.Create(partial)) await response.Content.CopyToAsync(destination, ct);
            File.Move(partial, archive);
        }
        finally { if (File.Exists(partial)) File.Delete(partial); }
    }
    await VerifyHashAsync(archive, metadata.GetProperty("sourceArchiveSha256").GetString()!, ct);
    await VerifyHashAsync(Path.Combine(root, "contracts/keycloak-26.8.1.openapi.json"), metadata.GetProperty("openApiSha256").GetString()!, ct);
    string source = Path.Combine(cache, "pinned-source");
    Directory.CreateDirectory(source);
    await using (var compressed = File.OpenRead(archive))
    await using (var gzip = new GZipStream(compressed, CompressionMode.Decompress))
    await using (var tar = new TarReader(gzip))
    {
        while (await tar.GetNextEntryAsync(cancellationToken: ct) is { } entry)
        {
            if (entry.EntryType is not (TarEntryType.RegularFile or TarEntryType.V7RegularFile)) continue;
            int separator = entry.Name.IndexOf('/');
            if (separator < 0) continue;
            string relative = entry.Name[(separator + 1)..];
            if (!relative.EndsWith(".java", StringComparison.Ordinal) || !relative.Contains("/src/main/java/", StringComparison.Ordinal)) continue;
            string target = ScriptHost.Within(source, relative);
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            await using var destination = File.Create(target);
            if (entry.DataStream is not null) await entry.DataStream.CopyToAsync(destination, ct);
        }
    }
    await ScriptHost.RunCheckedAsync(root, "dotnet", ["run", "--project", "tools/Keycloak.Admin.Sdk.Generator", "--", root, source], ct);
});

static async Task VerifyHashAsync(string path, string expected, CancellationToken ct)
{
    await using var stream = File.OpenRead(path);
    string actual = Convert.ToHexStringLower(await SHA256.HashDataAsync(stream, ct));
    if (!actual.Equals(expected, StringComparison.Ordinal)) throw new InvalidDataException("SHA256 does not match the pinned baseline: " + Path.GetFileName(path));
}
