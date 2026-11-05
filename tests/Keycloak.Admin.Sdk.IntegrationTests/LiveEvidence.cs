using System.Security.Cryptography;
using System.Text;

internal static class LiveEvidence
{
    public static string Fingerprint(string root)
    {
        string[] roots = ["src", "tests/Keycloak.Admin.Sdk.IntegrationTests", "local/keycloak"];
        var paths = roots.SelectMany(p => Directory.EnumerateFiles(Path.Combine(root, p), "*", SearchOption.AllDirectories))
            .Where(p => !p.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar).Any(s => s is "bin" or "obj") && Path.GetExtension(p) is ".cs" or ".csproj" or ".yaml")
            .Concat(new[] { "global.json", "Directory.Build.props", "contracts/admin-api-routes.json", "contracts/baseline.json", "tests/Keycloak.Admin.Sdk.AotSmoke/Dockerfile", "tools/ScriptSupport.cs" }.Select(p => Path.Combine(root, p)))
            .Concat(Directory.EnumerateFiles(Path.Combine(root, "contracts/capabilities"), "*.json"))
            .OrderBy(p => Path.GetRelativePath(root, p).Replace('\\', '/'), StringComparer.Ordinal);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (string path in paths)
        {
            hash.AppendData(Encoding.UTF8.GetBytes(Path.GetRelativePath(root, path).Replace('\\', '/') + "\n"));
            hash.AppendData(Encoding.UTF8.GetBytes(File.ReadAllText(path).Replace("\r\n", "\n", StringComparison.Ordinal) + "\n"));
        }
        return Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
    }
}
