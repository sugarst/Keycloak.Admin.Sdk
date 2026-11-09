using System.Security.Cryptography;
using System.Text;

internal static class LiveEvidence
{
    public static string Fingerprint(string root) => Fingerprint(root, false);
    // Promotion changes the generated support catalog, not the code/contract inputs under test.
    public static string ValidationFingerprint(string root) => Fingerprint(root, true);
    private static string Fingerprint(string root, bool validation)
    {
        string[] roots = ["src", "tests", "local/keycloak", "tools"];
        var paths = roots.SelectMany(p => Directory.EnumerateFiles(Path.Combine(root, p), "*", SearchOption.AllDirectories))
            .Where(p => !p.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar).Any(s => s is "bin" or "obj") && Path.GetExtension(p) is ".cs" or ".csproj" or ".yaml" or ".props" or ".json")
            .Concat(new[] { "global.json", "Directory.Build.props", "Keycloak.Admin.Sdk.slnx", "contracts/admin-api-routes.json", "contracts/baseline.json", "tests/Keycloak.Admin.Sdk.AotSmoke/Dockerfile", "tools/Shared/ScriptSupport.cs" }.Select(p => Path.Combine(root, p)))
            .Concat(new[] { "local/keycloak/kerberos/Dockerfile", "local/keycloak/kerberos/start.sh", "local/keycloak/kerberos/ticket.py" }.Select(p => Path.Combine(root, p)).Where(File.Exists))
            .Concat(new[] { "contracts/capabilities.json", "contracts/capability-rules.json", "Target.props", "tools/Shared/TargetBaseline.cs" }.Select(p => Path.Combine(root, p)))
            .Concat(Directory.EnumerateFiles(Path.Combine(root, "contracts"), "*.json"))
            .Append(Path.Combine(root, "contracts/source-files.sha256"))
            .Select(Path.GetFullPath)
            .Where(p => !validation || Path.GetRelativePath(root, p).Replace('\\', '/') is not ("contracts/capabilities.json" or "contracts/platform-capabilities.json" or "contracts/application-verification-profiles.json"))
            .Distinct(StringComparer.Ordinal)
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
