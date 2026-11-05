#!/usr/bin/env -S dotnet --
#:property TargetFramework=net10.0
#:property PublishAot=false
#:include ScriptSupport.cs

using System.Security.Cryptography;
using System.Text.Json.Nodes;

return await ScriptHost.ExecuteAsync(args, "dotnet run --file tools/Test-AcceptanceGate.cs -- [--v1|--v2]", ["--v1", "--v2"], async ct =>
{
    if (args.Length > 1) throw new ArgumentException("Choose one route.");
    string root = ScriptHost.RepositoryRoot(), route = args.Contains("--v1") ? "fgap-v1-compat" : "fgap-v2-stable", flag = args.Contains("--v1") ? "--v1" : "--v2";
    await ScriptHost.RunCheckedAsync(root, "dotnet", ["run", "--file", "tools/Check-FullAcceptance.cs", "--", flag], ct);
    var cases = new (string Name, Action<JsonObject, List<string>> Mutate, string Error)[]
    {
        ("missing", (_, lines) => lines.RemoveAt(1), "Missing, altered or unsupported"),
        ("duplicate", (_, lines) => lines.Add(lines[1]), "Invalid or duplicate business proof"),
        ("failed-response", (_, lines) => { var f = lines[1].Split('\t'); f[2] = "403"; lines[1] = string.Join('\t', f); }, "Invalid or duplicate business proof"),
        ("empty-proof", (_, lines) => { var f = lines[1].Split('\t'); f[3] = ""; lines[1] = string.Join('\t', f); }, "Invalid or duplicate business proof"),
        ("extra-operation", (_, lines) => lines.Add("GET\t/admin/unsupported\t200\tfabricated row"), "Missing, altered or unsupported"),
        ("stale-source", (m, _) => m["sourceFingerprint"] = "stale", "Incomplete, wrong-server or stale"),
        ("incomplete", (m, _) => m["completed"] = false, "Incomplete, wrong-server or stale"),
        ("wrong-mode", (m, _) => m["mode"] = "not-native-or-managed", "Incomplete, wrong-server or stale"),
        ("bad-exclusions", (_, _) => { }, "Invalid exclusion ledger"),
        ("no-fgap-proof", (m, _) => m["evidence"]!["fgapDelegation"]!["revocationDenied"] = false, "FGAP delegation must be verified"),
        ("no-support-policy-proof", (m, _) => m["evidence"]!["supportPolicyLocalGuards"] = false, "Real acceptance must use the support policy")
    };
    string parent = "acceptance-gate-selftest-" + Guid.NewGuid().ToString("N");
    foreach (var test in cases)
    {
        string relative = parent + "/" + test.Name, directory = ScriptHost.Within(Path.Combine(root, "artifacts"), relative); Directory.CreateDirectory(directory);
        foreach (string path in Directory.EnumerateFiles(Path.Combine(root, "artifacts/full-live"), route + "-*")) File.Copy(path, Path.Combine(directory, Path.GetFileName(path)));
        string prefix = Path.Combine(directory, route + "-managed");
        var manifest = JsonNode.Parse(await File.ReadAllTextAsync(prefix + ".json", ct))!.AsObject();
        var lines = (await File.ReadAllLinesAsync(prefix + ".tsv", ct)).ToList();
        test.Mutate(manifest, lines);
        if (test.Name == "bad-exclusions")
        {
            string[] exclusions = await File.ReadAllLinesAsync(prefix + "-excluded.tsv", ct);
            exclusions[^1] = exclusions[1];
            await File.WriteAllLinesAsync(prefix + "-excluded.tsv", exclusions, ct);
        }
        await File.WriteAllLinesAsync(prefix + ".tsv", lines, ct);
        manifest["ledgerSha256"] = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(prefix + ".tsv", ct))).ToLowerInvariant();
        await File.WriteAllTextAsync(prefix + ".json", manifest.ToJsonString(), ct);
        var result = await ScriptHost.RunAsync(root, "dotnet", ["run", "--file", "tools/Check-FullAcceptance.cs", "--", flag, "--evidence=" + relative], ct, capture: true);
        if (result.ExitCode == 0 || !(result.StandardOutput + result.StandardError).Contains(test.Error, StringComparison.Ordinal)) throw new InvalidOperationException("Gate failed negative control: " + test.Name);
        Console.WriteLine("PASS full-acceptance gate negative control: " + test.Name);
    }
});
