#!/usr/bin/env -S dotnet --
#:property TargetFramework=net10.0
#:property PublishAot=false
#:include ScriptSupport.cs
#:include TargetBaseline.cs
#:include PlatformCoverage.cs
#:include ApplicationAcceptance.cs
#:include ../tests/Keycloak.Admin.Sdk.IntegrationTests/LiveEvidence.cs

return await ScriptHost.ExecuteAsync(args, "dotnet run --file tools/Generate-PlatformMatrix.cs -- [--check|--require-complete]",
    ["--check", "--require-complete"], async ct =>
{
    if (args.Length > 1) throw new ArgumentException("Choose one mode.");
    string root = ScriptHost.RepositoryRoot(); var result = PlatformCoverage.Generate(root);
    if (args.Contains("--require-complete") && !result.Complete)
        throw new InvalidDataException("Full application coverage is not achieved: protocol and host integration acceptance remains unpromoted. See docs/contracts/platform-capability-matrix.md.");
    foreach (var (path, text) in new[] { ("contracts/platform-capabilities.json", result.Json), ("docs/contracts/platform-capability-matrix.md", result.Markdown) })
    {
        if (args.Contains("--check"))
        { if (!File.Exists(Path.Combine(root, path)) || File.ReadAllText(Path.Combine(root, path)).Replace("\r\n", "\n", StringComparison.Ordinal) != text) throw new InvalidDataException("Stale platform capability matrix: " + path); }
        else await File.WriteAllTextAsync(Path.Combine(root, path), text, ct);
    }
    Console.WriteLine("PASS pinned platform inventory and explicit responsibility mappings; this does not assert full application support.");
});
