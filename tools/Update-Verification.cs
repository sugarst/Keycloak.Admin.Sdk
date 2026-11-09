#!/usr/bin/env -S dotnet --
#:property TargetFramework=net10.0
#:property PublishAot=false
#:include Shared/ScriptSupport.cs
#:include Shared/TargetBaseline.cs

return await ScriptHost.ExecuteAsync(args, "dotnet run --file tools/Update-Verification.cs", [], async ct =>
{
    string root = ScriptHost.RepositoryRoot();
    var routing = (await File.ReadAllLinesAsync(Path.Combine(root, "artifacts/routing-verified.tsv"), ct)).ToHashSet(StringComparer.Ordinal);
    string livePath = Path.Combine(root, "artifacts/live-endpoints.tsv");
    var live = new Dictionary<string, SortedSet<string>>(StringComparer.Ordinal);
    foreach (string line in await File.ReadAllLinesAsync(livePath, ct))
    {
        var fields = line.Split('\t');
        if (fields.Length != 3) throw new InvalidDataException("Expected method, path and status in live-endpoints.tsv.");
        string key = fields[0] + "\t" + fields[1];
        if (!live.TryGetValue(key, out var statuses)) live[key] = statuses = new(StringComparer.Ordinal);
        statuses.Add(fields[2]);
    }
    string inventory = Path.Combine(root, "docs/contracts/endpoint-inventory.md");
    string[] lines = await File.ReadAllLinesAsync(inventory, ct);
    string[] methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];
    for (int i = 0; i < lines.Length; i++)
    {
        string line = lines[i];
        if (!methods.Any(method => line.StartsWith("| " + method + " |", StringComparison.Ordinal))) continue;
        string[] columns = line.Split('|');
        if (columns.Length != 8) throw new InvalidDataException("Unexpected endpoint inventory columns.");
        string key = columns[1].Trim() + "\t" + columns[2].Trim().Trim('`');
        columns[5] = routing.Contains(key) ? " routing pass " : " pending ";
        columns[6] = live.TryGetValue(key, out var statuses) ? " HTTP " + string.Join(',', statuses) + " " : " pending ";
        lines[i] = string.Join('|', columns);
    }
    await File.WriteAllLinesAsync(inventory, lines, ct);
    File.Copy(livePath, Path.Combine(root, "docs/contracts/live-endpoints.tsv"), overwrite: true);
    Console.WriteLine($"Routing: {routing.Count}; live method/path observations: {live.Count}.");
});
