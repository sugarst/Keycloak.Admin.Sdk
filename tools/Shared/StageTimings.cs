using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;

internal sealed class StageTimings(string path) : IAsyncDisposable
{
    private readonly DateTimeOffset started = DateTimeOffset.UtcNow;
    private readonly Stopwatch total = Stopwatch.StartNew();
    private readonly List<Stage> stages = [];
    internal bool Completed { get; set; }

    internal async Task RunAsync(string name, Func<Task> run)
    {
        Console.WriteLine("START " + name);
        var watch = Stopwatch.StartNew();
        bool passed = false;
        try { await run(); passed = true; }
        finally
        {
            stages.Add(new(name, passed, watch.Elapsed.TotalSeconds));
            Console.WriteLine($"{(passed ? "PASS" : "FAIL")} {name}: {watch.Elapsed.TotalSeconds:F2}s");
        }
    }

    public async ValueTask DisposeAsync()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        var json = new JsonObject
        {
            ["startedUtc"] = started.ToString("O"), ["completed"] = Completed, ["totalSeconds"] = total.Elapsed.TotalSeconds,
            ["stages"] = new JsonArray(stages.Select(s => (JsonNode)new JsonObject
                { ["Name"] = s.Name, ["Passed"] = s.Passed, ["Seconds"] = s.Seconds }).ToArray())
        };
        await File.WriteAllTextAsync(path, json.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine($"Release elapsed: {total.Elapsed.TotalSeconds:F2}s; timings: {path}");
    }

    private sealed record Stage(string Name, bool Passed, double Seconds);
}
