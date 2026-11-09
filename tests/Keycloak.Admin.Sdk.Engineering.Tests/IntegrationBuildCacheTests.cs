using System.Text.Json;
using Microsoft.VisualStudio.TestTools.UnitTesting;

[TestClass]
public sealed class IntegrationBuildCacheTests
{
    [TestMethod]
    public async Task ReusesBinariesUntilSourceInputsChange()
    {
        using var fixture = new Fixture();
        string first = await fixture.Get();
        Assert.AreEqual(first, await fixture.Get());
        Assert.AreEqual(1, fixture.Builds);
        fixture.Fingerprint = "changed-contract-or-source";
        Assert.AreNotEqual(first, await fixture.Get());
        Assert.AreEqual(2, fixture.Builds);
    }

    [TestMethod]
    [DataRow("missing")]
    [DataRow("tampered")]
    [DataRow("extra")]
    public async Task RejectsIncompleteOrModifiedArtifacts(string mutation)
    {
        using var fixture = new Fixture();
        string first = await fixture.Get(), binary = Path.Combine(first, "integration.dll");
        if (mutation == "missing") File.Delete(binary);
        else if (mutation == "tampered") File.WriteAllText(binary, "different-binary");
        else File.WriteAllText(Path.Combine(first, "unexpected.dll"), "extra-dependency");
        Assert.AreNotEqual(first, await fixture.Get());
        Assert.AreEqual(2, fixture.Builds);
    }

    [TestMethod]
    [DataRow("not-json")]
    [DataRow("{}")]
    [DataRow("{\"Fingerprint\":\"initial\",\"Output\":\"../../outside\"}")]
    public async Task MalformedManifestForcesRebuild(string manifest)
    {
        using var fixture = new Fixture();
        await fixture.Get();
        File.WriteAllText(fixture.Manifest, manifest);
        await fixture.Get();
        Assert.AreEqual(2, fixture.Builds);
    }

    [TestMethod]
    public async Task FailedBuildLeavesPreviousSuccessfulCacheIntact()
    {
        using var fixture = new Fixture();
        string first = await fixture.Get();
        fixture.Fingerprint = "new-input";
        await Assert.ThrowsAsync<IOException>(() => fixture.Get((_, _) => throw new IOException("compiler failed")));
        fixture.Fingerprint = "initial";
        Assert.AreEqual(first, await fixture.Get());
        Assert.AreEqual(1, fixture.Builds);
    }

    [TestMethod]
    public async Task ChangedInputsDuringBuildCannotProduceCacheEntry()
    {
        using var fixture = new Fixture();
        await Assert.ThrowsAsync<InvalidDataException>(() => fixture.Get(async (output, ct) =>
        {
            await fixture.Build(output, ct);
            fixture.Fingerprint = "edited-during-build";
        }));
        Assert.IsFalse(File.Exists(fixture.Manifest));
        await fixture.Get();
        Assert.AreEqual(2, fixture.Builds);
    }

    [TestMethod]
    public async Task ConcurrentRequestsShareBuildAndLockWaitCanBeCancelled()
    {
        using var fixture = new Fixture();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var finish = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Task<string> first = fixture.Get(async (output, ct) =>
        {
            started.SetResult();
            await finish.Task.WaitAsync(ct);
            await fixture.Build(output, ct);
        }, timeout.Token);
        await started.Task.WaitAsync(timeout.Token);
        Task<string> second = fixture.Get(ct: timeout.Token);
        using var cancelled = new CancellationTokenSource();
        Task<string> third = fixture.Get(ct: cancelled.Token);
        cancelled.Cancel();
        await Assert.ThrowsAsync<OperationCanceledException>(() => third);
        finish.SetResult();
        Assert.AreEqual(await first, await second);
        Assert.AreEqual(1, fixture.Builds);
    }

    [TestMethod]
    public async Task CancelledAndMissingExecutableBuildsAreNeverCached()
    {
        using var fixture = new Fixture();
        using var cancelled = new CancellationTokenSource();
        await Assert.ThrowsAsync<OperationCanceledException>(() => fixture.Get(async (output, ct) =>
        {
            await fixture.Build(output, ct);
            cancelled.Cancel();
        }, cancelled.Token));
        Assert.IsFalse(File.Exists(fixture.Manifest));
        await Assert.ThrowsAsync<FileNotFoundException>(() => fixture.Get((_, _) => Task.CompletedTask));
        Assert.IsFalse(File.Exists(fixture.Manifest));
        await fixture.Get();
    }

    [TestMethod]
    public async Task FailedStageStillWritesTimingReport()
    {
        using var fixture = new Fixture();
        string report = Path.Combine(fixture.Root, "timings.json");
        await using (var timings = new StageTimings(report))
            await Assert.ThrowsAsync<IOException>(() => timings.RunAsync("compile", () => throw new IOException("failed")));
        using var json = JsonDocument.Parse(File.ReadAllText(report));
        Assert.IsFalse(json.RootElement.GetProperty("completed").GetBoolean());
        var stage = json.RootElement.GetProperty("stages")[0];
        Assert.AreEqual("compile", stage.GetProperty("Name").GetString());
        Assert.IsFalse(stage.GetProperty("Passed").GetBoolean());
    }

    private sealed class Fixture : IDisposable
    {
        internal string Root { get; } = Path.Combine(Path.GetTempPath(), "keycloak-build-cache-" + Guid.NewGuid().ToString("N"));
        internal string Fingerprint { get; set; } = "initial";
        internal int Builds { get; private set; }
        internal string Manifest => Path.Combine(Root, "artifacts/integration-builds/test/manifest.json");
        internal Task<string> Get(Func<string, CancellationToken, Task>? build = null, CancellationToken ct = default) =>
            IntegrationBuildCache.GetAsync(Root, "test", () => Fingerprint, "integration.dll", build ?? Build, ct);
        internal async Task Build(string output, CancellationToken ct)
        {
            Builds++;
            await File.WriteAllTextAsync(Path.Combine(output, "integration.dll"), "binary-" + Builds, ct);
            await File.WriteAllTextAsync(Path.Combine(output, "dependency.dll"), "dependency", ct);
        }
        public void Dispose() { if (Directory.Exists(Root)) Directory.Delete(Root, true); }
    }
}
