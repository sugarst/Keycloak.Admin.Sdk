using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Text.Json;

internal static class ScriptHost
{
    public static string RepositoryRoot([CallerFilePath] string source = "")
    {
        var directory = new DirectoryInfo(Path.GetDirectoryName(source)!);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "Keycloak.Admin.Sdk.slnx")))
            directory = directory.Parent;
        return directory?.FullName ?? throw new DirectoryNotFoundException("Cannot locate the repository root.");
    }

    public static async Task<int> ExecuteAsync(string[] args, string usage, string[] allowedFlags, Func<CancellationToken, Task> action)
    {
        if (args is ["--help"] or ["-h"]) { Console.WriteLine(usage); return 0; }
        if (args.Any(arg => !allowedFlags.Contains(arg, StringComparer.Ordinal)) || args.Distinct(StringComparer.Ordinal).Count() != args.Length)
        {
            Console.Error.WriteLine(usage);
            return 2;
        }

        using var cancellation = new CancellationTokenSource();
        ConsoleCancelEventHandler onCancel = (_, e) => { e.Cancel = true; cancellation.Cancel(); };
        Console.CancelKeyPress += onCancel;
        try { await action(cancellation.Token); return 0; }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
        {
            Console.Error.WriteLine("Cancelled.");
            return 130;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine(error.Message);
            return 1;
        }
        finally { Console.CancelKeyPress -= onCancel; }
    }

    public static async Task<CommandResult> RunAsync(string root, string executable, IEnumerable<string> arguments,
        CancellationToken cancellationToken, bool capture = false, IReadOnlyDictionary<string, string?>? environment = null)
    {
        var start = new ProcessStartInfo(executable)
        {
            WorkingDirectory = root,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        foreach (var argument in arguments) start.ArgumentList.Add(argument);
        if (environment is not null)
            foreach (var (name, value) in environment)
                if (value is null) start.Environment.Remove(name); else start.Environment[name] = value;
        using var process = Process.Start(start) ?? throw new InvalidOperationException($"Cannot start {executable}.");
        var stdout = capture ? process.StandardOutput.ReadToEndAsync() : ForwardAsync(process.StandardOutput, Console.Out);
        var stderr = capture ? process.StandardError.ReadToEndAsync() : ForwardAsync(process.StandardError, Console.Error);
        try { await process.WaitForExitAsync(cancellationToken); }
        catch (OperationCanceledException)
        {
            try { if (!process.HasExited) process.Kill(entireProcessTree: true); }
            catch (InvalidOperationException) { }
            await process.WaitForExitAsync(CancellationToken.None);
            await Task.WhenAll(stdout, stderr);
            throw;
        }
        return new(process.ExitCode, await stdout, await stderr);
    }

    public static async Task<CommandResult> RunCheckedAsync(string root, string executable, IEnumerable<string> arguments,
        CancellationToken cancellationToken, bool capture = false, IReadOnlyDictionary<string, string?>? environment = null)
    {
        var result = await RunAsync(root, executable, arguments, cancellationToken, capture, environment);
        if (result.ExitCode != 0)
            throw new InvalidOperationException($"{executable} failed (exit {result.ExitCode})." + (capture ? "\n" + result.StandardError : ""));
        return result;
    }

    public static JsonDocument Baseline(string root) => JsonDocument.Parse(File.ReadAllText(Path.Combine(root, "contracts/baseline.json")));

    private static async Task<string> ForwardAsync(StreamReader source, TextWriter destination)
    {
        var buffer = new char[4096];
        int count;
        while ((count = await source.ReadAsync(buffer)) > 0)
        {
            await destination.WriteAsync(buffer.AsMemory(0, count));
            await destination.FlushAsync();
        }
        return "";
    }

    public static string Within(string directory, string relative)
    {
        string boundary = Path.GetFullPath(directory).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        string path = Path.GetFullPath(Path.Combine(boundary, relative));
        if (!path.StartsWith(boundary, OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
            throw new InvalidDataException("Path escapes its intended directory.");
        return path;
    }

    public static IEnumerable<string> RepositoryFiles(string root)
    {
        var excluded = new HashSet<string>([".git", ".cache", "artifacts", "bin", "obj", ".vs"], StringComparer.OrdinalIgnoreCase);
        var pending = new Stack<string>();
        pending.Push(root);
        while (pending.TryPop(out var directory))
        {
            foreach (var file in Directory.EnumerateFiles(directory)) yield return file;
            foreach (var child in Directory.EnumerateDirectories(directory))
                if (!excluded.Contains(Path.GetFileName(child)) && (File.GetAttributes(child) & FileAttributes.ReparsePoint) == 0)
                    pending.Push(child);
        }
    }
}

internal sealed record CommandResult(int ExitCode, string StandardOutput, string StandardError);
