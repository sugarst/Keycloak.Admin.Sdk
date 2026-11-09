using System.Text;

namespace Keycloak.Admin.Sdk.Protocols;

/// <summary>Reads a host-configured projected Kubernetes or workload JWT file afresh for each request, including atomic token rotation.
/// The filename is trusted startup configuration, never a request parameter. Keycloak validates the federation trust and token claims.</summary>
public sealed class ProjectedWorkloadToken
{
    private readonly string path;
    public ProjectedWorkloadToken(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (!Path.IsPathFullyQualified(path)) throw new ArgumentException("An absolute host-configured token filename is required.", nameof(path));
        this.path = path;
    }
    public async ValueTask<string> ReadAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        // Permit an orchestrator's atomic replacement. Never retain an open handle or cache a user's/workload's old credential.
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 4096, FileOptions.Asynchronous | FileOptions.SequentialScan);
        using var buffer = new MemoryStream(); var block = new byte[4096]; int read;
        while ((read = await stream.ReadAsync(block, cancellationToken).ConfigureAwait(false)) != 0)
        {
            if (buffer.Length + read > 65536) throw new InvalidDataException("Projected workload token exceeds its bound.");
            buffer.Write(block, 0, read);
        }
        cancellationToken.ThrowIfCancellationRequested(); string credential = new UTF8Encoding(false, true).GetString(buffer.ToArray()).Trim();
        if (credential.Length == 0 || credential.Any(char.IsWhiteSpace)) throw new InvalidDataException("Projected workload token is empty or malformed.");
        return credential;
    }
}
