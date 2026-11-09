using System.Diagnostics;

// Isolated MIT KDC and a loopback SPNEGO counterpart. The application runtime image is unchanged.
internal sealed class ProtocolKerberosFixture : IAsyncDisposable
{
    internal string DirectoryPath { get; }
    internal string ImageId { get; private set; } = "";
    private readonly string root, parent, tag = "keycloak-sdk-kerberos-fixture:" + Guid.NewGuid().ToString("N");
    private string? container;
    private ProtocolKerberosFixture(string root)
    {
        this.root = root; parent = Path.GetFullPath(Path.Combine(root, "artifacts/application-protocols/kerberos")) + Path.DirectorySeparatorChar;
        DirectoryPath = Path.GetFullPath(Path.Combine(parent, Guid.NewGuid().ToString("N")));
    }
    internal static async Task<ProtocolKerberosFixture> CreateAsync(string root, CancellationToken ct)
    {
        var fixture = new ProtocolKerberosFixture(root); Directory.CreateDirectory(fixture.DirectoryPath);
        try
        {
            await File.WriteAllTextAsync(Path.Combine(fixture.DirectoryPath, "krb5.conf"), """
                [libdefaults]
                  default_realm = SDK.TEST
                  dns_lookup_kdc = false
                  dns_lookup_realm = false
                  dns_canonicalize_hostname = false
                  rdns = false
                  udp_preference_limit = 1
                [realms]
                  SDK.TEST = {
                    kdc = 127.0.0.1:18090
                  }
                """, ct);
            await File.WriteAllTextAsync(Path.Combine(fixture.DirectoryPath, "kdc.conf"), """
                [kdcdefaults]
                  kdc_ports = 18090
                  kdc_tcp_ports = 18090
                [realms]
                  SDK.TEST = {
                    database_name = /var/lib/krb5kdc/principal
                    key_stash_file = /var/lib/krb5kdc/.k5.SDK.TEST
                    max_life = 1h
                    max_renewable_life = 2h
                    supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal
                  }
                """, ct);
            await ScriptHost.RunCheckedAsync(root, "docker", ["build", "--tag", fixture.tag, "local/keycloak/kerberos"], ct);
            var identity = await ScriptHost.RunCheckedAsync(root, "docker", ["image", "inspect", "--format", "{{.Id}}", fixture.tag], ct, capture: true);
            fixture.ImageId = identity.StandardOutput.Trim();
            if (fixture.ImageId.Length != 71 || !fixture.ImageId.StartsWith("sha256:", StringComparison.Ordinal) || !fixture.ImageId[7..].All(char.IsAsciiHexDigit)) throw new InvalidDataException("Missing immutable Kerberos counterpart image identity.");
            return fixture;
        }
        catch { await fixture.DisposeAsync(); throw; }
    }
    internal async Task StartAsync(string networkContainer, CancellationToken ct)
    {
        container = networkContainer + "-kerberos";
        await ScriptHost.RunCheckedAsync(root, "docker", ["run", "--detach", "--name", container, "--network", "container:" + networkContainer, "-v", DirectoryPath + ":/kerberos", ImageId], ct);
        var elapsed = Stopwatch.StartNew();
        while (elapsed.Elapsed < TimeSpan.FromSeconds(30))
        {
            var state = await ScriptHost.RunCheckedAsync(root, "docker", ["inspect", "--format", "{{.State.Status}} {{.State.Health.Status}}", container], ct, capture: true);
            if (state.StandardOutput.Trim() == "running healthy") return;
            if (state.StandardOutput.StartsWith("exited", StringComparison.Ordinal)) throw new InvalidDataException("Owned Kerberos counterpart exited before readiness.");
            await Task.Delay(TimeSpan.FromSeconds(1), ct);
        }
        throw new TimeoutException("Owned Kerberos counterpart did not become ready.");
    }
    public async ValueTask DisposeAsync()
    {
        using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        if (container is not null)
        {
            var removal = await ScriptHost.RunAsync(root, "docker", ["rm", "--force", container], cleanup.Token, capture: true);
            if (removal.ExitCode != 0 && !removal.StandardError.Contains("No such container", StringComparison.OrdinalIgnoreCase)) throw new IOException("Owned Kerberos container cleanup failed.");
        }
        var imageRemoval = await ScriptHost.RunAsync(root, "docker", ["image", "rm", tag], cleanup.Token, capture: true);
        if (imageRemoval.ExitCode != 0 && !imageRemoval.StandardError.Contains("No such image", StringComparison.OrdinalIgnoreCase)) throw new IOException("Owned Kerberos image tag cleanup failed.");
        string path = Path.GetFullPath(DirectoryPath);
        if (!path.StartsWith(parent, StringComparison.OrdinalIgnoreCase)) throw new IOException("Kerberos cleanup escaped its owned workspace.");
        if (Directory.Exists(path)) Directory.Delete(path, true);
    }
}
