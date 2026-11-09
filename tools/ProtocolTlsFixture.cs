using System.Net;
using System.Security.Cryptography.X509Certificates;

// Test-only CA and leaves. Private keys stay in an ignored, unique directory, are never printed, and are removed after containers stop.
internal sealed class ProtocolTlsFixture : IAsyncDisposable
{
    internal string DirectoryPath { get; }
    internal string WorkspacePath { get; }
    private readonly string parent;
    private ProtocolTlsFixture(string root)
    {
        parent = Path.GetFullPath(Path.Combine(root, "artifacts/application-protocols/tls")) + Path.DirectorySeparatorChar;
        DirectoryPath = Path.GetFullPath(Path.Combine(parent, Guid.NewGuid().ToString("N")));
        WorkspacePath = "/workspace/" + Path.GetRelativePath(root, DirectoryPath).Replace('\\', '/');
    }
    internal static async Task<ProtocolTlsFixture> CreateAsync(string root, CancellationToken ct)
    {
        var fixture = new ProtocolTlsFixture(root); Directory.CreateDirectory(fixture.DirectoryPath);
        try
        {
            using var caKey = System.Security.Cryptography.RSA.Create(2048);
            var caRequest = new CertificateRequest("CN=sdk-protocol-test-ca", caKey, System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1);
            caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            caRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            caRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(caRequest.PublicKey, false));
            using var ca = caRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-2), DateTimeOffset.UtcNow.AddHours(2));
            await File.WriteAllTextAsync(Path.Combine(fixture.DirectoryPath, "ca.pem"), ca.ExportCertificatePem(), ct);
            foreach (string name in new[] { "server", "client", "other-client", "social" })
            {
                using var key = System.Security.Cryptography.RSA.Create(2048);
                var request = new CertificateRequest("CN=sdk-mtls-" + name, key, System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1);
                request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
                request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
                request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new System.Security.Cryptography.OidCollection { new(name is "server" or "social" ? "1.3.6.1.5.5.7.3.1" : "1.3.6.1.5.5.7.3.2") }, true));
                if (name == "server") { var san = new SubjectAlternativeNameBuilder(); san.AddIpAddress(IPAddress.Loopback); san.AddDnsName("localhost"); request.CertificateExtensions.Add(san.Build()); }
                if (name == "social") { var san = new SubjectAlternativeNameBuilder(); foreach (string host in new[] { "api.twitter.com", "api.instagram.com", "graph.instagram.com" }) san.AddDnsName(host); request.CertificateExtensions.Add(san.Build()); }
                using var certificate = request.Create(ca, DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1), System.Security.Cryptography.RandomNumberGenerator.GetBytes(16));
                await File.WriteAllTextAsync(Path.Combine(fixture.DirectoryPath, name + ".pem"), certificate.ExportCertificatePem(), ct);
                await File.WriteAllTextAsync(Path.Combine(fixture.DirectoryPath, name + ".key"), key.ExportPkcs8PrivateKeyPem(), ct);
            }
            return fixture;
        }
        catch { await fixture.DisposeAsync(); throw; }
    }
    public ValueTask DisposeAsync()
    {
        string target = Path.GetFullPath(DirectoryPath);
        if (!target.StartsWith(parent, StringComparison.OrdinalIgnoreCase)) throw new IOException("TLS fixture cleanup escaped its owned workspace directory.");
        if (Directory.Exists(target)) Directory.Delete(target, true);
        return ValueTask.CompletedTask;
    }
}
