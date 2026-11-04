using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using static LiveContext;

internal static class FullCertificates
{
    public static async Task RunAsync(LiveContext c, LiveFacts f)
    {
        const string root = "clients/{client-uuid}/certificates/{attr}";
        var p = new[] { ("client-uuid", f.Client), ("attr", "jwt.credential") };
        var generated = await c.Post(root + "/generate", paths: p);
        var read = await c.Get(root, null, p);
        c.Prove(S(generated.J, "privateKey").Length > 100 && S(read.J, "certificate") == S(generated.J, "certificate") && S(read.J, "privateKey").Length == 0, "Generated keypair returns private key once and persists public certificate only", generated, read);
        using var rsa = RSA.Create(2048);
        using var certificate = new CertificateRequest("CN=full-client-upload", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(2));
        foreach (string action in new[] { "upload", "upload-certificate" })
        {
            var multipart = new MultipartFormDataContent();
            multipart.Add(new StringContent("Certificate PEM"), "keystoreFormat");
            multipart.Add(new StringContent(certificate.ExportCertificatePem(), Encoding.ASCII), "file", "full.pem");
            var uploaded = await c.Call("POST", root + "/" + action, raw: multipart, paths: p);
            read = await c.Get(root, null, p);
            using var stored = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(S(read.J, "certificate")));
            c.Prove(stored.Thumbprint == certificate.Thumbprint && S(uploaded.J, "certificate") == S(read.J, "certificate"), "Multipart " + action + " persists exact uploaded X509 certificate", uploaded, read);
        }
        var config = O("""{"format":"PKCS12","storePassword":"full-store-password","keyPassword":"full-store-password","keyAlias":"full-client","realmCertificate":false,"keySize":2048,"validity":1}""");
        var download = await c.Post(root + "/download", config, null, p);
        // Keycloak's JDK uses a higher MAC iteration count than the .NET loader default.
        var limits = new Pkcs12LoaderLimits { MacIterationLimit = 2_000_000, IndividualKdfIterationLimit = 2_000_000, TotalKdfIterationLimit = 5_000_000 };
        using var publicStore = X509CertificateLoader.LoadPkcs12(download.Response.Content.Span, "full-store-password", loaderLimits: limits);
        c.Prove(publicStore.Thumbprint == certificate.Thumbprint && !publicStore.HasPrivateKey, "Downloaded PKCS12 contains exact persisted public certificate without private key", download);
        var bundle = await c.Post(root + "/generate-and-download", config, null, p);
        using var privateStore = X509CertificateLoader.LoadPkcs12(bundle.Response.Content.Span, "full-store-password", loaderLimits: limits);
        read = await c.Get(root, null, p);
        using var persisted = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(S(read.J, "certificate")));
        c.Prove(privateStore.HasPrivateKey && privateStore.Thumbprint == persisted.Thumbprint && persisted.Thumbprint != certificate.Thumbprint && S(read.J, "privateKey").Length == 0, "Generate-and-download returns usable private-key PKCS12 while persisting only the new public certificate", bundle, read);
        Console.WriteLine("PASS full client certificates: generation, both multipart uploads and parsed PKCS12 public/private downloads.");
    }
}
