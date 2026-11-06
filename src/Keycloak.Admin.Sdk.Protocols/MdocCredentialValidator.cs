using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.IdentityModel.Tokens;

namespace Keycloak.Admin.Sdk.Protocols;

public sealed class VerifiedMdocCredential
{
    public string DocumentType { get; }
    public JsonElement Namespaces { get; }
    public string HolderThumbprint { get; }
    public DateTimeOffset ValidUntil { get; }
    internal VerifiedMdocCredential(string type, JsonElement namespaces, string holder, DateTimeOffset until)
    { DocumentType = type; Namespaces = namespaces.Clone(); HolderThumbprint = holder; ValidUntil = until; }
}

/// <summary>Uses .NET COSE, CBOR and X.509 validation for mdoc IssuerSigned credentials.
/// The host explicitly supplies trusted CA roots and keeps them alive. Embedded x5chain certificates never establish trust.
/// Online certificate revocation is the default; isolated offline fixtures must explicitly choose their revocation mode.</summary>
public sealed class MdocCredentialValidator
{
    private readonly ProtocolTransport transport;
    private readonly X509Certificate2[] roots;
    private readonly X509RevocationMode revocation;
    private readonly TimeProvider clock;
    public MdocCredentialValidator(ProtocolTransport transport, IEnumerable<X509Certificate2> trustedRoots, X509RevocationMode revocationMode = X509RevocationMode.Online, TimeProvider? clock = null)
    {
        this.transport = transport ?? throw new ArgumentNullException(nameof(transport)); ArgumentNullException.ThrowIfNull(trustedRoots);
        roots = trustedRoots.ToArray();
        if (roots.Length is 0 or > 16 || roots.Any(c => c is null)) throw new ArgumentException("Explicit bounded mdoc CA trust roots are required.", nameof(trustedRoots));
        if (!Enum.IsDefined(revocationMode)) throw new ArgumentOutOfRangeException(nameof(revocationMode));
        revocation = revocationMode; this.clock = clock ?? TimeProvider.System;
    }
    public async Task<VerifiedMdocCredential> ValidateAsync(string credential, Oid4vcCredentialConfiguration configuration, string expectedHolderThumbprint, CancellationToken cancellationToken = default)
    {
        WalletJson.Credential(credential); ArgumentNullException.ThrowIfNull(configuration); WalletJson.Text(expectedHolderThumbprint);
        if (configuration.Issuer != transport.Issuer || configuration.Format != "mso_mdoc") throw new ArgumentException("A matching mdoc issuer configuration is required.", nameof(configuration));
        await transport.EnsureEnabledAsync([Oid4vcIssuerClient.Feature, "KeycloakSdk.Protocols.WalletMdoc"], cancellationToken).ConfigureAwait(false);
        try
        {
            var document = MdocCbor.Map(Base64UrlEncoder.DecodeBytes(credential));
            var message = CoseMessage.DecodeSign1(document["issuerAuth"].Span);
            var embeddedPayload = message.Content ?? throw new InvalidDataException("Detached mdoc issuer authentication is not permitted.");
            int algorithm = message.ProtectedHeaders.GetValueAsInt32(CoseHeaderLabel.Algorithm);
            // DecodeSign1 already rejects labels duplicated across protected and unprotected buckets.
            if (algorithm is not (-7 or -35 or -36)
                || message.ProtectedHeaders.ContainsKey(CoseHeaderLabel.CriticalHeaders) || message.UnprotectedHeaders.ContainsKey(CoseHeaderLabel.CriticalHeaders))
                throw new InvalidDataException("Explicit supported protected mdoc signing algorithm is required.");
            var header = new CoseHeaderLabel(33);
            ReadOnlyMemory<byte> chainBytes = message.ProtectedHeaders.TryGetValue(header, out var protectedChain) ? protectedChain.EncodedValue : message.UnprotectedHeaders[header].EncodedValue;
            var certificates = new List<X509Certificate2>();
            try
            {
                var reader = new CborReader(chainBytes, CborConformanceMode.Strict);
                var encoded = reader.PeekState() == CborReaderState.ByteString ? new[] { chainBytes } : MdocCbor.Array(chainBytes);
                if (encoded.Length is 0 or > 8) throw new InvalidDataException("A bounded mdoc certificate chain is required.");
                foreach (var certificate in encoded) certificates.Add(X509CertificateLoader.LoadCertificate(MdocCbor.Bytes(certificate)));
                using var chain = new X509Chain(); chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.CustomTrustStore.AddRange(roots); chain.ChainPolicy.ExtraStore.AddRange(certificates.Skip(1).ToArray());
                chain.ChainPolicy.DisableCertificateDownloads = true; chain.ChainPolicy.RevocationMode = revocation; chain.ChainPolicy.VerificationTime = clock.GetUtcNow().UtcDateTime;
                chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
                if (!chain.Build(certificates[0])) throw new InvalidDataException("Untrusted mdoc issuer certificate.");
                using var publicKey = certificates[0].GetECDsaPublicKey();
                if (publicKey is null || !message.VerifyEmbedded(publicKey)) throw new InvalidDataException("Invalid mdoc issuer signature.");
            }
            finally { foreach (var certificate in certificates) certificate.Dispose(); }
            var mso = MdocCbor.Map(MdocCbor.Embedded(embeddedPayload));
            string type = MdocCbor.Text(mso["docType"]);
            if (type != WalletJson.String(configuration.Document, "doctype") || MdocCbor.Text(mso["version"]) != "1.0" || MdocCbor.Text(mso["digestAlgorithm"]) != "SHA-256")
                throw new InvalidDataException("Invalid mdoc type version or digest algorithm.");
            var validity = MdocCbor.Map(mso["validityInfo"]); var signed = MdocCbor.Date(validity["signed"]); var from = MdocCbor.Date(validity["validFrom"]); var until = MdocCbor.Date(validity["validUntil"]);
            var now = clock.GetUtcNow();
            if (signed > now.AddSeconds(30) || from > now.AddSeconds(30) || until <= now || until <= from || until <= signed) throw new InvalidDataException("Invalid mdoc validity interval.");
            var deviceInfo = MdocCbor.Map(mso["deviceKeyInfo"]); var device = MdocCbor.IntegerMap(deviceInfo["deviceKey"]);
            if (MdocCbor.Integer(device[1]) != 2 || MdocCbor.Integer(device[-1]) != 1 || device.ContainsKey(-4)) throw new InvalidDataException("An mdoc P-256 public holder key is required.");
            var jwk = new JsonObject { ["kty"] = "EC", ["crv"] = "P-256", ["x"] = Base64UrlEncoder.Encode(MdocCbor.Bytes(device[-2])), ["y"] = Base64UrlEncoder.Encode(MdocCbor.Bytes(device[-3])) };
            string holder = Base64UrlEncoder.Encode(new JsonWebKey(jwk.ToJsonString()).ComputeJwkThumbprint());
            if (holder != expectedHolderThumbprint) throw new InvalidDataException("Mdoc device key does not match the requesting wallet.");
            var digests = MdocCbor.Map(mso["valueDigests"]); var namespaces = new JsonObject();
            foreach (var space in MdocCbor.Map(document["nameSpaces"]))
            {
                var allowed = MdocCbor.IntegerMap(digests[space.Key]); var used = new HashSet<long>(); var values = new JsonObject();
                foreach (var encoded in MdocCbor.Array(space.Value))
                {
                    var item = MdocCbor.Map(MdocCbor.Embedded(encoded)); long id = MdocCbor.Integer(item["digestID"]);
                    if (id < 0 || !used.Add(id) || !allowed.TryGetValue(id, out var expected) || !CryptographicOperations.FixedTimeEquals(SHA256.HashData(encoded.Span), MdocCbor.Bytes(expected)))
                        throw new InvalidDataException("An mdoc data element is not bound to its signed digest.");
                    string name = MdocCbor.Text(item["elementIdentifier"]);
                    if (values.ContainsKey(name) || MdocCbor.Bytes(item["random"]).Length < 16) throw new InvalidDataException("Invalid or duplicate mdoc data element.");
                    values[name] = MdocCbor.Json(item["elementValue"]);
                }
                namespaces[space.Key] = values;
            }
            using var claims = JsonDocument.Parse(namespaces.ToJsonString()); cancellationToken.ThrowIfCancellationRequested();
            return new(type, claims.RootElement, holder, until);
        }
        catch (Exception error) when (error is ArgumentException or CryptographicException or CborContentException or InvalidOperationException or KeyNotFoundException or FormatException or InvalidDataException)
        { throw new InvalidDataException("Invalid mdoc credential."); }
    }
}
