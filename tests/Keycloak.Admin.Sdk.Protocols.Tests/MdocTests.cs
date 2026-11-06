using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Keycloak.Admin.Sdk.Protocols;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualStudio.TestTools.UnitTesting;

[TestClass]
public sealed class MdocTests
{
    [TestMethod]
    public async Task CoseAndCertificateValidationBindDataTypeLifetimeAndDevice()
    {
        using var f = new Fixture(); var validator = new MdocCredentialValidator(f.Transport, [f.Root], X509RevocationMode.NoCheck, f.Clock);
        foreach (bool singleCertificate in new[] { false, true })
        {
            var credential = await validator.ValidateAsync(f.Build(singleCertificate: singleCertificate), f.Configuration, f.Holder.Thumbprint);
            Assert.AreEqual("org.sdk.identity", credential.DocumentType); Assert.AreEqual(f.Holder.Thumbprint, credential.HolderThumbprint);
            Assert.AreEqual("user@example.invalid", credential.Namespaces.GetProperty("org.sdk.identity").GetProperty("email").GetString());
            Assert.IsTrue(credential.ValidUntil > f.Clock.Now);
        }
        string valid = f.Build();
        await Assert.ThrowsAsync<InvalidDataException>(() => validator.ValidateAsync(valid, f.Configuration, "other-device"));
        using var untrusted = new Fixture();
        await Assert.ThrowsAsync<InvalidDataException>(() => new MdocCredentialValidator(f.Transport, [untrusted.Root], X509RevocationMode.NoCheck).ValidateAsync(valid, f.Configuration, f.Holder.Thumbprint));
        await Assert.ThrowsAsync<ArgumentException>(() => validator.ValidateAsync(valid, new(f.Transport.Issuer, "jwt", Json("{\"format\":\"jwt_vc_json\"}")), f.Holder.Thumbprint));
        await Assert.ThrowsAsync<ArgumentException>(() => validator.ValidateAsync(valid, new(new("https://other.invalid/realms/r"), "mdoc", f.Configuration.Document), f.Holder.Thumbprint));
        Assert.Throws<ArgumentException>(() => new MdocCredentialValidator(f.Transport, []));
        Assert.Throws<ArgumentException>(() => new MdocCredentialValidator(f.Transport, Enumerable.Repeat(f.Root, 17)));
        Assert.Throws<ArgumentException>(() => new MdocCredentialValidator(f.Transport, [null!]));
        Assert.Throws<ArgumentOutOfRangeException>(() => new MdocCredentialValidator(f.Transport, [f.Root], (X509RevocationMode)9));
        using var canceled = new CancellationTokenSource(); canceled.Cancel();
        await Assert.ThrowsAsync<OperationCanceledException>(() => validator.ValidateAsync(valid, f.Configuration, f.Holder.Thumbprint, canceled.Token));
        Assert.Throws<ArgumentNullException>(() => new MdocCredentialValidator(null!, [f.Root]));
    }

    [TestMethod]
    public async Task SignedMsoAndElementMutationsCannotProduceVerifiedMdocClaims()
    {
        using var f = new Fixture(); var validator = new MdocCredentialValidator(f.Transport, [f.Root], X509RevocationMode.NoCheck, f.Clock);
        foreach (Action<Dictionary<string, byte[]>> mutation in new Action<Dictionary<string, byte[]>>[]
        {
            m => m["version"] = Text("2.0"), m => m["docType"] = Text("other"), m => m["digestAlgorithm"] = Text("SHA-512"),
            m => m["validityInfo"] = f.Validity(signed: f.Clock.Now.AddMinutes(1)), m => m["validityInfo"] = f.Validity(from: f.Clock.Now.AddMinutes(1)),
            m => m["validityInfo"] = f.Validity(until: f.Clock.Now.AddMinutes(-1)),
            m => m["validityInfo"] = f.Validity(from: f.Clock.Now.AddSeconds(20), until: f.Clock.Now.AddSeconds(10)),
            m => m["validityInfo"] = f.Validity(signed: f.Clock.Now.AddSeconds(20), until: f.Clock.Now.AddSeconds(10)),
            m => m["deviceKeyInfo"] = Map(new() { ["deviceKey"] = Integers(new() { [1] = Integer(3), [-1] = Integer(1) }) }),
            m => m["deviceKeyInfo"] = Map(new() { ["deviceKey"] = Integers(new() { [1] = Integer(2), [-1] = Integer(2) }) }),
            m => { var device = f.Device(); device[-4] = Bytes([1]); m["deviceKeyInfo"] = Map(new() { ["deviceKey"] = Integers(device) }); },
            m => m["valueDigests"] = Map(new() { ["org.sdk.identity"] = Integers(new() { [0] = Bytes([0]) }) }),
            m => m.Remove("deviceKeyInfo")
        })
            await Assert.ThrowsAsync<InvalidDataException>(() => validator.ValidateAsync(f.Build(mutation), f.Configuration, f.Holder.Thumbprint));
        foreach (Action<Dictionary<string, byte[]>> mutation in new Action<Dictionary<string, byte[]>>[]
            { i => i["digestID"] = Integer(-1), i => i["digestID"] = Integer(99), i => i["random"] = Bytes(new byte[8]) })
            await Assert.ThrowsAsync<InvalidDataException>(() => validator.ValidateAsync(f.Build(mutateItem: mutation), f.Configuration, f.Holder.Thumbprint));
        await Assert.ThrowsAsync<InvalidDataException>(() => validator.ValidateAsync(f.Build(tamperElement: true), f.Configuration, f.Holder.Thumbprint));
        await Assert.ThrowsAsync<InvalidDataException>(() => validator.ValidateAsync(f.Build(repeatElement: true), f.Configuration, f.Holder.Thumbprint));
        foreach (string invalid in new[] { "not-base64", Base64UrlEncoder.Encode(new byte[] { 0xa0 }), Base64UrlEncoder.Encode(new byte[] { 0x80 }) })
            await Assert.ThrowsAsync<InvalidDataException>(() => validator.ValidateAsync(invalid, f.Configuration, f.Holder.Thumbprint));
    }

    [TestMethod]
    public async Task CoseTrustHeadersAndDetachedContentCannotBypassAuthentication()
    {
        using var f = new Fixture(); var validator = new MdocCredentialValidator(f.Transport, [f.Root], X509RevocationMode.NoCheck, f.Clock);
        await Assert.ThrowsAsync<InvalidDataException>(() => validator.ValidateAsync(f.Build(detached: true), f.Configuration, f.Holder.Thumbprint));
        await Assert.ThrowsAsync<InvalidDataException>(() => validator.ValidateAsync(f.Build(certificateCount: 0), f.Configuration, f.Holder.Thumbprint));
        await Assert.ThrowsAsync<InvalidDataException>(() => validator.ValidateAsync(f.Build(certificateCount: 9), f.Configuration, f.Holder.Thumbprint));
        await Assert.ThrowsAsync<InvalidDataException>(() => validator.ValidateAsync(f.Build(badSignature: true), f.Configuration, f.Holder.Thumbprint));
        foreach (bool protect in new[] { false, true })
            await Assert.ThrowsAsync<InvalidDataException>(() => validator.ValidateAsync(f.Build(critical: protect ? 1 : 2), f.Configuration, f.Holder.Thumbprint));
        await validator.ValidateAsync(f.Build(protectedChain: true), f.Configuration, f.Holder.Thumbprint);
        using var rsa = RSA.Create(2048);
        using var rsaCertificate = new CertificateRequest("CN=RSA Root", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSelfSigned(f.Clock.Now.AddHours(-1), f.Clock.Now.AddHours(1));
        await Assert.ThrowsAsync<InvalidDataException>(() => new MdocCredentialValidator(f.Transport, [rsaCertificate], X509RevocationMode.NoCheck, f.Clock)
            .ValidateAsync(f.Build(certificate: rsaCertificate.RawData), f.Configuration, f.Holder.Thumbprint));
        await Assert.ThrowsAsync<InvalidDataException>(() => validator.ValidateAsync(f.Build(rsaSigner: rsa), f.Configuration, f.Holder.Thumbprint));
        foreach (int size in new[] { 384, 521 })
        {
            using var alternate = new Fixture(size);
            await new MdocCredentialValidator(alternate.Transport, [alternate.Root], X509RevocationMode.NoCheck, alternate.Clock)
                .ValidateAsync(alternate.Build(), alternate.Configuration, alternate.Holder.Thumbprint);
        }
        await Assert.ThrowsAsync<InvalidDataException>(() => validator.ValidateAsync(f.Build(duplicateName: true), f.Configuration, f.Holder.Thumbprint));
    }

    [TestMethod]
    public void CborValuesAreBoundedStrictAndPreserveClaimTypes()
    {
        var map = Map(new() { ["null"] = Encode(w => w.WriteNull()), ["true"] = Encode(w => w.WriteBoolean(true)), ["number"] = Integer(-1),
            ["double"] = Encode(w => w.WriteDouble(1.5)), ["single"] = Encode(w => w.WriteSingle(2.5f)), ["half"] = Encode(w => w.WriteHalf((Half)3.5)),
            ["bytes"] = Bytes([1, 2]), ["text"] = Text("value"), ["array"] = Array(Text("inside")) });
        var claims = Json(MdocCbor.Json(map)!.ToJsonString()); Assert.IsTrue(claims.GetProperty("true").GetBoolean()); Assert.AreEqual(-1, claims.GetProperty("number").GetInt32());
        Assert.AreEqual("AQI=", claims.GetProperty("bytes").GetString()); Assert.AreEqual(1.5, claims.GetProperty("double").GetDouble()); Assert.AreEqual("inside", claims.GetProperty("array")[0].GetString());
        Assert.Throws<InvalidDataException>(() => MdocCbor.Json(Encode(w => w.WriteDouble(double.NaN))));
        Assert.Throws<InvalidDataException>(() => MdocCbor.Json(Encode(w => w.WriteSimpleValue((CborSimpleValue)16))));
        Assert.Throws<InvalidDataException>(() => MdocCbor.Json(map, 33));
        Assert.Throws<InvalidDataException>(() => MdocCbor.Text(Text("one").Concat(Text("two")).ToArray()));
        Assert.Throws<InvalidDataException>(() => MdocCbor.Embedded(Encode(w => { w.WriteTag((CborTag)25); w.WriteByteString([]); })));
        Assert.Throws<InvalidDataException>(() => MdocCbor.Date(Encode(w => { w.WriteTag((CborTag)1); w.WriteTextString("invalid"); })));
        Assert.Throws<InvalidDataException>(() => MdocCbor.Date(Encode(w => { w.WriteTag((CborTag)0); w.WriteTextString("2026"); })));
        Assert.AreEqual(2026, MdocCbor.Date(Encode(w => { w.WriteTag((CborTag)0); w.WriteTextString("2026-11-07T00:00:00Z"); })).Year);
        Assert.Throws<InvalidDataException>(() => MdocCbor.Array(Array(Enumerable.Repeat(Integer(1), 1001).ToArray())));
        Assert.Throws<InvalidDataException>(() => MdocCbor.Map(Map(Enumerable.Range(0, 1001).ToDictionary(i => "key" + i, _ => Text("value")))));
        Assert.Throws<InvalidDataException>(() => MdocCbor.IntegerMap(Integers(Enumerable.Range(0, 1001).ToDictionary(i => (long)i, _ => Text("value")))));
    }

    private static JsonElement Json(string value) { using var document = JsonDocument.Parse(value); return document.RootElement.Clone(); }
    private static byte[] Encode(Action<CborWriter> write) { var writer = new CborWriter(CborConformanceMode.Strict); write(writer); return writer.Encode(); }
    private static byte[] Text(string value) => Encode(w => w.WriteTextString(value));
    private static byte[] Integer(long value) => Encode(w => w.WriteInt64(value));
    private static byte[] Bytes(byte[] value) => Encode(w => w.WriteByteString(value));
    private static byte[] Embedded(byte[] value) => Encode(w => { w.WriteTag((CborTag)24); w.WriteByteString(value); });
    private static byte[] Array(params byte[][] values) => Encode(w => { w.WriteStartArray(values.Length); foreach (var value in values) w.WriteEncodedValue(value); w.WriteEndArray(); });
    private static byte[] Map(Dictionary<string, byte[]> values) => Encode(w => { w.WriteStartMap(values.Count); foreach (var pair in values) { w.WriteTextString(pair.Key); w.WriteEncodedValue(pair.Value); } w.WriteEndMap(); });
    private static byte[] Integers(Dictionary<long, byte[]> values) => Encode(w => { w.WriteStartMap(values.Count); foreach (var pair in values) { w.WriteInt64(pair.Key); w.WriteEncodedValue(pair.Value); } w.WriteEndMap(); });
    private sealed class FixedClock : TimeProvider { internal DateTimeOffset Now = DateTimeOffset.UtcNow; public override DateTimeOffset GetUtcNow() => Now; }
    private sealed class Fixture : IDisposable
    {
        internal readonly ECDsa IssuerKey, RootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256), DeviceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        internal readonly X509Certificate2 Root, Certificate; internal readonly HttpClient Http = new(); internal readonly ProtocolTransport Transport;
        internal readonly FixedClock Clock = new(); internal readonly Oid4vcProofKey Holder;
        internal Oid4vcCredentialConfiguration Configuration => new(Transport.Issuer, "mdoc", Json("{\"format\":\"mso_mdoc\",\"doctype\":\"org.sdk.identity\"}"));
        internal Fixture(int size = 256)
        {
            IssuerKey = ECDsa.Create(size == 384 ? ECCurve.NamedCurves.nistP384 : size == 521 ? ECCurve.NamedCurves.nistP521 : ECCurve.NamedCurves.nistP256);
            var ca = new CertificateRequest("CN=Root", RootKey, HashAlgorithmName.SHA256); ca.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            Root = ca.CreateSelfSigned(Clock.Now.AddDays(-1), Clock.Now.AddDays(1));
            var leaf = new CertificateRequest("CN=Issuer", IssuerKey, HashAlgorithmName.SHA256); leaf.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            Certificate = leaf.Create(Root, Clock.Now.AddHours(-1), Clock.Now.AddHours(1), RandomNumberGenerator.GetBytes(16));
            Transport = new(Http, new("https://issuer.invalid"), "r"); Holder = Oid4vcProofKey.FromEcdsa(DeviceKey);
        }
        internal Dictionary<long, byte[]> Device()
        { var p = DeviceKey.ExportParameters(false); return new() { [1] = Integer(2), [-1] = Integer(1), [-2] = Bytes(p.Q.X!), [-3] = Bytes(p.Q.Y!) }; }
        internal byte[] Validity(DateTimeOffset? signed = null, DateTimeOffset? from = null, DateTimeOffset? until = null)
        {
            byte[] Date(DateTimeOffset date) => Encode(w => { w.WriteTag((CborTag)0); w.WriteTextString(date.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", System.Globalization.CultureInfo.InvariantCulture)); });
            return Map(new() { ["signed"] = Date(signed ?? Clock.Now.AddMinutes(-1)), ["validFrom"] = Date(from ?? Clock.Now.AddMinutes(-1)), ["validUntil"] = Date(until ?? Clock.Now.AddMinutes(10)) });
        }
        internal string Build(Action<Dictionary<string, byte[]>>? mutateMso = null, Action<Dictionary<string, byte[]>>? mutateItem = null, bool singleCertificate = false,
            int certificateCount = 1, bool detached = false, bool badSignature = false, bool tamperElement = false, bool repeatElement = false,
            int critical = 0, bool protectedChain = false, byte[]? certificate = null, RSA? rsaSigner = null, bool duplicateName = false)
        {
            var item = new Dictionary<string, byte[]> { ["digestID"] = Integer(0), ["random"] = Bytes(new byte[16]), ["elementIdentifier"] = Text("email"), ["elementValue"] = Text("user@example.invalid") };
            mutateItem?.Invoke(item); byte[] encodedItem = Embedded(Map(item));
            var mso = new Dictionary<string, byte[]> { ["version"] = Text("1.0"), ["digestAlgorithm"] = Text("SHA-256"), ["docType"] = Text("org.sdk.identity"), ["validityInfo"] = Validity(),
                ["deviceKeyInfo"] = Map(new() { ["deviceKey"] = Integers(Device()) }), ["valueDigests"] = Map(new() { ["org.sdk.identity"] = Integers(new() { [0] = Bytes(SHA256.HashData(encodedItem)) }) }) };
            byte[]? otherItem = null;
            if (duplicateName)
            {
                var other = new Dictionary<string, byte[]>(item) { ["digestID"] = Integer(1) }; otherItem = Embedded(Map(other));
                mso["valueDigests"] = Map(new() { ["org.sdk.identity"] = Integers(new() { [0] = Bytes(SHA256.HashData(encodedItem)), [1] = Bytes(SHA256.HashData(otherItem)) }) });
            }
            mutateMso?.Invoke(mso); byte[] payload = Embedded(Map(mso));
            var protectedHeaders = new CoseHeaderMap();
            var headers = new CoseHeaderMap(); var chainTarget = protectedChain ? protectedHeaders : headers;
            chainTarget[new(33)] = CoseHeaderValue.FromEncodedValue(singleCertificate ? Bytes(certificate ?? Certificate.RawData) : Array(Enumerable.Repeat(Bytes(certificate ?? Certificate.RawData), certificateCount).ToArray()));
            if (critical != 0)
            { var target = critical == 1 ? protectedHeaders : headers; target[new(42)] = CoseHeaderValue.FromInt32(1); target[CoseHeaderLabel.CriticalHeaders] = CoseHeaderValue.FromEncodedValue(Array(Integer(42))); }
            var hash = IssuerKey.KeySize == 384 ? HashAlgorithmName.SHA384 : IssuerKey.KeySize == 521 ? HashAlgorithmName.SHA512 : HashAlgorithmName.SHA256;
            var signer = rsaSigner is null ? new CoseSigner(IssuerKey, hash, protectedHeaders, headers) : new CoseSigner(rsaSigner, RSASignaturePadding.Pss, HashAlgorithmName.SHA256, protectedHeaders, headers);
            byte[] authentication = detached ? CoseSign1Message.SignDetached(payload, signer) : CoseSign1Message.SignEmbedded(payload, signer);
            if (badSignature) authentication[^1] ^= 1;
            if (tamperElement) { item["elementValue"] = Text("attacker@example.invalid"); encodedItem = Embedded(Map(item)); }
            byte[] entries = repeatElement ? Array(encodedItem, encodedItem) : otherItem is not null ? Array(encodedItem, otherItem) : Array(encodedItem);
            return Base64UrlEncoder.Encode(Map(new() { ["issuerAuth"] = authentication, ["nameSpaces"] = Map(new() { ["org.sdk.identity"] = entries }) }));
        }
        public void Dispose() { Http.Dispose(); Certificate.Dispose(); Root.Dispose(); IssuerKey.Dispose(); RootKey.Dispose(); DeviceKey.Dispose(); }
    }
}
