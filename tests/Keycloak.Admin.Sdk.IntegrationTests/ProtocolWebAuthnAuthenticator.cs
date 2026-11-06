using System.Buffers.Binary;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.IdentityModel.Tokens;

// Owned software authenticator for real server ceremonies. This is test infrastructure, not a browser
// WebAuthn implementation shipped to applications. Production browser mediation remains in Keycloak's UI.
internal sealed class ProtocolWebAuthnAuthenticator : IDisposable
{
    private readonly ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly byte[] credentialId = RandomNumberGenerator.GetBytes(32);
    private readonly Uri origin;
    private uint counter;
    private string userHandle = "";
    internal bool TamperOrigin, TamperSignature;
    internal bool UseConditionalUi;
    internal int Registrations, Authentications;
    internal ProtocolWebAuthnAuthenticator(Uri server) { origin = new(server.GetLeftPart(UriPartial.Authority)); }
    internal Dictionary<string, string>? Respond(string html)
    {
        bool register = html.Contains("id=\"attestationObject\"", StringComparison.Ordinal);
        if (!register && (Registrations == 0 || (!UseConditionalUi && html.Contains("id=\"kc-form-login\"", StringComparison.Ordinal)) || !html.Contains("id=\"authenticatorData\"", StringComparison.Ordinal))) return null;
        string challenge = Setting(html, "challenge"), rpId = Setting(html, "rpId");
        string client = new JsonObject { ["type"] = register ? "webauthn.create" : "webauthn.get", ["challenge"] = challenge,
            ["origin"] = TamperOrigin ? "https://foreign.invalid" : origin.GetLeftPart(UriPartial.Authority), ["crossOrigin"] = false }.ToJsonString();
        byte[] clientBytes = Encoding.UTF8.GetBytes(client), rpHash = SHA256.HashData(Encoding.UTF8.GetBytes(rpId));
        byte[] auth = new byte[37]; rpHash.CopyTo(auth, 0); auth[32] = register ? (byte)0x45 : (byte)0x05; BinaryPrimitives.WriteUInt32BigEndian(auth.AsSpan(33), ++counter);
        var fields = new Dictionary<string, string> { ["clientDataJSON"] = Base64UrlEncoder.Encode(clientBytes) };
        if (register)
        {
            Registrations++; userHandle = Setting(html, "userid"); var p = key.ExportParameters(false);
            var cose = new CborWriter(CborConformanceMode.Strict); cose.WriteStartMap(5);
            cose.WriteInt32(1); cose.WriteInt32(2); cose.WriteInt32(3); cose.WriteInt32(-7); cose.WriteInt32(-1); cose.WriteInt32(1);
            cose.WriteInt32(-2); cose.WriteByteString(p.Q.X!); cose.WriteInt32(-3); cose.WriteByteString(p.Q.Y!); cose.WriteEndMap();
            byte[] length = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(length, checked((ushort)credentialId.Length));
            byte[] attested = [.. auth, .. new byte[16], .. length, .. credentialId, .. cose.Encode()];
            var writer = new CborWriter(CborConformanceMode.Strict); writer.WriteStartMap(3); writer.WriteTextString("fmt"); writer.WriteTextString("none");
            writer.WriteTextString("attStmt"); writer.WriteStartMap(0); writer.WriteEndMap(); writer.WriteTextString("authData"); writer.WriteByteString(attested); writer.WriteEndMap();
            fields["attestationObject"] = Base64UrlEncoder.Encode(writer.Encode()); fields["publicKeyCredentialId"] = Base64UrlEncoder.Encode(credentialId);
            fields["authenticatorLabel"] = "Owned test authenticator"; fields["transports"] = "internal"; fields["authenticatorAttachment"] = "platform";
        }
        else
        {
            Authentications++; byte[] signature = key.SignData([.. auth, .. SHA256.HashData(clientBytes)], HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
            if (TamperSignature) signature[^1] ^= 1;
            fields["authenticatorData"] = Base64UrlEncoder.Encode(auth); fields["signature"] = Base64UrlEncoder.Encode(signature);
            fields["credentialId"] = Base64UrlEncoder.Encode(credentialId); fields["userHandle"] = userHandle;
        }
        return fields;
    }
    private static string Setting(string html, string name)
    {
        var match = Regex.Match(html, @"\b" + name + @"\s*:\s*(""(?:[^""\\]|\\.)*"")", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
        if (!match.Success) throw new InvalidDataException("Pinned WebAuthn ceremony setting was absent: " + name);
        using var value = System.Text.Json.JsonDocument.Parse(match.Groups[1].Value); return value.RootElement.GetString()!;
    }
    public void Dispose() => key.Dispose();
}
