using System.Formats.Asn1;
using System.Net.Sockets;
using System.Text;

// Minimal LDAP wire client for seeding/modifying a REAL OpenLDAP container.
// No LDAP responses or Admin API responses are synthesized.
internal sealed class LdapFixture : IAsyncDisposable
{
    private readonly TcpClient socket = new();
    private int messageId;
    private NetworkStream Stream => socket.GetStream();
    public static async Task<LdapFixture> Connect(CancellationToken cancellationToken = default)
    {
        var client = new LdapFixture();
        try
        {
            await client.socket.ConnectAsync(Environment.GetEnvironmentVariable("KC_TEST_LDAP_HOST")!, int.Parse(Environment.GetEnvironmentVariable("KC_TEST_LDAP_PORT")!, System.Globalization.CultureInfo.InvariantCulture), cancellationToken);
            await client.Request(0, w => { w.WriteInteger(3); Octet(w, "cn=admin,dc=example,dc=org"); w.WriteOctetString(Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable("KC_TEST_LDAP_PASSWORD")!), new Asn1Tag(TagClass.ContextSpecific, 0)); }, cancellationToken);
            return client;
        }
        catch { client.socket.Dispose(); throw; }
    }
    public Task Add(string dn, CancellationToken cancellationToken, params (string Attribute, string[] Values)[] attributes) => Request(8, w =>
    {
        Octet(w, dn); using (w.PushSequence()) foreach (var (attribute, values) in attributes)
        { using (w.PushSequence()) { Octet(w, attribute); using (w.PushSetOf()) foreach (string value in values) Octet(w, value); } }
    }, cancellationToken);
    public Task Replace(string dn, string attribute, string value, CancellationToken cancellationToken = default) => Request(6, w =>
    {
        Octet(w, dn); using (w.PushSequence()) using (w.PushSequence())
        { w.WriteEnumeratedValue(Change.Replace); using (w.PushSequence()) { Octet(w, attribute); using (w.PushSetOf()) Octet(w, value); } }
    }, cancellationToken);
    public Task Delete(string dn, CancellationToken cancellationToken = default, bool ignoreMissing = false) => Request(10, w => w.WriteOctetString(Encoding.UTF8.GetBytes(dn), new Asn1Tag(TagClass.Application, 10)), cancellationToken, primitive: true, ignoreMissing: ignoreMissing);
    private static void Octet(AsnWriter writer, string value) => writer.WriteOctetString(Encoding.UTF8.GetBytes(value));
    private async Task Request(int application, Action<AsnWriter> operation, CancellationToken cancellationToken, bool primitive = false, bool ignoreMissing = false)
    {
        var writer = new AsnWriter(AsnEncodingRules.BER);
        using (writer.PushSequence())
        {
            writer.WriteInteger(++messageId);
            if (primitive) operation(writer);
            else using (writer.PushSequence(new Asn1Tag(TagClass.Application, application, true))) operation(writer);
        }
        await Stream.WriteAsync(writer.Encode(), cancellationToken);
        byte[] prefix = new byte[2]; await Stream.ReadExactlyAsync(prefix, cancellationToken);
        int length = prefix[1]; var packet = new List<byte>(prefix);
        if ((length & 128) != 0)
        {
            int bytes = length & 127; if (bytes is < 1 or > 4) throw new IOException("Invalid LDAP BER length");
            byte[] size = new byte[bytes]; await Stream.ReadExactlyAsync(size, cancellationToken); packet.AddRange(size);
            length = 0; foreach (byte b in size) length = (length << 8) | b;
        }
        if (length > 1_000_000) throw new IOException("Oversized LDAP result");
        byte[] payload = new byte[length]; await Stream.ReadExactlyAsync(payload, cancellationToken); packet.AddRange(payload);
        var envelope = new AsnReader(packet.ToArray(), AsnEncodingRules.BER).ReadSequence();
        if (envelope.ReadInteger() != messageId) throw new IOException("LDAP message ID mismatch");
        var result = envelope.ReadSequence(new Asn1Tag(TagClass.Application, application + 1, true));
        var status = result.ReadEnumeratedValue<Result>();
        result.ReadOctetString(); string diagnostic = Encoding.UTF8.GetString(result.ReadOctetString());
        if (status != Result.Success && !(ignoreMissing && status == Result.NoSuchObject)) throw new IOException("Actual OpenLDAP result " + (int)status + ": " + diagnostic);
    }
    private enum Result { Success = 0, NoSuchObject = 32 }
    private enum Change { Replace = 2 }
    public ValueTask DisposeAsync() { socket.Dispose(); return ValueTask.CompletedTask; }
}
