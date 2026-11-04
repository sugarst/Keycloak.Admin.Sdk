using System.Buffers.Binary;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

// BCL-only PostgreSQL v3 / SCRAM-SHA-256 client for an out-of-band cache mutation.
internal sealed class PostgresFixture : IAsyncDisposable
{
    private readonly TcpClient socket = new();
    private NetworkStream Stream => socket.GetStream();
    public static async Task<PostgresFixture> Connect()
    {
        var c = new PostgresFixture();
        await c.socket.ConnectAsync(Environment.GetEnvironmentVariable("KC_TEST_PG_HOST")!, int.Parse(Environment.GetEnvironmentVariable("KC_TEST_PG_PORT")!, System.Globalization.CultureInfo.InvariantCulture));
        byte[] start = Encoding.UTF8.GetBytes("user\0" + Environment.GetEnvironmentVariable("KC_TEST_PG_USER") + "\0database\0" + Environment.GetEnvironmentVariable("KC_TEST_PG_DATABASE") + "\0client_encoding\0UTF8\0\0");
        await c.Stream.WriteAsync((byte[])[.. I32(start.Length + 8), 0, 3, 0, 0, .. start]);
        string nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(24)), bare = "n=,r=" + nonce;
        byte[]? expected = null;
        while (true)
        {
            var (tag, data) = await c.Receive();
            if (tag == 'R')
            {
                int type = BinaryPrimitives.ReadInt32BigEndian(data);
                if (type == 10)
                {
                    string first = "n,," + bare; byte[] encoded = Encoding.UTF8.GetBytes(first);
                    await c.Send('p', [.. Encoding.ASCII.GetBytes("SCRAM-SHA-256\0"), .. I32(encoded.Length), .. encoded]);
                }
                else if (type == 11)
                {
                    string serverFirst = Encoding.UTF8.GetString(data.AsSpan(4));
                    var parts = serverFirst.Split(',').ToDictionary(v => v[..1], v => v[2..]);
                    if (!parts["r"].StartsWith(nonce, StringComparison.Ordinal) || parts["r"] == nonce) throw new IOException("SCRAM nonce mismatch");
                    int iterations = int.Parse(parts["i"], System.Globalization.CultureInfo.InvariantCulture);
                    if (iterations is < 4096 or > 1_000_000) throw new IOException("Unexpected SCRAM iteration count");
                    byte[] salted = Rfc2898DeriveBytes.Pbkdf2(Environment.GetEnvironmentVariable("KC_TEST_PG_PASSWORD")!, Convert.FromBase64String(parts["s"]), iterations, HashAlgorithmName.SHA256, 32);
                    string final = "c=biws,r=" + parts["r"];
                    byte[] message = Encoding.UTF8.GetBytes(bare + "," + serverFirst + "," + final);
                    byte[] clientKey = HMACSHA256.HashData(salted, Encoding.ASCII.GetBytes("Client Key"));
                    byte[] signature = HMACSHA256.HashData(SHA256.HashData(clientKey), message);
                    for (int i = 0; i < clientKey.Length; i++) clientKey[i] ^= signature[i];
                    expected = HMACSHA256.HashData(HMACSHA256.HashData(salted, Encoding.ASCII.GetBytes("Server Key")), message);
                    await c.Send('p', Encoding.UTF8.GetBytes(final + ",p=" + Convert.ToBase64String(clientKey)));
                }
                else if (type == 12)
                {
                    string final = Encoding.UTF8.GetString(data.AsSpan(4));
                    if (!final.StartsWith("v=", StringComparison.Ordinal) || expected is null || !CryptographicOperations.FixedTimeEquals(expected, Convert.FromBase64String(final[2..]))) throw new IOException("SCRAM server proof mismatch");
                }
                else if (type != 0) throw new IOException("Unsupported PostgreSQL authentication " + type);
            }
            else if (tag == 'E') throw Error(data);
            else if (tag == 'Z') return c;
        }
    }
    public async Task<List<string[]>> Query(string sql)
    {
        await Send('Q', Encoding.UTF8.GetBytes(sql + "\0"));
        var rows = new List<string[]>();
        while (true)
        {
            var (tag, data) = await Receive();
            if (tag == 'E') throw Error(data);
            if (tag == 'Z') return rows;
            if (tag != 'D') continue;
            int count = BinaryPrimitives.ReadInt16BigEndian(data), offset = 2;
            var row = new string[count];
            for (int i = 0; i < count; i++) { int length = BinaryPrimitives.ReadInt32BigEndian(data.AsSpan(offset)); offset += 4; row[i] = length < 0 ? "" : Encoding.UTF8.GetString(data, offset, length); if (length > 0) offset += length; }
            rows.Add(row);
        }
    }
    private async Task Send(char tag, byte[] data) => await Stream.WriteAsync((byte[])[(byte)tag, .. I32(data.Length + 4), .. data]);
    private async Task<(char Tag, byte[] Data)> Receive()
    {
        byte[] header = new byte[5]; await Stream.ReadExactlyAsync(header);
        int length = BinaryPrimitives.ReadInt32BigEndian(header.AsSpan(1)) - 4;
        if (length is < 0 or > 10_000_000) throw new IOException("Invalid PostgreSQL frame");
        byte[] payload = new byte[length]; await Stream.ReadExactlyAsync(payload); return ((char)header[0], payload);
    }
    private static IOException Error(byte[] data) => new("Actual PostgreSQL error: " + Encoding.UTF8.GetString(data).Replace('\0', ' '));
    private static byte[] I32(int number) { byte[] data = new byte[4]; BinaryPrimitives.WriteInt32BigEndian(data, number); return data; }
    public ValueTask DisposeAsync() { socket.Dispose(); return ValueTask.CompletedTask; }
}
