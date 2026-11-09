using System.Formats.Cbor;
using System.Globalization;
using System.Text.Json.Nodes;

namespace Keycloak.Admin.Sdk.Protocols;

internal static class MdocCbor
{
    private static CborReader Reader(ReadOnlyMemory<byte> value) => new(value, CborConformanceMode.Strict);
    private static void End(CborReader reader) { if (reader.BytesRemaining != 0) throw new InvalidDataException("Trailing mdoc CBOR content."); }
    internal static Dictionary<string, ReadOnlyMemory<byte>> Map(ReadOnlyMemory<byte> bytes)
    {
        var reader = Reader(bytes); reader.ReadStartMap(); var result = new Dictionary<string, ReadOnlyMemory<byte>>(StringComparer.Ordinal);
        while (reader.PeekState() != CborReaderState.EndMap)
        {
            if (result.Count >= 1000 || !result.TryAdd(reader.ReadTextString(), reader.ReadEncodedValue())) throw new InvalidDataException("Duplicate or excessive mdoc map key.");
        }
        reader.ReadEndMap(); End(reader); return result;
    }
    internal static Dictionary<long, ReadOnlyMemory<byte>> IntegerMap(ReadOnlyMemory<byte> bytes)
    {
        var reader = Reader(bytes); reader.ReadStartMap(); var result = new Dictionary<long, ReadOnlyMemory<byte>>();
        while (reader.PeekState() != CborReaderState.EndMap)
        {
            if (result.Count >= 1000 || !result.TryAdd(reader.ReadInt64(), reader.ReadEncodedValue())) throw new InvalidDataException("Duplicate or excessive mdoc integer key.");
        }
        reader.ReadEndMap(); End(reader); return result;
    }
    internal static ReadOnlyMemory<byte>[] Array(ReadOnlyMemory<byte> bytes)
    {
        var reader = Reader(bytes); reader.ReadStartArray(); var result = new List<ReadOnlyMemory<byte>>();
        while (reader.PeekState() != CborReaderState.EndArray)
        {
            if (result.Count >= 1000) throw new InvalidDataException("Excessive mdoc array elements."); result.Add(reader.ReadEncodedValue());
        }
        reader.ReadEndArray(); End(reader); return result.ToArray();
    }
    internal static byte[] Bytes(ReadOnlyMemory<byte> bytes) { var reader = Reader(bytes); var value = reader.ReadByteString(); End(reader); return value; }
    internal static string Text(ReadOnlyMemory<byte> bytes) { var reader = Reader(bytes); string value = reader.ReadTextString(); End(reader); return value; }
    internal static long Integer(ReadOnlyMemory<byte> bytes) { var reader = Reader(bytes); long value = reader.ReadInt64(); End(reader); return value; }
    internal static byte[] Embedded(ReadOnlyMemory<byte> bytes)
    { var reader = Reader(bytes); if ((ulong)reader.ReadTag() != 24) throw new InvalidDataException("An encoded-CBOR tag is required."); var value = reader.ReadByteString(); End(reader); return value; }
    internal static DateTimeOffset Date(ReadOnlyMemory<byte> bytes)
    {
        var reader = Reader(bytes);
        if ((ulong)reader.ReadTag() != 0) throw new InvalidDataException("An mdoc date-time tag is required.");
        string text = reader.ReadTextString(); End(reader);
        if (!DateTimeOffset.TryParseExact(text, ["yyyy-MM-dd'T'HH:mm:ssK", "yyyy-MM-dd'T'HH:mm:ss.FFFFFFFK"], CultureInfo.InvariantCulture, DateTimeStyles.None, out var value)) throw new InvalidDataException("Invalid mdoc date-time.");
        return value;
    }
    internal static JsonNode? Json(ReadOnlyMemory<byte> bytes, int depth = 0)
    {
        if (depth > 32) throw new InvalidDataException("Mdoc claim nesting exceeds its bound.");
        var reader = Reader(bytes);
        switch (reader.PeekState())
        {
            case CborReaderState.StartMap:
                var obj = new JsonObject(); foreach (var pair in Map(bytes)) obj[pair.Key] = Json(pair.Value, depth + 1); return obj;
            case CborReaderState.StartArray:
                var array = new JsonArray(); foreach (var value in Array(bytes)) array.Add(Json(value, depth + 1)); return array;
            case CborReaderState.TextString: return JsonValue.Create(Text(bytes));
            case CborReaderState.UnsignedInteger: case CborReaderState.NegativeInteger: return JsonValue.Create(Integer(bytes));
            case CborReaderState.Boolean: var boolean = reader.ReadBoolean(); End(reader); return JsonValue.Create(boolean);
            case CborReaderState.Null: reader.ReadNull(); End(reader); return null;
            case CborReaderState.ByteString: return JsonValue.Create(Convert.ToBase64String(Bytes(bytes)));
            case CborReaderState.HalfPrecisionFloat: case CborReaderState.SinglePrecisionFloat: case CborReaderState.DoublePrecisionFloat:
                double number = reader.ReadDouble(); End(reader); if (!double.IsFinite(number)) throw new InvalidDataException("Non-finite mdoc claim."); return JsonValue.Create(number);
            default: throw new InvalidDataException("Unsupported mdoc claim encoding.");
        }
    }
}
