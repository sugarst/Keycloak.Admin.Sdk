using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.IdentityModel.Tokens;

namespace Keycloak.Admin.Sdk.Protocols;

/// <summary>RFC 9901 disclosure processing after issuer signature verification. No issuer or key is fetched from a disclosure.</summary>
internal static class SdJwtDisclosures
{
    internal static JsonElement Resolve(JsonElement signedClaims, IReadOnlyList<string> disclosures)
    {
        if (disclosures.Count > 100) throw new InvalidDataException("Too many selective disclosures.");
        WalletJson.Object(signedClaims);
        string algorithm = signedClaims.TryGetProperty("_sd_alg", out var alg) ? alg.GetString()! : "sha-256";
        Hash(algorithm, ""); // Validate the declared hash even when no disclosure is presented.
        var supplied = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        foreach (string encoded in disclosures)
        {
            if (encoded.Length is 0 or > 65536 || encoded.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('-' or '_')))
                throw new InvalidDataException("Invalid disclosure encoding.");
            using var document = JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(encoded), new JsonDocumentOptions { MaxDepth = 32 });
            var value = document.RootElement;
            if (value.ValueKind != JsonValueKind.Array || value.GetArrayLength() is not (2 or 3) || value[0].ValueKind != JsonValueKind.String || value[0].GetString()!.Length == 0
                || !supplied.TryAdd(Hash(algorithm, encoded), value.Clone())) throw new InvalidDataException("Invalid or duplicate disclosure.");
        }
        var used = new HashSet<string>(StringComparer.Ordinal); var seen = new HashSet<string>(StringComparer.Ordinal);
        JsonNode? Visit(JsonElement value, int depth)
        {
            if (depth > 32) throw new InvalidDataException("Selective disclosure nesting exceeds its bound.");
            JsonElement? Disclosure(string digest)
            {
                if (!seen.Add(digest) || seen.Count > 1000) throw new InvalidDataException("Repeated or excessive disclosure digest.");
                if (!supplied.TryGetValue(digest, out var result)) return null;
                used.Add(digest); return result;
            }
            if (value.ValueKind == JsonValueKind.Object)
            {
                WalletJson.Object(value); var result = new JsonObject();
                foreach (var property in value.EnumerateObject())
                {
                    if (property.Name == "...") throw new InvalidDataException("A disclosure array placeholder cannot be an object claim.");
                    if (property.Name == "_sd_alg") { if (depth != 0) throw new InvalidDataException("Nested disclosure hash algorithm."); continue; }
                    if (property.Name != "_sd") result[property.Name] = Visit(property.Value, depth + 1);
                }
                if (value.TryGetProperty("_sd", out var digests))
                {
                    if (digests.ValueKind != JsonValueKind.Array) throw new InvalidDataException("Disclosure digests must be an array.");
                    foreach (var digest in digests.EnumerateArray())
                    {
                        if (digest.ValueKind != JsonValueKind.String || string.IsNullOrEmpty(digest.GetString())) throw new InvalidDataException("Invalid disclosure digest.");
                        if (Disclosure(digest.GetString()!) is not { } item) continue;
                        if (item.GetArrayLength() != 3 || item[1].ValueKind != JsonValueKind.String) throw new InvalidDataException("An object disclosure requires a claim name.");
                        string name = item[1].GetString()!;
                        if (name is "_sd" or "..." or "_sd_alg" || result.ContainsKey(name)) throw new InvalidDataException("Disclosures cannot overwrite signed claims.");
                        result[name] = Visit(item[2], depth + 1);
                    }
                }
                return result;
            }
            if (value.ValueKind == JsonValueKind.Array)
            {
                var result = new JsonArray();
                foreach (var item in value.EnumerateArray())
                {
                    if (item.ValueKind == JsonValueKind.Object && item.TryGetProperty("...", out var digest))
                    {
                        WalletJson.Object(item);
                        if (item.EnumerateObject().Count() != 1 || digest.ValueKind != JsonValueKind.String || string.IsNullOrEmpty(digest.GetString())) throw new InvalidDataException("Invalid array disclosure placeholder.");
                        if (Disclosure(digest.GetString()!) is not { } disclosed) continue;
                        if (disclosed.GetArrayLength() != 2) throw new InvalidDataException("An array disclosure cannot contain a claim name.");
                        result.Add(Visit(disclosed[1], depth + 1));
                    }
                    else result.Add(Visit(item, depth + 1));
                }
                return result;
            }
            return JsonNode.Parse(value.GetRawText());
        }
        var resolved = Visit(signedClaims, 0);
        if (used.Count != supplied.Count) throw new InvalidDataException("A disclosure is not bound to the signed credential.");
        using var output = JsonDocument.Parse(resolved!.ToJsonString()); return output.RootElement.Clone();
    }
    internal static string Hash(string algorithm, string text)
    {
        byte[] bytes = Encoding.ASCII.GetBytes(text);
        byte[] digest = algorithm switch { "sha-256" => SHA256.HashData(bytes), "sha-384" => SHA384.HashData(bytes), "sha-512" => SHA512.HashData(bytes), _ => throw new InvalidDataException("Unsupported selective-disclosure hash algorithm.") };
        return Base64UrlEncoder.Encode(digest);
    }
}
