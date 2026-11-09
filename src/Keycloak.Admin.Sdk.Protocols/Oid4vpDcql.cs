using System.Text.Json;

namespace Keycloak.Admin.Sdk.Protocols;

// Keycloak 26.8.1 extracts one SD-JWT presentation. The wallet also enforces the requested type and
// disclosed claims, because the upstream verifier currently leaves those DCQL checks to a future task.
internal static class Oid4vpDcql
{
    internal static void Require(JsonElement query, string id, JsonElement claims)
    {
        WalletJson.Object(query); var credentials = query.GetProperty("credentials");
        if (credentials.ValueKind != JsonValueKind.Array || credentials.GetArrayLength() != 1 || query.EnumerateObject().Any(p => p.Name != "credentials"))
            throw new InvalidDataException("The Keycloak verifier profile accepts one explicit credential query.");
        var requested = credentials[0]; WalletJson.Object(requested);
        if (WalletJson.String(requested, "id") != id || WalletJson.String(requested, "format") != "dc+sd-jwt"
            || requested.EnumerateObject().Any(p => p.Name is not ("id" or "format" or "meta" or "claims" or "claim_sets" or "require_cryptographic_holder_binding" or "multiple")))
            throw new InvalidDataException("Unsupported credential query contract.");
        if (requested.TryGetProperty("multiple", out var multiple) && multiple.GetBoolean()) throw new InvalidDataException("Multiple credentials are not supported by this Keycloak verifier.");
        if (requested.TryGetProperty("require_cryptographic_holder_binding", out var binding) && !binding.GetBoolean()) throw new InvalidDataException("This wallet profile requires holder binding.");
        var meta = requested.GetProperty("meta"); WalletJson.Object(meta);
        var types = meta.GetProperty("vct_values");
        if (types.ValueKind != JsonValueKind.Array || !types.EnumerateArray().Any(t => t.ValueKind == JsonValueKind.String && t.GetString() == WalletJson.String(claims, "vct")))
            throw new InvalidDataException("Credential does not satisfy the requested type.");
        if (!requested.TryGetProperty("claims", out var required)) return;
        if (required.ValueKind != JsonValueKind.Array || required.GetArrayLength() > 100) throw new InvalidDataException("Invalid bounded DCQL claims query.");
        var satisfied = new Dictionary<string, bool>(StringComparer.Ordinal); var outcomes = new List<bool>();
        foreach (var claim in required.EnumerateArray())
        {
            WalletJson.Object(claim);
            if (claim.EnumerateObject().Any(p => p.Name is not ("id" or "path" or "values"))) throw new InvalidDataException("Unsupported DCQL claim requirement.");
            var path = claim.GetProperty("path");
            if (path.ValueKind != JsonValueKind.Array || path.GetArrayLength() is 0 or > 32) throw new InvalidDataException("Invalid DCQL claim path.");
            IEnumerable<JsonElement> selected = [claims];
            foreach (var part in path.EnumerateArray())
            {
                if (part.ValueKind == JsonValueKind.String) selected = selected.Where(v => v.ValueKind == JsonValueKind.Object && v.TryGetProperty(part.GetString()!, out _)).Select(v => v.GetProperty(part.GetString()!)).ToArray();
                else if (part.ValueKind == JsonValueKind.Null) selected = selected.Where(v => v.ValueKind == JsonValueKind.Array).SelectMany(v => v.EnumerateArray()).ToArray();
                else if (part.ValueKind == JsonValueKind.Number && part.TryGetInt32(out int index) && index >= 0) selected = selected.Where(v => v.ValueKind == JsonValueKind.Array && index < v.GetArrayLength()).Select(v => v[index]).ToArray();
                else throw new InvalidDataException("Invalid DCQL claim path component.");
            }
            bool present = selected.Any();
            if (claim.TryGetProperty("values", out var values))
            {
                if (values.ValueKind != JsonValueKind.Array || values.GetArrayLength() is 0 or > 100) throw new InvalidDataException("Invalid DCQL claim values.");
                present = selected.Any(v => values.EnumerateArray().Any(expected => JsonElement.DeepEquals(v, expected)));
            }
            outcomes.Add(present);
            if (claim.TryGetProperty("id", out var claimId) && !satisfied.TryAdd(claimId.GetString()!, present)) throw new InvalidDataException("Duplicate DCQL claim identifier.");
        }
        if (requested.TryGetProperty("claim_sets", out var sets))
        {
            if (sets.ValueKind != JsonValueKind.Array || sets.GetArrayLength() is 0 or > 100) throw new InvalidDataException("Invalid DCQL claim sets.");
            if (!sets.EnumerateArray().Any(set => set.ValueKind == JsonValueKind.Array && set.GetArrayLength() > 0 && set.EnumerateArray().All(name => name.ValueKind == JsonValueKind.String && satisfied.GetValueOrDefault(name.GetString()!))))
                throw new InvalidDataException("Selected disclosures do not satisfy a requested claim set.");
        }
        else if (outcomes.Any(present => !present)) throw new InvalidDataException("Selected disclosures omit a required claim.");
    }
}
