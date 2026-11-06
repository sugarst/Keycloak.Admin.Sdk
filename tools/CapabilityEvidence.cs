using System.Security.Cryptography;
using System.Text.Json.Nodes;
using System.Text.Json;
using System.Text.Json.Serialization;

// Build-time evidence handling only. Production clients cannot load a host-supplied support catalog.
internal static class CapabilityEvidence
{
    public static string Json(JsonNode node) => node.ToJsonString(new JsonSerializerOptions { WriteIndented = true, TypeInfoResolver = CapabilityEvidenceJsonContext.Default });
    public static string Digest(string path) => Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path)));
    public static string Archive(string root, string path)
    {
        string relative = "docs/contracts/capability-evidence/" + Digest(path) + ".json";
        string destination = Path.Combine(root, relative);
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        if (File.Exists(destination))
        {
            if (Digest(destination) != Digest(path)) throw new InvalidDataException("Immutable evidence collision.");
        }
        else File.Copy(path, destination);
        return relative;
    }

    public static void ImportFullAcceptance(string root, JsonObject catalog, string directory, bool promote = false)
    {
        var nonStableIds = catalog["endpoints"]!.AsArray().Where(e => e!["stage"]!.GetValue<string>() is "Preview" or "Experimental")
            .SelectMany(e => e!["supportProfiles"]?.AsArray().Select(id => id!.GetValue<string>()) ?? []).ToHashSet(StringComparer.Ordinal);
        var profiles = new JsonArray();
        foreach (var old in catalog["verificationProfiles"]?.AsArray() ?? [])
            if (nonStableIds.Contains(old!["id"]!.GetValue<string>())) profiles.Add(old.DeepClone());
        foreach (var entry in catalog["endpoints"]!.AsArray())
            if (entry!["stage"]!.GetValue<string>() is not ("Preview" or "Experimental")) entry["supportProfiles"] = new JsonArray();
        foreach (string route in new[] { "fgap-v2-stable", "fgap-v1-compat" })
        foreach (string mode in new[] { "managed", "native-aot" })
        {
            string path = Path.Combine(directory, route + "-" + mode + ".json");
            var report = JsonNode.Parse(File.ReadAllText(path))!.AsObject();
            if (report["route"]!.GetValue<string>() != route || report["mode"]!.GetValue<string>() != mode || !report["completed"]!.GetValue<bool>()
                || report["missing"]!.GetValue<int>() != 0 || report["accepted"]!.GetValue<int>() != report["expected"]!.GetValue<int>()
                || report["evidence"]!["serverVersion"]!.GetValue<string>() != catalog["serverVersion"]!.GetValue<string>())
                throw new InvalidDataException("Incomplete or wrong-target full acceptance evidence.");
            string profileId = Digest(path), routeName = route == "fgap-v2-stable" ? "FgapV2Stable" : "FgapV1Compatibility";
            string modeName = mode == "managed" ? "Managed" : "NativeAot";
            HashSet<string>? passed = null;
            if (promote)
            {
                string ledger = Path.ChangeExtension(path, ".tsv");
                if (Digest(ledger) != report["ledgerSha256"]!.GetValue<string>()) throw new InvalidDataException("Full acceptance ledger hash mismatch.");
                passed = new(StringComparer.Ordinal);
                foreach (string row in File.ReadLines(ledger).Skip(1))
                {
                    string[] cells = row.Split('\t');
                    if (cells.Length != 4 || !int.TryParse(cells[2], out int status) || status is < 200 or >= 300 || string.IsNullOrWhiteSpace(cells[3]) || !passed.Add(cells[0] + " " + cells[1]))
                        throw new InvalidDataException("Invalid full acceptance operation proof.");
                }
            }
            profiles.Add(new JsonObject
            {
                ["id"] = profileId, ["route"] = routeName, ["runtime"] = modeName,
                ["runtimeIdentifier"] = mode == "managed" ? null : "linux-musl-x64",
                ["verification"] = "Contract, " + modeName, ["sourceFingerprint"] = report["sourceFingerprint"]!.DeepClone(),
                ["evidence"] = Archive(root, path), ["evidenceSha256"] = profileId
            });
            int selected = 0;
            foreach (var entry in catalog["endpoints"]!.AsArray())
            {
                // Import only existing verified claims; migration never promotes an unverified feature.
                if (entry!["stage"]!.GetValue<string>() is "Preview" or "Experimental"
                    || (passed is null ? entry["support"]!.GetValue<string>() == "NotSupported" : !passed.Contains(entry["method"]!.GetValue<string>() + " " + entry["path"]!.GetValue<string>()))
                    || !entry["routes"]!.AsArray().Any(r => r!.GetValue<string>() == routeName)) continue;
                entry["supportProfiles"]!.AsArray().Add(JsonValue.Create(profileId)); selected++;
            }
            if (selected != report["accepted"]!.GetValue<int>()) throw new InvalidDataException("Catalog claims differ from the archived acceptance scope.");
        }
        catalog["schemaVersion"] = 2; catalog["verificationProfiles"] = profiles;
    }

    public static void RefreshAggregate(JsonObject endpoint, JsonArray profiles)
    {
        var selected = endpoint["supportProfiles"]!.AsArray().Select(id => profiles.Single(p => p!["id"]!.GetValue<string>() == id!.GetValue<string>())!).ToArray();
        bool managed = selected.Any(p => p["runtime"]!.GetValue<string>() == "Managed"), native = selected.Any(p => p["runtime"]!.GetValue<string>() == "NativeAot");
        endpoint["verification"] = "Contract" + (managed ? ", Managed" : "") + (native ? ", NativeAot" : "");
        endpoint["support"] = selected.Length == 0 ? "NotSupported" : endpoint["stage"]!.GetValue<string>() == "Deprecated" ? "Compatibility" : "Supported";
    }
}

[JsonSerializable(typeof(JsonNode))]
[JsonSerializable(typeof(string))]
[JsonSerializable(typeof(int))]
[JsonSerializable(typeof(bool))]
internal partial class CapabilityEvidenceJsonContext : JsonSerializerContext;
