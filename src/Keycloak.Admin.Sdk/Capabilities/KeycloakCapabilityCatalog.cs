using System.Text.Json;

namespace Keycloak.Admin.Sdk.Capabilities;

/// <summary>Exactly one immutable target per SDK build. Historical targets belong to historical packages.</summary>
public static class KeycloakCapabilityCatalog
{
    public static KeycloakReleaseCapabilities Current { get; } = Load();
    public static KeycloakReleaseCapabilities? Find(string version) => Current.ServerVersion == version ? Current : null;

    private static KeycloakReleaseCapabilities Load()
    {
        using var stream = typeof(KeycloakCapabilityCatalog).Assembly.GetManifestResourceStream("Keycloak.Capabilities.Current.json")!;
        using var document = JsonDocument.Parse(stream);
        return Read(document.RootElement);
    }

    internal static KeycloakReleaseCapabilities Read(JsonElement root)
    {
        int schema = root.GetProperty("schemaVersion").GetInt32();
        if (schema is not (1 or 2)) throw new InvalidDataException("Unknown capability catalog schema.");
        var profiles = schema == 1 ? [] : root.GetProperty("verificationProfiles").EnumerateArray().Select(ReadProfile).ToArray();
        if (profiles.Select(p => p.Id).Distinct(StringComparer.Ordinal).Count() != profiles.Length)
            throw new InvalidDataException("Duplicate verification profile.");
        var byId = profiles.ToDictionary(p => p.Id, StringComparer.Ordinal);
        var endpoints = root.GetProperty("endpoints").EnumerateArray().Select(e => new KeycloakEndpointCapability(
            e.GetProperty("operation").GetString()!, e.GetProperty("method").GetString()!, e.GetProperty("path").GetString()!, e.GetProperty("featureId").GetString()!,
            Enum.Parse<KeycloakFeatureStage>(e.GetProperty("stage").GetString()!),
            Enum.Parse<KeycloakImplementationStatus>(e.GetProperty("implementation").GetString()!),
            Enum.Parse<KeycloakSupportStatus>(e.GetProperty("support").GetString()!),
            Enum.Parse<KeycloakVerification>(e.GetProperty("verification").GetString()!),
            e.GetProperty("requiredServerFeatures").EnumerateArray().Select(f => f.GetString()!).ToArray(), e.GetProperty("evidence").GetString()!,
            e.GetProperty("routes").EnumerateArray().Select(r => Enum.Parse<KeycloakAdminRoute>(r.GetString()!)).ToArray(),
            schema == 1 ? [] : e.GetProperty("supportProfiles").EnumerateArray().Select(id => byId.TryGetValue(id.GetString()!, out var profile)
                ? profile : throw new InvalidDataException("Unknown verification profile reference.")).ToArray())).ToArray();
        if (schema == 2)
            foreach (var endpoint in endpoints)
            {
                if (endpoint.SupportProfiles.Select(p => p.Id).Distinct(StringComparer.Ordinal).Count() != endpoint.SupportProfiles.Count
                    || endpoint.SupportProfiles.Any(p => !endpoint.Routes.Contains(p.Route) || (endpoint.Verification & p.Verification) != p.Verification)
                    || (endpoint.Support == KeycloakSupportStatus.NotSupported && endpoint.SupportProfiles.Count != 0)
                    || (endpoint.Support != KeycloakSupportStatus.NotSupported && endpoint.SupportProfiles.Count == 0))
                    throw new InvalidDataException("Inconsistent endpoint verification profiles.");
            }
        return new(root.GetProperty("serverVersion").GetString()!, root.GetProperty("sourceCommit").GetString()!, endpoints, profiles, schema);
    }

    private static KeycloakVerificationProfile ReadProfile(JsonElement p)
    {
        var runtime = Enum.Parse<KeycloakRuntimeProfile>(p.GetProperty("runtime").GetString()!);
        var route = Enum.Parse<KeycloakAdminRoute>(p.GetProperty("route").GetString()!);
        var verification = Enum.Parse<KeycloakVerification>(p.GetProperty("verification").GetString()!);
        string? rid = p.GetProperty("runtimeIdentifier").GetString();
        string fingerprint = p.GetProperty("sourceFingerprint").GetString()!, digest = p.GetProperty("evidenceSha256").GetString()!;
        string id = p.GetProperty("id").GetString()!, evidence = p.GetProperty("evidence").GetString()!;
        KeycloakVerification required = KeycloakVerification.Contract | (runtime == KeycloakRuntimeProfile.Managed ? KeycloakVerification.Managed : KeycloakVerification.NativeAot);
        static bool Hash(string value) => value.Length == 64 && value.All(c => char.IsAsciiHexDigit(c));
        if (!Enum.IsDefined(route) || runtime is not (KeycloakRuntimeProfile.Managed or KeycloakRuntimeProfile.NativeAot)
            || (verification & required) != required || (verification & ~(KeycloakVerification.Contract | KeycloakVerification.Managed | KeycloakVerification.NativeAot)) != 0
            || (runtime == KeycloakRuntimeProfile.Managed ? rid is not null : string.IsNullOrWhiteSpace(rid) || rid.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '-'))
            || !Hash(fingerprint) || !Hash(digest) || string.IsNullOrWhiteSpace(id) || string.IsNullOrWhiteSpace(evidence))
            throw new InvalidDataException("Invalid verification profile.");
        return new(id, route, runtime, rid, verification, fingerprint, evidence, digest);
    }
}
