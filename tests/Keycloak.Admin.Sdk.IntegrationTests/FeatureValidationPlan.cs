using System.Text.Json;
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Capabilities;

internal sealed record FeatureValidationPlan(string Id, string FeatureId, KeycloakFeatureStage Stage, string[] ServerFeatures, string[] Operations)
{
    public static FeatureValidationPlan Load(string root, string id)
    {
        if (string.IsNullOrWhiteSpace(id) || id.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '-')) throw new InvalidDataException("Invalid validation plan ID.");
        using var json = JsonDocument.Parse(File.ReadAllText(Path.Combine(root, "contracts/feature-validation-plans.json")));
        var value = json.RootElement;
        if (value.GetProperty("schemaVersion").GetInt32() != 1 || value.GetProperty("serverVersion").GetString() != KeycloakTarget.Version
            || !value.GetProperty("plans").TryGetProperty(id, out var plan)) throw new InvalidDataException("Unknown or wrong-version validation plan.");
        string feature = plan.GetProperty("featureId").GetString()!;
        var stage = Enum.Parse<KeycloakFeatureStage>(plan.GetProperty("stage").GetString()!);
        string[] features = plan.GetProperty("serverFeatures").EnumerateArray().Select(f => f.GetString()!).ToArray();
        string[] operations = plan.GetProperty("operations").EnumerateArray().Select(f => f.GetString()!).ToArray();
        if (stage is not (KeycloakFeatureStage.Preview or KeycloakFeatureStage.Experimental) || features.Length == 0 || features.Any(string.IsNullOrWhiteSpace)
            || features.Distinct(StringComparer.Ordinal).Count() != features.Length || operations.Length == 0 || operations.Distinct(StringComparer.Ordinal).Count() != operations.Length
            || operations.Any(op => !KeycloakCapabilityCatalog.Current.Endpoints.Any(e => e.Operation == op && e.FeatureId == feature && e.Stage == stage
                && e.RequiredServerFeatures.Where(f => f != "ADMIN_API").All(features.Contains))))
            throw new InvalidDataException("Validation plan differs from the pinned capability contract.");
        return new(id, feature, stage, features, operations);
    }
    public string ResultPath(string root, string route, string mode, string? rid, bool guarded)
        => Path.Combine(root, "artifacts/feature-validation", Id, route + "-" + mode + (rid is null ? "" : "-" + rid) + (guarded ? "-guarded" : "-candidate") + ".json");
}
