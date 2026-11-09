using System.Text.Json;
using System.Text.Json.Nodes;
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Capabilities;

internal static class FeatureAcceptance
{
    public static FeatureValidationPlan Validate(string root, JsonObject report, bool requireGuarded)
    {
        var target = TargetBaseline.Load(root);
        string Text(string name) => report[name]?.GetValue<string>() ?? throw new InvalidDataException("Missing feature evidence field: " + name);
        var plan = FeatureValidationPlan.Load(root, Text("plan"));
        string mode = Text("mode"), route = Text("route"), phase = Text("phase");
        bool native = mode == "native-aot";
        string? rid = report["runtimeIdentifier"]?.GetValue<string>();
        static bool Hash(string value) => value.Length == 64 && value.All(char.IsAsciiHexDigit);
        if (report["schemaVersion"]?.GetValue<int>() != 1 || report["completed"]?.GetValue<bool>() != true
            || Text("serverVersion") != target.Version || Text("keycloakSourceCommit") != target.Commit
            || Text("featureId") != plan.FeatureId || Text("stage") != plan.Stage.ToString()
            || Text("validationFingerprint") != LiveEvidence.ValidationFingerprint(root)
            || mode is not ("managed" or "native-aot") || route is not ("fgap-v2-stable" or "fgap-v1-compat")
            || phase is not ("candidate" or "guarded") || (requireGuarded && phase != "guarded")
            || !Hash(Text("executableSha256")) || report["nativePublished"]?.GetValue<bool>() != native
            || (native ? string.IsNullOrWhiteSpace(rid) || rid.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '-') : rid is not null))
            throw new InvalidDataException("Incomplete, wrong-target/runtime or stale feature evidence.");
        using var server = JsonDocument.Parse(report["serverInfo"]?.ToJsonString() ?? throw new InvalidDataException("Missing actual server features."));
        KeycloakRoute.Load(root, route).ValidateServer(server.RootElement, plan.ServerFeatures.ToHashSet(StringComparer.Ordinal));
        foreach (string feature in plan.ServerFeatures.Append("ADMIN_API"))
            if (!server.RootElement.GetProperty("features").EnumerateArray().Any(f => f.GetProperty("name").GetString() == feature && f.GetProperty("enabled").GetBoolean()))
                throw new InvalidDataException("Required server feature is disabled or unknown.");
        if (requireGuarded && (Text("catalogSha256") != CapabilityEvidence.Digest(Path.Combine(root, "contracts/capabilities.json"))
            || report["flagDenialVerified"]?.GetValue<bool>() != true || Text("gate") != (native ? "core-snapshot" : "platform-snapshot")))
            throw new InvalidDataException("Final feature acceptance requires the current catalog and runtime host gate.");
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var node in report["operations"]?.AsArray() ?? throw new InvalidDataException("Missing operation proofs."))
        {
            string operation = node?["operation"]?.GetValue<string>() ?? "";
            var endpoint = KeycloakCapabilityCatalog.Current.Endpoints.SingleOrDefault(e => e.Operation == operation);
            if (endpoint is null || !plan.Operations.Contains(operation) || !seen.Add(operation)
                || node!["method"]?.GetValue<string>() != endpoint.Method || node["path"]?.GetValue<string>() != endpoint.Path
                || node["status"]?.GetValue<int>() is not (>= 200 and < 300) || string.IsNullOrWhiteSpace(node["proof"]?.GetValue<string>()))
                throw new InvalidDataException("Missing, duplicate, unsuccessful or incorrect feature operation proof.");
        }
        if (!seen.SetEquals(plan.Operations)) throw new InvalidDataException("Feature plan has unverified operations.");
        return plan;
    }

    public static void Promote(string root, string reportPath)
    {
        var report = JsonNode.Parse(File.ReadAllText(reportPath))!.AsObject();
        var plan = Validate(root, report, false);
        var catalog = JsonNode.Parse(File.ReadAllText(Path.Combine(root, "contracts/capabilities.json")))!.AsObject();
        var target = TargetBaseline.Load(root);
        if (catalog["schemaVersion"]!.GetValue<int>() != 2 || catalog["serverVersion"]!.GetValue<string>() != target.Version || catalog["sourceCommit"]!.GetValue<string>() != target.Commit)
            throw new InvalidDataException("Cannot promote into another target catalog.");
        string mode = report["mode"]!.GetValue<string>() == "managed" ? "Managed" : "NativeAot";
        string route = report["route"]!.GetValue<string>() == "fgap-v2-stable" ? "FgapV2Stable" : "FgapV1Compatibility";
        string id = CapabilityEvidence.Digest(reportPath);
        var profiles = catalog["verificationProfiles"]!.AsArray();
        if (!profiles.Any(p => p!["id"]!.GetValue<string>() == id))
            profiles.Add(new JsonObject
            {
                ["id"] = id, ["route"] = route, ["runtime"] = mode, ["runtimeIdentifier"] = report["runtimeIdentifier"]?.DeepClone(),
                ["verification"] = "Contract, " + mode, ["sourceFingerprint"] = report["validationFingerprint"]!.DeepClone(),
                ["evidence"] = CapabilityEvidence.Archive(root, reportPath), ["evidenceSha256"] = id
            });
        foreach (var endpoint in catalog["endpoints"]!.AsArray().Where(e => plan.Operations.Contains(e!["operation"]!.GetValue<string>())))
        {
            if (!endpoint!["routes"]!.AsArray().Any(r => r!.GetValue<string>() == route)) throw new InvalidDataException("Evidence route is unavailable for operation.");
            var ids = endpoint["supportProfiles"]!.AsArray();
            for (int i = ids.Count - 1; i >= 0; i--)
            {
                var old = profiles.Single(p => p!["id"]!.GetValue<string>() == ids[i]!.GetValue<string>())!;
                if (old["route"]!.GetValue<string>() == route && old["runtime"]!.GetValue<string>() == mode
                    && old["runtimeIdentifier"]?.GetValue<string>() == report["runtimeIdentifier"]?.GetValue<string>()) ids.RemoveAt(i);
            }
            ids.Add(JsonValue.Create(id)); CapabilityEvidence.RefreshAggregate(endpoint.AsObject(), profiles);
            endpoint["evidence"] = "verificationProfiles:" + id;
        }
        var used = catalog["endpoints"]!.AsArray().SelectMany(e => e!["supportProfiles"]!.AsArray().Select(p => p!.GetValue<string>())).ToHashSet(StringComparer.Ordinal);
        for (int i = profiles.Count - 1; i >= 0; i--) if (!used.Contains(profiles[i]!["id"]!.GetValue<string>())) profiles.RemoveAt(i);
        File.WriteAllText(Path.Combine(root, "contracts/capabilities.json"), CapabilityEvidence.Json(catalog).Replace("\r\n", "\n", StringComparison.Ordinal) + "\n");
    }

    public static IEnumerable<(FeatureValidationPlan Plan, string Route, string Mode, string? Rid)> Supported(string root)
    {
        using var plans = JsonDocument.Parse(File.ReadAllText(Path.Combine(root, "contracts/feature-validation-plans.json")));
        foreach (var endpoint in KeycloakCapabilityCatalog.Current.Endpoints.Where(e => e.Stage is Keycloak.Admin.Sdk.Capabilities.KeycloakFeatureStage.Preview or Keycloak.Admin.Sdk.Capabilities.KeycloakFeatureStage.Experimental))
        foreach (var profile in endpoint.SupportProfiles)
        {
            string id = plans.RootElement.GetProperty("plans").EnumerateObject().Single(p => p.Value.GetProperty("featureId").GetString() == endpoint.FeatureId).Name;
            yield return (FeatureValidationPlan.Load(root, id), profile.Route == Keycloak.Admin.Sdk.Capabilities.KeycloakAdminRoute.FgapV2Stable ? "fgap-v2-stable" : "fgap-v1-compat",
                profile.Runtime == Keycloak.Admin.Sdk.Capabilities.KeycloakRuntimeProfile.Managed ? "managed" : "native-aot", profile.RuntimeIdentifier);
        }
    }
}
