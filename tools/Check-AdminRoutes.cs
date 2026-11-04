#!/usr/bin/env -S dotnet --
#:property TargetFramework=net10.0
#:property PublishAot=false
#:include ScriptSupport.cs
#:include ../tests/Keycloak.Admin.Sdk.IntegrationTests/KeycloakRouteSupport.cs
#:project ../src/Keycloak.Admin.Sdk/Keycloak.Admin.Sdk.csproj

using System.Text.Json;
using System.Text.RegularExpressions;
using Keycloak.Admin.Sdk;

return await ScriptHost.ExecuteAsync(args, "dotnet run --file tools/Check-AdminRoutes.cs -- [--source]", ["--source"], async ct =>
{
    string root = ScriptHost.RepositoryRoot();
    var stable = KeycloakRoute.Load(root, "fgap-v2-stable");
    var compat = KeycloakRoute.Load(root, "fgap-v1-compat");
    using var correct = JsonDocument.Parse("""{"systemInfo":{"version":"26.8.1"},"profileInfo":{"disabledFeatures":["ADMIN_FINE_GRAINED_AUTHZ"],"previewFeatures":["OID4VC_VCI"],"experimentalFeatures":["SSF"]},"features":[{"name":"ADMIN_FINE_GRAINED_AUTHZ_V2","type":"DEFAULT","enabled":true},{"name":"OID4VC_VCI","type":"PREVIEW","enabled":false}]}""");
    stable.ValidateServer(correct.RootElement);
    void Reject(Action action)
    {
        try { action(); } catch (InvalidDataException) { return; }
        throw new InvalidOperationException("Route policy accepted a negative control.");
    }
    Reject(() => compat.ValidateServer(correct.RootElement));
    Reject(() => KeycloakRoute.Load(root, "unknown-route"));
    using var previewEnabled = JsonDocument.Parse(correct.RootElement.GetRawText().Replace("\"type\":\"PREVIEW\",\"enabled\":false", "\"type\":\"PREVIEW\",\"enabled\":true", StringComparison.Ordinal));
    Reject(() => stable.ValidateServer(previewEnabled.RootElement));
    using var desiredDisabled = JsonDocument.Parse(correct.RootElement.GetRawText().Replace("\"type\":\"DEFAULT\",\"enabled\":true", "\"type\":\"DEFAULT\",\"enabled\":false", StringComparison.Ordinal));
    Reject(() => stable.ValidateServer(desiredDisabled.RootElement));
    if (args.Contains("--source"))
    {
        string java = await File.ReadAllTextAsync(Path.Combine(root, ".cache/keycloak/pinned-source/common/src/main/java/org/keycloak/common/Profile.java"), ct);
        foreach (var feature in stable.ExcludedFeatures)
        {
            string symbol = feature.Feature.Replace('-', '_').ToUpperInvariant();
            if (!Regex.IsMatch(java, @"\b" + symbol + @"\([^\r\n]*Type\." + feature.Type)) throw new InvalidDataException("Feature stage differs from pinned release source: " + feature.Feature);
        }
        if (!Regex.IsMatch(java, @"\bWORKFLOWS\([^\r\n]*Type\.DEFAULT")) throw new InvalidDataException("Review workflows release maturity.");
    }
    var rows = new List<string> { "method\tpath\tsdkMethod\tfgapV2Scope\tfgapV2Reason\tfgapV1Scope\tfgapV1Reason" };
    foreach (var e in AdminEndpointCatalog.All)
    {
        string? v2 = stable.Exclusion(e.Path), v1 = compat.Exclusion(e.Path);
        rows.Add(string.Join('\t', e.Method, e.Path, e.Operation, v2 is null ? "in-scope" : "excluded", v2 ?? "stable 26.8.1", v1 is null ? "in-scope" : "excluded", v1 ?? "26.8.1 compatibility route"));
    }
    await File.WriteAllLinesAsync(Path.Combine(root, "docs/contracts/admin-api-support-matrix.tsv"), rows, ct);
    Console.WriteLine($"PASS route policy and negative controls. Stable scope: {AdminEndpointCatalog.All.Count(e => stable.Exclusion(e.Path) is null)}; compatibility scope: {AdminEndpointCatalog.All.Count(e => compat.Exclusion(e.Path) is null)}.");
});
