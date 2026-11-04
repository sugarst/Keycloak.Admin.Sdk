using System.Net;
using System.Text;
using System.Text.Json;
using Keycloak.Admin.Sdk;

// Hand-written wire expectations from the Java implementations, independent of OpenAPI/generator fixtures.
public static class AlignmentContracts
{
    public static async Task CertificateUploadHasBodyAsync()
    {
        using var handler = new WireHandler(async (request, ct) =>
        {
            await Multipart(request, ["keystoreFormat", "Certificate PEM", "file", "certificate.pem", "certificate bytes"], ct);
            return Json("{\"certificate\":\"encoded\",\"publicKey\":\"key\"}");
        });
        using var http = new HttpClient(handler);
        var body = new MultipartFormDataContent(); body.Add(new StringContent("Certificate PEM"), "keystoreFormat"); body.Add(new StringContent("certificate bytes"), "file", "certificate.pem");
        var response = await Client(http).IdentityProviders.UploadCertificateAsync("realm", body);
        Require(response.Body?.Certificate == "encoded", "Implicit multipart request and certificate response contract");
    }
    public static async Task SamlExampleStringAsync()
    {
        using var handler = new WireHandler((_, _) => Task.FromResult(Json("\"<samlp:Response xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol'/>\"")));
        using var http = new HttpClient(handler);
        var reply = await Client(http).ClientScopeEvaluate.GenerateExampleSamlResponseAsync("realm", "client", userId: "user");
        Require(reply.Body is not null && reply.Body.StartsWith("<samlp:Response", StringComparison.Ordinal), "@JsonValue SAML wrapper is read as a JSON string");
    }
    public static async Task WorkflowArraysAsync()
    {
        using var handler = new WireHandler((r, _) =>
        {
            Require(r.Method == HttpMethod.Get && r.RequestUri!.AbsolutePath == "/admin/realms/demo/workflows/scheduled/user-1", "Scheduled workflow route");
            return Task.FromResult(Json("[]"));
        });
        using var http = new HttpClient(handler);
        var sdk = Client(http);
        var empty = await sdk.Workflows.GetScheduledWorkflowsAsync("demo", "user-1");
        Require(empty.Body is { Count: 0 } && empty.HasBody, "An empty workflow array is a valid body");
        handler.Action = (_, _) => Task.FromResult(Json("[{\"id\":\"wf-1\",\"name\":\"first\",\"steps\":[]},{\"id\":\"wf-2\",\"name\":\"second\",\"steps\":[]}]"));
        var populated = await sdk.Workflows.GetScheduledWorkflowsAsync("demo", "user-1");
        Require(populated.Body is { Count: 2 } && populated.Body[0].Id == "wf-1" && populated.Body[1].Name == "second", "Workflow array element contracts");
    }

    public static Task PolicyQueriesAsync() => AuthorizationQueriesAsync(permissionPath: false);
    public static Task PermissionQueriesAsync() => AuthorizationQueriesAsync(permissionPath: true);

    private static async Task AuthorizationQueriesAsync(bool permissionPath)
    {
        string segment = permissionPath ? "permission" : "policy";
        using var handler = new WireHandler((r, _) =>
        {
            Require(r.Method == HttpMethod.Get && r.RequestUri!.AbsolutePath == $"/admin/realms/demo/clients/client-1/authz/resource-server/{segment}/user", "Authorization route");
            var query = Form(r.RequestUri!.Query.TrimStart('?'));
            var expected = new Dictionary<string, string>
            {
                ["fields"] = "*", ["policyId"] = "p-1", ["name"] = "名字 +&", ["type"] = "user", ["resourceType"] = "resource-type",
                ["resource"] = "r-1", ["scope"] = "s-1", ["permission"] = "false", ["owner"] = "u-1", ["first"] = "0", ["max"] = "1"
            };
            Require(query.Count == expected.Count && expected.All(p => query.GetValueOrDefault(p.Key) == p.Value), "All 11 independently specified query bindings, including false/0 and encoded Unicode");
            return Task.FromResult(Json("[]"));
        });
        using var http = new HttpClient(handler);
        var sdk = Client(http);
        var response = permissionPath
            ? await sdk.Policy.FindByIdAsync("demo", "client-1", "user", fields: "*", policyId: "p-1", name: "名字 +&", typeQuery: "user", resourceType: "resource-type", resource: "r-1", scope: "s-1", permission: false, owner: "u-1", first: 0, max: 1)
            : await sdk.Policy.FindByIdGETAdminRealmsRealmClientsClientUuidAuthzResourceServerPolicyTypeAsync("demo", "client-1", "user", fields: "*", policyId: "p-1", name: "名字 +&", typeQuery: "user", resourceType: "resource-type", resource: "r-1", scope: "s-1", permission: false, owner: "u-1", first: 0, max: 1);
        Require(response.Body.ValueKind == JsonValueKind.Array, "Provider-type branches return arrays");
        handler.Action = (r, _) =>
        {
            Require(r.RequestUri!.Query == "", "Absent optional filters are omitted");
            return Task.FromResult(Json("{\"id\":\"p-1\"}"));
        };
        var entity = permissionPath
            ? await sdk.Policy.FindByIdAsync("demo", "client-1", "p-1")
            : await sdk.Policy.FindByIdGETAdminRealmsRealmClientsClientUuidAuthzResourceServerPolicyTypeAsync("demo", "client-1", "p-1");
        Require(entity.Body.GetProperty("id").GetString() == "p-1", "ID branches still return objects");
    }

    public static async Task IdentityProviderMediaAsync()
    {
        using var handler = new WireHandler(async (r, ct) =>
        {
            Require(r.RequestUri!.AbsolutePath == "/admin/realms/demo/identity-provider/import-config", "IDP import path");
            await Multipart(r, ["providerId", "file", "fixture.xml", "metadata-中"], ct);
            return Json("{\"singleSignOnServiceUrl\":\"https://idp.invalid/sso\"}");
        });
        using var http = new HttpClient(handler);
        var sdk = Client(http);
        var multipart = new MultipartFormDataContent("independent-idp-boundary");
        multipart.Add(new StringContent("saml"), "providerId");
        multipart.Add(new StringContent("metadata-中", Encoding.UTF8, "application/xml"), "file", "fixture.xml");
        var imported = await sdk.IdentityProviders.ImportFromAsync("demo", multipart);
        Require(imported.Body!["singleSignOnServiceUrl"] == "https://idp.invalid/sso", "IDP dictionary response");
        handler.Action = async (r, ct) =>
        {
            Require(r.Content!.Headers.ContentType!.MediaType == "application/json", "IDP JSON content type");
            using var doc = JsonDocument.Parse(await r.Content.ReadAsStringAsync(ct));
            Require(doc.RootElement.GetProperty("fromUrl").GetString() == "https://metadata.invalid/", "IDP JSON payload is not re-quoted");
            return Json("{}");
        };
        await sdk.IdentityProviders.ImportFromAsync("demo", new StringContent("{\"providerId\":\"saml\",\"fromUrl\":\"https://metadata.invalid/\"}", Encoding.UTF8, "application/json"));
    }

    public static async Task LocalizationMediaAsync()
    {
        using var handler = new WireHandler(async (r, ct) =>
        {
            Require(r.RequestUri!.AbsolutePath == "/admin/realms/demo/localization/zh-CN", "Localization import path");
            await Multipart(r, ["file", "messages.json", "你好"], ct);
            return new(HttpStatusCode.NoContent);
        });
        using var http = new HttpClient(handler);
        var sdk = Client(http);
        var multipart = new MultipartFormDataContent("independent-localization-boundary");
        multipart.Add(new StringContent("{\"hello\":\"你好\"}", Encoding.UTF8, "application/json"), "file", "messages.json");
        await sdk.RealmLocalization.CreateOrUpdateRealmLocalizationTextsFromFileAsync("demo", "zh-CN", multipart);
        handler.Action = async (r, ct) =>
        {
            Require(r.Content!.Headers.ContentType!.MediaType == "application/json", "Localization JSON content type");
            using var doc = JsonDocument.Parse(await r.Content.ReadAsStringAsync(ct));
            Require(doc.RootElement.GetProperty("hello").GetString() == "你好", "Localization JSON payload");
            return new(HttpStatusCode.NoContent);
        };
        await sdk.RealmLocalization.CreateOrUpdateRealmLocalizationTextsFromFileAsync("demo", "zh-CN", new StringContent("{\"hello\":\"你好\"}", Encoding.UTF8, "application/json"));
    }

    public static async Task SmtpMediaAsync()
    {
        using var handler = new WireHandler(async (r, ct) =>
        {
            Require(r.RequestUri!.AbsolutePath == "/admin/realms/demo/testSMTPConnection", "SMTP test path");
            Require(r.Content!.Headers.ContentType!.MediaType == "application/x-www-form-urlencoded", "SMTP form content type");
            var form = Form(await r.Content.ReadAsStringAsync(ct));
            using var config = JsonDocument.Parse(form["config"]);
            Require(config.RootElement.GetProperty("host").GetString() == "smtp +&.invalid", "SMTP config is form-encoded exactly once");
            return new(HttpStatusCode.NoContent);
        });
        using var http = new HttpClient(handler);
        var sdk = Client(http);
        await sdk.RealmAdmin.TestSMTPConnectionAsync("demo", new FormUrlEncodedContent(new Dictionary<string, string> { ["config"] = "{\"host\":\"smtp +&.invalid\"}" }));
        handler.Action = async (r, ct) =>
        {
            Require(r.Content!.Headers.ContentType!.MediaType == "application/json", "SMTP JSON content type");
            using var config = JsonDocument.Parse(await r.Content.ReadAsStringAsync(ct));
            Require(config.RootElement.GetProperty("host").GetString() == "smtp.invalid", "SMTP JSON payload");
            return new(HttpStatusCode.NoContent);
        };
        await sdk.RealmAdmin.TestSMTPConnectionAsync("demo", new StringContent("{\"host\":\"smtp.invalid\"}", Encoding.UTF8, "application/json"));
    }

    public static async Task RunAsync()
    {
        await SamlExampleStringAsync();
        await CertificateUploadHasBodyAsync();
        await WorkflowArraysAsync(); await PolicyQueriesAsync(); await PermissionQueriesAsync();
        await IdentityProviderMediaAsync(); await LocalizationMediaAsync(); await SmtpMediaAsync();
        Console.WriteLine("PASS: six independent source-based contract cases (arrays, branch queries, multipart, JSON and form).");
    }

    private static KeycloakAdminClient Client(HttpClient http) => new(http, new Uri("https://keycloak.invalid/"));
    private static HttpResponseMessage Json(string body) => new(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
    private static void Require(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
    private static Dictionary<string, string> Form(string encoded) => encoded.Split('&', StringSplitOptions.RemoveEmptyEntries)
        .Select(pair => pair.Split('=', 2)).ToDictionary(p => Uri.UnescapeDataString(p[0].Replace('+', ' ')), p => Uri.UnescapeDataString(p[1].Replace('+', ' ')), StringComparer.Ordinal);
    private static async Task Multipart(HttpRequestMessage request, string[] parts, CancellationToken ct)
    {
        Require(request.Method == HttpMethod.Post && request.Content is not null, "Multipart POST body");
        Require(request.Content!.Headers.ContentType!.MediaType == "multipart/form-data", "Preserve multipart media type");
        Require(request.Content.Headers.ContentType.Parameters.Any(p => p.Name == "boundary"), "Preserve multipart boundary");
        string payload = await request.Content.ReadAsStringAsync(ct);
        Require(parts.All(part => payload.Contains(part, StringComparison.Ordinal)), "Preserve multipart fields, file name and UTF-8 payload");
    }
    private sealed class WireHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> action) : HttpMessageHandler
    {
        public Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> Action { get; set; } = action;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => Action(request, cancellationToken);
    }
}
