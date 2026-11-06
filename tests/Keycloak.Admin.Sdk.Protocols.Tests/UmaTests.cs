using System.Net;
using System.Text.Json;
using Keycloak.Admin.Sdk.Protocols;
using Microsoft.VisualStudio.TestTools.UnitTesting;

[TestClass]
public sealed class UmaTests
{
    [TestMethod]
    public async Task ProtectionAndRuntimeAuthorizationKeepPatAndUserCredentialsExplicit()
    {
        using var handler = new Handler(); using var http = new HttpClient(handler);
        var transport = new ProtocolTransport(http, new("https://identity.invalid"), "r"); var client = new UmaClient(transport);
        var body = JsonDocument.Parse("{}").RootElement;
        await client.DiscoverAsync(); Assert.AreEqual("/realms/r/.well-known/uma2-configuration", handler.Path);
        await client.CreatePermissionAsync(JsonDocument.Parse("[]").RootElement, "pat"); Assert.AreEqual("/realms/r/authz/protection/permission", handler.Path);
        await client.CreateTicketAsync(body, "pat"); Assert.AreEqual("/realms/r/authz/protection/permission/ticket", handler.Path);
        await client.UpdateTicketAsync(body, "pat"); Assert.AreEqual("PUT", handler.Method);
        await client.GetTicketsAsync("pat", [new("granted", "false")]); Assert.AreEqual("?granted=false", handler.Query);
        await client.CountTicketsAsync("pat"); Assert.AreEqual("/realms/r/authz/protection/permission/ticket/count", handler.Path);
        await client.DeleteTicketAsync("ticket/id", "pat"); Assert.AreEqual("/realms/r/authz/protection/permission/ticket/ticket%2Fid", handler.Path);
        await client.CreatePolicyAsync("resource", body, "owner"); Assert.AreEqual("/realms/r/authz/protection/uma-policy/resource", handler.Path); Assert.AreEqual("POST", handler.Method);
        await client.GetPolicyAsync("policy", "owner"); Assert.AreEqual("/realms/r/authz/protection/uma-policy/policy", handler.Path);
        await client.UpdatePolicyAsync("policy", body, "owner"); Assert.AreEqual("PUT", handler.Method);
        await client.GetPoliciesAsync("owner"); Assert.AreEqual("/realms/r/authz/protection/uma-policy", handler.Path);
        await client.DeletePolicyAsync("policy", "owner"); Assert.AreEqual("DELETE", handler.Method);
        await client.AuthorizeAsync("user", "api", ["one#read", "two#write"], "signed-ticket", UmaResponseMode.Token, "existing-rpt", true);
        StringAssert.Contains(handler.Body, "permission=one%23read&permission=two%23write");
        StringAssert.Contains(handler.Body, "ticket=signed-ticket"); StringAssert.Contains(handler.Body, "rpt=existing-rpt"); StringAssert.Contains(handler.Body, "submit_request=true");
        Assert.AreEqual("Bearer user", handler.Authorization); Assert.IsFalse(handler.Body.Contains("response_mode", StringComparison.Ordinal));
        await client.AuthorizeAsync("user", "api", responseMode: UmaResponseMode.Permissions); StringAssert.Contains(handler.Body, "response_mode=permissions");
        handler.Response = """{"result":true}"""; Assert.IsTrue(await client.EvaluateAsync("user", "api", ["r#s"]));
        StringAssert.Contains(handler.Body, "response_mode=decision");
        handler.Response = """{"result":false}"""; Assert.IsFalse(await client.EvaluateAsync("user", "api", []));
        handler.Response = ""; await Assert.ThrowsAsync<InvalidDataException>(() => client.EvaluateAsync("user", "api", []));
        handler.Status = HttpStatusCode.Forbidden; handler.Response = """{"error":"access_denied"}""";
        Assert.IsFalse(await client.EvaluateAsync("user", "api", []));
        handler.Status = HttpStatusCode.Unauthorized;
        await Assert.ThrowsAsync<KeycloakProtocolException>(() => client.EvaluateAsync("user", "api", []));
        handler.Status = HttpStatusCode.Forbidden; handler.Response = "{}";
        await Assert.ThrowsAsync<KeycloakProtocolException>(() => client.EvaluateAsync("user", "api", []));
        Assert.Throws<ArgumentException>(() => client.AuthorizeAsync("", "api")); Assert.Throws<ArgumentException>(() => client.AuthorizeAsync("user", ""));
        Assert.Throws<ArgumentException>(() => client.AuthorizeAsync("user", "api", [""])); Assert.Throws<ArgumentException>(() => client.AuthorizeAsync("user", "api", ticket: ""));
        Assert.Throws<ArgumentException>(() => client.AuthorizeAsync("user", "api", existingRpt: ""));
        Assert.Throws<ArgumentOutOfRangeException>(() => client.AuthorizeAsync("user", "api", responseMode: (UmaResponseMode)123));
        Assert.Throws<ArgumentException>(() => client.CreateTicketAsync(body, "")); Assert.Throws<ArgumentException>(() => client.GetTicketsAsync(""));
        Assert.Throws<ArgumentNullException>(() => new UmaClient(null!));
    }

    [TestMethod]
    public async Task ProviderSpecificCompatibilityRequestsUseTheirDeclaredMediaTypes()
    {
        using var handler = new Handler(); using var http = new HttpClient(handler);
        var transport = new ProtocolTransport(http, new("https://identity.invalid"), "r"); var body = JsonDocument.Parse("{}").RootElement;
        await RealmResourceClient.DefaultClientRegistration(transport).CreateAsync(body, "initial");
        Assert.AreEqual("/realms/r/clients-registrations/default", handler.Path);
        var registration = new ClientRegistrationClient(transport);
        await registration.GetInstallationAsync("app", "rat"); Assert.AreEqual("/realms/r/clients-registrations/install/app", handler.Path);
        Assert.Throws<ArgumentException>(() => registration.GetInstallationAsync("app", ""));
        await registration.RegisterSamlDescriptorAsync("<EntityDescriptor/>", "initial");
        Assert.AreEqual("/realms/r/clients-registrations/saml2-entity-descriptor", handler.Path); Assert.AreEqual("application/xml", handler.ContentType);
        Assert.AreEqual("<EntityDescriptor/>", handler.Body);
        Assert.Throws<ArgumentException>(() => registration.RegisterSamlDescriptorAsync("", "initial")); Assert.Throws<ArgumentException>(() => registration.RegisterSamlDescriptorAsync("xml", ""));
        Assert.Throws<ArgumentNullException>(() => new ClientRegistrationClient(null!));
    }

    [TestMethod]
    public async Task AccountResourceSharingUsesUserScopedRoutesAndPermissionArrays()
    {
        using var handler = new Handler(); using var http = new HttpClient(handler);
        var client = new AccountResourcesClient(new(http, new("https://identity.invalid"), "r"));
        await client.GetOwnedAsync("user", [new("first", "0"), new("max", "10")]); Assert.AreEqual("/realms/r/account/resources", handler.Path);
        await client.GetSharedWithMeAsync("user"); Assert.AreEqual("/realms/r/account/resources/shared-with-me", handler.Path);
        await client.GetSharedWithOthersAsync("user"); Assert.AreEqual("/realms/r/account/resources/shared-with-others", handler.Path);
        await client.GetPendingAsync("user"); Assert.AreEqual("/realms/r/account/resources/pending-requests", handler.Path);
        await client.GetAsync("resource/id", "user"); Assert.AreEqual("/realms/r/account/resources/resource%2Fid", handler.Path);
        await client.GetPermissionsAsync("resource", "user"); Assert.AreEqual("/realms/r/account/resources/resource/permissions", handler.Path);
        await client.GetPermissionRequestsAsync("resource", "user"); Assert.AreEqual("/realms/r/account/resources/resource/permissions/requests", handler.Path);
        await client.FindPermissionUserAsync("resource", "username", "user"); Assert.AreEqual("?value=username", handler.Query);
        await client.UpdatePermissionsAsync("resource", JsonDocument.Parse("[]").RootElement, "user"); Assert.AreEqual("PUT", handler.Method); Assert.AreEqual("[]", handler.Body);
        Assert.Throws<ArgumentException>(() => client.FindPermissionUserAsync("resource", "", "user"));
        Assert.Throws<ArgumentException>(() => client.GetOwnedAsync("")); Assert.Throws<ArgumentException>(() => client.UpdatePermissionsAsync("r", default, ""));
        Assert.Throws<ArgumentNullException>(() => new AccountResourcesClient(null!));
    }

    private sealed class Handler : HttpMessageHandler
    {
        internal string Path = "", Query = "", Method = "", Body = "", Authorization = "", ContentType = "", Response = "{}";
        internal HttpStatusCode Status = HttpStatusCode.OK;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Path = request.RequestUri!.AbsolutePath; Query = request.RequestUri.Query; Method = request.Method.Method;
            Authorization = request.Headers.Authorization?.ToString() ?? ""; ContentType = request.Content?.Headers.ContentType?.MediaType ?? "";
            Body = request.Content is null ? "" : await request.Content.ReadAsStringAsync(cancellationToken);
            return new(Status) { Content = new StringContent(Response) };
        }
    }
}
