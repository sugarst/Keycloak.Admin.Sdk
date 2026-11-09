using System.Net;
using System.Text.Json;
using Keycloak.Admin.Sdk.Protocols;
using Microsoft.VisualStudio.TestTools.UnitTesting;

[TestClass]
public sealed class OidcOptionsTests
{
    [TestMethod]
    public async Task AuthorizationActionsAssuranceClaimsAndTheSingleSupportedResourceSurviveParAndTokenRequests()
    {
        using var handler = new Handler(); using var http = new HttpClient(handler); var client = new OidcClient(new(http, new("https://identity.invalid/"), "r"));
        var options = new OidcAuthorizationOptions { LoginHint = "user+", IdentityProvider = "provider", Action = "idp_link:provider", Prompt = "login", AcrValues = "gold silver",
            Locale = "zh-CN", MaximumAuthenticationAgeSeconds = 0, Claims = JsonDocument.Parse("""{"id_token":{"acr":{"essential":true,"values":["gold"]}}}""").RootElement,
            Resources = [new("https://api.invalid/one")] };
        var transaction = new OidcLoginTransaction(client, "c", new("https://app.invalid/callback"), options: options);
        string query = transaction.AuthorizationUri.Query;
        foreach (string expected in new[] { "kc_idp_hint=provider", "kc_action=idp_link%3Aprovider", "login_hint=user%2B", "prompt=login", "acr_values=gold%20silver", "max_age=0", "claims=", "ui_locales=zh-CN",
            "resource=https%3A%2F%2Fapi.invalid%2Fone" }) StringAssert.Contains(query, expected);
        var auth = OAuthClientAuthentication.Public("c");
        await client.PushAuthorizationAsync(auth, transaction.AuthorizationUri);
        StringAssert.Contains(handler.Body, "resource=https%3A%2F%2Fapi.invalid%2Fone");
        await client.ClientCredentialsAsync(auth, resources: options.Resources);
        StringAssert.Contains(handler.Body, "resource=https%3A%2F%2Fapi.invalid%2Fone");
        await client.RefreshAsync(auth, "refresh", resources: [new("urn:resource:two")]); StringAssert.Contains(handler.Body, "resource=urn%3Aresource%3Atwo");
        await client.RedeemCodeAsync(auth, "code", new("https://app.invalid/callback"), new string('v', 43), resources: options.Resources); StringAssert.Contains(handler.Body, "resource=https%3A%2F%2Fapi.invalid%2Fone");
        Uri Create(OidcAuthorizationOptions value) => client.CreateAuthorizationUri("c", new("https://app.invalid/cb"), "state", "nonce", new string('v', 43), options: value);
        foreach (var invalid in new OidcAuthorizationOptions[] { new() { LoginHint = "" }, new() { IdentityProvider = "" }, new() { Action = " " }, new() { Prompt = " " }, new() { AcrValues = "" },
            new() { Locale = " " }, new() { MaximumAuthenticationAgeSeconds = -1 }, new() { Claims = JsonDocument.Parse("[]").RootElement }, new() { Resources = [new("relative", UriKind.Relative)] },
            new() { Resources = [new("https://user:password@api.invalid")] }, new() { Resources = [new("https://api.invalid/#fragment")] }, new() { Resources = [new("https://api.invalid/?query")] }, new() { Resources = [new("urn:r:one"), new("urn:r:two")] } })
            Assert.Throws<ArgumentException>(() => Create(invalid));
        Assert.Throws<ArgumentNullException>(() => Create(new() { Resources = null! }));
        Assert.Throws<ArgumentNullException>(() => Create(new() { Resources = [null!] }));
        Assert.Throws<ArgumentException>(() => client.ClientCredentialsAsync(auth, resources: [new("relative", UriKind.Relative)]));
        Assert.Throws<ArgumentException>(() => client.PushAuthorizationAsync(auth, new(transaction.AuthorizationUri.AbsoluteUri + "&resource=urn%3Ar%3Atwo")));
    }
    private sealed class Handler : HttpMessageHandler
    {
        internal string Body = "";
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        { Body = await request.Content!.ReadAsStringAsync(cancellationToken); return new(HttpStatusCode.OK) { Content = new StringContent("{}") }; }
    }
}
