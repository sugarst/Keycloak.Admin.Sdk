using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Keycloak.Admin.Sdk.Protocols;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualStudio.TestTools.UnitTesting;

[TestClass]
public sealed class OidcRefreshTests
{
    [TestMethod]
    public async Task RefreshIdentityCannotSubstituteTheOriginalClientSubjectOrAuthenticationContext()
    {
        using var rsa = RSA.Create(2048); var parameters = rsa.ExportParameters(false);
        var keys = new JsonObject { ["keys"] = new JsonArray(new JsonObject { ["kty"] = "RSA", ["n"] = Base64UrlEncoder.Encode(parameters.Modulus), ["e"] = Base64UrlEncoder.Encode(parameters.Exponent) }) };
        using var handler = new Handler(keys.ToJsonString()); using var http = new HttpClient(handler);
        var oidc = new OidcClient(new(http, new("https://issuer.invalid"), "r")); var validator = new OidcTokenValidator(oidc, "app");
        var claims = new JsonObject { ["iss"] = oidc.Issuer.AbsoluteUri, ["sub"] = "user", ["aud"] = "app", ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            ["exp"] = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds(), ["nonce"] = "nonce", ["auth_time"] = DateTimeOffset.UtcNow.AddMinutes(-1).ToUnixTimeSeconds() };
        string Sign(JsonObject payload) => new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(payload.ToJsonString(), new SigningCredentials(new RsaSecurityKey(rsa), "RS256"));
        var original = await validator.ValidateIdTokenAsync(Sign(claims), "nonce", "access");
        var refreshed = (JsonObject)claims.DeepClone(); refreshed.Remove("nonce");
        Assert.AreEqual("user", (await validator.ValidateRefreshedIdTokenAsync(Sign(refreshed), original, "access")).Subject);
        Assert.AreEqual("user", (await validator.ValidateRefreshedIdTokenAsync(Sign(claims), original, "access")).Subject);
        foreach (var (name, replacement) in new[] { ("sub", "other"), ("nonce", "other") })
        { var changed = (JsonObject)claims.DeepClone(); changed[name] = replacement; await Assert.ThrowsAsync<InvalidDataException>(() => validator.ValidateRefreshedIdTokenAsync(Sign(changed), original, "access")); }
        var otherTime = (JsonObject)claims.DeepClone(); otherTime["auth_time"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        await Assert.ThrowsAsync<InvalidDataException>(() => validator.ValidateRefreshedIdTokenAsync(Sign(otherTime), original, "access"));
        var noContext = (JsonObject)refreshed.DeepClone(); noContext.Remove("auth_time");
        var withoutContext = await validator.ValidateExchangedIdTokenAsync(Sign(noContext));
        await Assert.ThrowsAsync<InvalidDataException>(() => validator.ValidateRefreshedIdTokenAsync(Sign(claims), withoutContext, "access"));
        await Assert.ThrowsAsync<InvalidDataException>(() => validator.ValidateRefreshedIdTokenAsync(Sign(refreshed), withoutContext, "access"));
        Assert.AreEqual("user", (await validator.ValidateRefreshedIdTokenAsync(Sign(noContext), withoutContext, "access")).Subject);
        foreach (JsonNode? audience in new JsonNode?[] { JsonValue.Create("foreign"), JsonValue.Create(1), new JsonArray("foreign"), new JsonArray(1, "foreign") })
        {
            var wrong = (JsonObject)claims.DeepClone(); wrong["aud"] = audience;
            await Assert.ThrowsAsync<ArgumentException>(() => validator.ValidateRefreshedIdTokenAsync(Sign(refreshed), Original(wrong), "access"));
        }
        var multi = (JsonObject)claims.DeepClone(); multi["aud"] = new JsonArray(1, "foreign", "app"); multi["azp"] = "app";
        Assert.AreEqual("user", (await validator.ValidateRefreshedIdTokenAsync(Sign(refreshed), Original(multi), "access")).Subject);
        foreach (JsonNode? party in new JsonNode?[] { JsonValue.Create("foreign"), JsonValue.Create(1) })
        { var wrong = (JsonObject)multi.DeepClone(); wrong["azp"] = party; await Assert.ThrowsAsync<ArgumentException>(() => validator.ValidateRefreshedIdTokenAsync(Sign(refreshed), Original(wrong), "access")); }
        multi["iss"] = "https://foreign.invalid/realms/r";
        await Assert.ThrowsAsync<ArgumentException>(() => validator.ValidateRefreshedIdTokenAsync(Sign(refreshed), Original(multi), "access"));
        await Assert.ThrowsAsync<ArgumentNullException>(() => validator.ValidateRefreshedIdTokenAsync(Sign(refreshed), null!, "access"));
        await Assert.ThrowsAsync<ArgumentException>(() => validator.ValidateRefreshedIdTokenAsync(Sign(refreshed), original, ""));
        using var canceled = new CancellationTokenSource(); canceled.Cancel();
        await Assert.ThrowsAsync<OperationCanceledException>(() => validator.ValidateRefreshedIdTokenAsync(Sign(refreshed), original, "access", canceled.Token));
    }
    private static OidcIdentity Original(JsonObject claims)
    { using var json = JsonDocument.Parse(claims.ToJsonString()); return new("user", claims["iss"]!.GetValue<string>(), new Dictionary<string, object>(), json.RootElement); }
    private sealed class Handler(string keys) : HttpMessageHandler
    { protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) { ct.ThrowIfCancellationRequested(); return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(keys, Encoding.UTF8, "application/json") }); } }
}
