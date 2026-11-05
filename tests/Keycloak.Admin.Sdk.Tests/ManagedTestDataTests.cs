using System.Net;
using System.Text.Json;
using AutoFixture;
using Bogus;
using Keycloak.Admin.Sdk;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using PasswordGenerator;

// Managed-only: do not link this file into AotSmoke or its shared contract suite.
[TestClass]
public sealed class ManagedTestDataTests
{
    private static readonly Uri Server = new("https://keycloak.invalid/auth/");

    [TestMethod]
    public async Task AutoFixtureUserPreservesExplicitFalseAndOmittedFields()
    {
        var fixture = new Fixture();
        var user = fixture.Build<UserRepresentation>().OmitAutoProperties()
            .With(u => u.Username, fixture.Create<string>())
            .With(u => u.FirstName, fixture.Create<string>())
            .With(u => u.Enabled, false)
            .Create();
        using var http = new HttpClient(new Handler(async (request, ct) =>
        {
            Assert.AreEqual(HttpMethod.Post, request.Method);
            Assert.AreEqual("/auth/admin/realms/demo/users", request.RequestUri!.AbsolutePath);
            using var json = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(ct));
            Assert.AreEqual(user.Username, json.RootElement.GetProperty("username").GetString());
            Assert.AreEqual(user.FirstName, json.RootElement.GetProperty("firstName").GetString());
            Assert.IsFalse(json.RootElement.GetProperty("enabled").GetBoolean());
            Assert.IsFalse(json.RootElement.TryGetProperty("email", out _));
            return new(HttpStatusCode.Created);
        }));
        var result = await new KeycloakAdminClient(http, Server).Users.CreateUserAsync("demo", user);
        Assert.AreEqual(HttpStatusCode.Created, result.StatusCode);
    }

    [TestMethod]
    public async Task BogusSeededUsersPreserveIdentityAcrossJsonResponse()
    {
        // Local seed and explicit IDs avoid parallel global random state and uniqueness assumptions.
        var faker = new Faker<UserRepresentation>("en").UseSeed(1729)
            .RuleFor(u => u.Id, f => "user-" + f.IndexFaker)
            .RuleFor(u => u.Username, f => f.Internet.UserName())
            .RuleFor(u => u.Email, f => f.Internet.Email())
            .RuleFor(u => u.FirstName, f => f.Name.FirstName())
            .RuleFor(u => u.Enabled, f => f.Random.Bool());
        var users = faker.Generate(12);
        var payload = JsonSerializer.Serialize(users, KeycloakJsonContext.Default.ListUserRepresentation);
        using var http = new HttpClient(new Handler((request, _) =>
        {
            Assert.AreEqual("?first=0&max=12", request.RequestUri!.Query);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(payload) });
        }));
        var result = await new KeycloakAdminClient(http, Server).Users.GetUsersAsync("demo", first: 0, max: 12);
        Assert.IsNotNull(result.Body);
        Assert.HasCount(users.Count, result.Body);
        for (int i = 0; i < users.Count; i++)
        {
            Assert.AreEqual(users[i].Id, result.Body[i].Id);
            Assert.AreEqual(users[i].Username, result.Body[i].Username);
            Assert.AreEqual(users[i].Email, result.Body[i].Email);
            Assert.AreEqual(users[i].FirstName, result.Body[i].FirstName);
            Assert.AreEqual(users[i].Enabled, result.Body[i].Enabled);
        }
    }

    [TestMethod]
    public async Task MoqVerifies401InvalidationAndSinglePolicyEvaluation()
    {
        using var cancellation = new CancellationTokenSource();
        var ct = cancellation.Token;
        var tokens = new Mock<IRefreshableAccessTokenProvider>(MockBehavior.Strict);
        tokens.SetupSequence(p => p.GetAccessTokenAsync(ct))
            .Returns(ValueTask.FromResult("old-token")).Returns(ValueTask.FromResult("new-token"));
        tokens.Setup(p => p.InvalidateAsync("old-token", ct)).Returns(ValueTask.CompletedTask);
        var policy = new Mock<IKeycloakAdminRequestPolicy>(MockBehavior.Strict);
        policy.Setup(p => p.EnsureAllowedAsync(HttpMethod.Get,
            new Uri(Server, "admin/realms/demo/users"), "Users.GetUsersAsync", ct)).Returns(ValueTask.CompletedTask);
        int calls = 0;
        using var http = new HttpClient(new Handler((request, _) =>
        {
            calls++;
            Assert.AreEqual(calls == 1 ? "old-token" : "new-token", request.Headers.Authorization!.Parameter);
            return Task.FromResult(calls == 1 ? new HttpResponseMessage(HttpStatusCode.Unauthorized)
                : new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("[]") });
        }));
        var sdk = new KeycloakAdminClient(http, Server, tokens.Object,
            new() { EnableUnauthorizedRecovery = true, RequestPolicy = policy.Object });
        await sdk.Users.GetUsersAsync("demo", cancellationToken: ct);
        Assert.AreEqual(2, calls);
        tokens.Verify(p => p.GetAccessTokenAsync(ct), Times.Exactly(2));
        tokens.Verify(p => p.InvalidateAsync("old-token", ct), Times.Once);
        tokens.VerifyNoOtherCalls();
        policy.Verify(p => p.EnsureAllowedAsync(HttpMethod.Get,
            new Uri(Server, "admin/realms/demo/users"), "Users.GetUsersAsync", ct), Times.Once);
        policy.VerifyNoOtherCalls();
    }

    [TestMethod]
    public async Task GeneratedPasswordSurvivesRequestAndIsExcludedFromHttpError()
    {
        string password = new Password(32).Next();
        Assert.AreEqual(32, password.Length);
        using var http = new HttpClient(new Handler(async (request, ct) =>
        {
            Assert.AreEqual(HttpMethod.Put, request.Method);
            Assert.AreEqual("/auth/admin/realms/demo/users/user-id/reset-password", request.RequestUri!.AbsolutePath);
            using var json = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(ct));
            Assert.AreEqual("password", json.RootElement.GetProperty("type").GetString());
            Assert.AreEqual(password, json.RootElement.GetProperty("value").GetString());
            Assert.IsFalse(json.RootElement.GetProperty("temporary").GetBoolean());
            return new(HttpStatusCode.BadRequest) { Content = new StringContent(password) };
        }));
        var sdk = new KeycloakAdminClient(http, Server);
        var error = await Assert.ThrowsAsync<KeycloakAdminException>(() => sdk.User.ResetPasswordAsync(
            "demo", "user-id", new() { Type = "password", Value = password, Temporary = false }));
        Assert.AreEqual(KeycloakErrorKind.BadRequest, error.ErrorKind);
        Assert.AreEqual("User.ResetPasswordAsync", error.Operation);
        Assert.IsFalse(error.ToString().Contains(password, StringComparison.Ordinal));
    }

    private sealed class Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => send(request, cancellationToken);
    }
}
