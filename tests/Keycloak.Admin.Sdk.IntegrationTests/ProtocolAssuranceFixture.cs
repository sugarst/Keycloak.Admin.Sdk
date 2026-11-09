using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Keycloak.Admin.Sdk;

internal sealed class ProtocolAssuranceFixture : IAsyncDisposable
{
    internal string Realm { get; }
    internal string UserId { get; private set; } = "";
    internal const string Username = "assurance-user";
    private readonly string otpSecret = Convert.ToHexString(RandomNumberGenerator.GetBytes(20));
    private readonly KeycloakAdminClient admin;
    private ProtocolAssuranceFixture(KeycloakAdminClient admin, string realm) { this.admin = admin; Realm = realm; }
    internal static async Task<ProtocolAssuranceFixture> CreateAsync(KeycloakAdminClient admin, string parentRealm, string password, CancellationToken ct)
    {
        var fixture = new ProtocolAssuranceFixture(admin, parentRealm + "-assurance");
        AuthenticationExecutionExportRepresentation Flow(string alias, string requirement, int priority) => new() { FlowAlias = alias, AuthenticatorFlow = true, Requirement = requirement, Priority = priority };
        AuthenticationExecutionExportRepresentation Auth(string name, string requirement, int priority, string? config = null) => new() { Authenticator = name, AuthenticatorFlow = false, Requirement = requirement, Priority = priority, AuthenticatorConfig = config };
        AuthenticationFlowRepresentation Subflow(string alias, List<AuthenticationExecutionExportRepresentation> executions, bool topLevel = false) => new() { Alias = alias, TopLevel = topLevel, BuiltIn = false, ProviderId = "basic-flow", AuthenticationExecutions = executions };
        var realm = new RealmRepresentation { Realm = fixture.Realm, Enabled = true, BrowserFlow = "sdk-assurance-browser", AuthenticationFlows = [
            Subflow("sdk-assurance-browser", [Auth("auth-cookie", "ALTERNATIVE", 0), Flow("sdk-assurance-forms", "ALTERNATIVE", 10)], true),
            Subflow("sdk-assurance-forms", [Flow("sdk-level-1", "CONDITIONAL", 0), Flow("sdk-level-2", "CONDITIONAL", 10)]),
            Subflow("sdk-level-1", [Auth("conditional-level-of-authentication", "REQUIRED", 0, "sdk-loa-1"), Auth("auth-username-password-form", "REQUIRED", 10, "sdk-pwd")]),
            Subflow("sdk-level-2", [Auth("conditional-level-of-authentication", "REQUIRED", 0, "sdk-loa-2"), Auth("auth-otp-form", "REQUIRED", 10, "sdk-otp")]) ],
            AuthenticatorConfig = [new() { Alias = "sdk-loa-1", Config = new() { ["loa-condition-level"] = "1", ["loa-max-age"] = "3600" } }, new() { Alias = "sdk-loa-2", Config = new() { ["loa-condition-level"] = "2", ["loa-max-age"] = "3600" } },
                new() { Alias = "sdk-pwd", Config = new() { ["default.reference.value"] = "pwd", ["default.reference.maxAge"] = "3600" } },
                new() { Alias = "sdk-otp", Config = new() { ["default.reference.value"] = "otp", ["default.reference.maxAge"] = "3600" } }] };
        await admin.RealmsAdmin.ImportRealmAsync(new StringContent(JsonSerializer.Serialize(realm, KeycloakJsonContext.Default.RealmRepresentation), Encoding.UTF8, "application/json"), ct);
        try
        {
            await admin.Users.CreateUserAsync(fixture.Realm, new() { Username = Username, Enabled = true, FirstName = "Assurance", LastName = "User", Email = "assurance@example.invalid", EmailVerified = true,
                Credentials = [new() { Type = "password", Value = password, Temporary = false }, new() { Type = "otp", UserLabel = "Test second factor",
                    SecretData = new JsonObject { ["value"] = fixture.otpSecret }.ToJsonString(), CredentialData = new JsonObject { ["subType"] = "totp", ["digits"] = 6, ["period"] = 30, ["algorithm"] = "HmacSHA1", ["counter"] = 0 }.ToJsonString() }] }, cancellationToken: ct);
            fixture.UserId = (await admin.Users.GetUsersAsync(fixture.Realm, username: Username, exact: true, cancellationToken: ct)).Body!.Single().Id!;
            return fixture;
        }
        catch { await fixture.DisposeAsync(); throw; }
    }
    internal Task CreateOidcClientAsync(string clientId, Uri callback, string? secret, CancellationToken ct)
        => CreateOidcClientCoreAsync(clientId, callback, secret, ct);
    private async Task CreateOidcClientCoreAsync(string clientId, Uri callback, string? secret, CancellationToken ct)
    {
        await admin.Clients.CreateClientAsync(Realm, new() { ClientId = clientId, Protocol = "openid-connect", Enabled = true, PublicClient = secret is null, Secret = secret,
            StandardFlowEnabled = true, RedirectUris = [callback.AbsoluteUri], Attributes = new() { ["pkce.code.challenge.method"] = "S256", ["acr.loa.map"] = "{\"urn:sdk:loa:1\":1,\"urn:sdk:loa:2\":2}" },
            ProtocolMappers = [new() { Name = "actual-authentication-methods", Protocol = "openid-connect", ProtocolMapper = "oidc-amr-mapper", Config = new() { ["id.token.claim"] = "true", ["access.token.claim"] = "true" } }] }, cancellationToken: ct);
    }
    internal ValueTask<string> CurrentOtpAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested(); Span<byte> counter = stackalloc byte[8]; BinaryPrimitives.WriteInt64BigEndian(counter, DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30);
        byte[] digest = HMACSHA1.HashData(Encoding.UTF8.GetBytes(otpSecret), counter); int offset = digest[^1] & 15;
        int number = BinaryPrimitives.ReadInt32BigEndian(digest.AsSpan(offset, 4)) & int.MaxValue;
        return ValueTask.FromResult((number % 1000000).ToString("D6", System.Globalization.CultureInfo.InvariantCulture));
    }
    public async ValueTask DisposeAsync()
    { using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(30)); await admin.RealmAdmin.DeleteRealmAsync(Realm, cleanup.Token); }
}
