using System.Net;
using System.Text.Json;
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Protocols;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

internal static class ProtocolDockerWorkflows
{
    internal static async Task RunAsync(KeycloakAdminClient admin, ProtocolTransport transport, string realm, string secret, Action<bool, string> check, CancellationToken ct)
    {
        await admin.Clients.CreateClientAsync(realm, new ClientRepresentation { ClientId = "docker-registry", Protocol = "docker-v2", Enabled = true,
            ProtocolMappers = [new ProtocolMapperRepresentation { Name = "test-registry-allow-requested-scopes", Protocol = "docker-v2", ProtocolMapper = "docker-v2-allow-all-mapper" }] }, cancellationToken: ct);
        var registry = new DockerRegistryClient(transport);
        string challenge = "Bearer realm=\"" + transport.Issuer.AbsoluteUri + "/protocol/docker-v2/auth\",service=\"docker-registry\",scope=\"repository:sdk/document:pull\"";
        var response = await registry.AuthenticateChallengeAsync(challenge, _ => ValueTask.FromResult(new NetworkCredential("account-user", secret)), ct);
        string compact = response.Json!.Value.GetProperty("token").GetString()!;
        var keys = (await new OidcClient(transport).GetSigningKeysAsync(ct)).Json!.Value;
        var parameters = new TokenValidationParameters { ValidIssuer = transport.Issuer.AbsoluteUri, ValidAudience = "docker-registry", ValidateIssuer = true, ValidateAudience = true,
            ValidateLifetime = true, RequireSignedTokens = true, ValidateIssuerSigningKey = true, IssuerSigningKeys = new JsonWebKeySet(keys.GetRawText()).GetSigningKeys(),
            ValidAlgorithms = ["RS256"], IncludeTokenOnFailedValidation = false, LogTokenId = false, LogValidationExceptions = false, ClockSkew = TimeSpan.FromSeconds(30) };
        var handler = new JsonWebTokenHandler { MapInboundClaims = false };
        var validated = await handler.ValidateTokenAsync(compact, parameters); ct.ThrowIfCancellationRequested();
        check(validated.IsValid, "Docker registry challenge returns a token with a valid pinned-realm signature issuer audience and lifetime");
        // Decode only after signature/issuer/audience/lifetime validation succeeds.
        using var payload = JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(compact.Split('.')[1]));
        var access = payload.RootElement.GetProperty("access")[0];
        check(payload.RootElement.GetProperty("sub").GetString() == "account-user" && access.GetProperty("type").GetString() == "repository"
            && access.GetProperty("name").GetString() == "sdk/document" && access.GetProperty("actions").EnumerateArray().Select(a => a.GetString()).SequenceEqual(["pull"]),
            "Docker registry token preserves the authenticated username and requested repository pull scope");
        bool badPassword = false, malformedScope = false;
        try { await registry.RequestTokenAsync("docker-registry", ["repository:sdk/document:pull"], _ => ValueTask.FromResult(new NetworkCredential("account-user", "wrong-password")), ct); }
        catch (KeycloakProtocolException e) when (e.StatusCode == HttpStatusCode.Unauthorized) { badPassword = true; }
        try { await registry.RequestTokenAsync("docker-registry", ["malformed-scope"], _ => ValueTask.FromResult(new NetworkCredential("account-user", secret)), ct); }
        catch (KeycloakProtocolException e) when (e.StatusCode == HttpStatusCode.BadRequest && e.Error == OAuthError.InvalidRequest) { malformedScope = true; }
        check(badPassword && malformedScope, "Docker registry rejects invalid credentials and malformed repository scopes");
        var app = (await admin.Clients.GetClientsAsync(realm, clientId: "docker-registry", cancellationToken: ct)).Body!.Single();
        var mapper = (await admin.Client.GetClientAsync(realm, app.Id!, cancellationToken: ct)).Body!.ProtocolMappers!.Single();
        await admin.SendAsync(HttpMethod.Delete, "/admin/realms/" + realm + "/clients/" + app.Id + "/protocol-mappers/models/" + mapper.Id, cancellationToken: ct);
        string restricted = (await registry.AuthenticateChallengeAsync(challenge, _ => ValueTask.FromResult(new NetworkCredential("account-user", secret)), ct)).Json!.Value.GetProperty("token").GetString()!;
        var restrictedValidation = await handler.ValidateTokenAsync(restricted, parameters); ct.ThrowIfCancellationRequested();
        using var restrictedPayload = JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(restricted.Split('.')[1]));
        check(restrictedValidation.IsValid && (!restrictedPayload.RootElement.TryGetProperty("access", out var grants) || grants.GetArrayLength() == 0),
            "Removing Docker scope-grant policy produces no repository access grants despite successful authentication");
    }
}
