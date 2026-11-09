using System.Net;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Protocols;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

internal static class ProtocolFederatedClientWorkflows
{
    internal static async Task RunAsync(KeycloakAdminClient admin, ProtocolTransport transport, string realm, Action<bool, string> check, CancellationToken ct)
    {
        using var key = RSA.Create(2048); using var rotatedKey = RSA.Create(2048); using var attackerKey = RSA.Create(2048);
        await using var issuer = new ProtocolWorkloadIssuer(key, "initial-key"); var oidc = new OidcClient(transport);
        string directory = Path.Combine(Path.GetTempPath(), "sdk-workload-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(directory);
        try
        {
            foreach (string kind in new[] { "kubernetes", "spiffe" })
            {
                issuer.Publish(key, "initial-key"); await admin.ClearKeysCache.ClearKeysCacheAsync(realm, cancellationToken: ct);
                string clientId = "workload-" + kind, alias = "issuer-" + kind, subject = kind == "kubernetes" ? "system:serviceaccount:sdk:application" : "spiffe://sdk.invalid/application";
                var provider = new IdentityProviderRepresentation { Alias = alias, ProviderId = kind, Enabled = true,
                    Config = kind == "kubernetes" ? new() { ["issuerDiscoveryUrl"] = ProtocolWorkloadIssuer.Root, ["federatedClientAssertionMaxExpiration"] = "120" }
                        : new() { ["trustDomain"] = "spiffe://sdk.invalid", ["bundleEndpoint"] = ProtocolWorkloadIssuer.Root + "/bundle", ["federatedClientAssertionMaxExpiration"] = "120" } };
                await admin.IdentityProviders.CreateAsync(realm, provider, ct);
                await admin.Clients.CreateClientAsync(realm, new ClientRepresentation { ClientId = clientId, Protocol = "openid-connect", Enabled = true, PublicClient = false,
                    ClientAuthenticatorType = "federated-jwt", ServiceAccountsEnabled = true, Attributes = new() { ["jwt.credential.issuer"] = alias, ["jwt.credential.sub"] = subject },
                    ProtocolMappers = [new() { Name = "audience", Protocol = "openid-connect", ProtocolMapper = "oidc-audience-mapper", Config = new() { ["included.client.audience"] = clientId, ["access.token.claim"] = "true" } }] }, cancellationToken: ct);
                var registered = (await admin.Clients.GetClientsAsync(realm, clientId: clientId, cancellationToken: ct)).Body!.Single();
                var serviceUser = (await admin.Client.GetServiceAccountUserAsync(realm, registered.Id!, ct)).Body!;
                string Assertion(RSA signingKey, string kid, string? aud = null, string? sub = null, bool expired = false, string? externalIssuer = null)
                {
                    var now = DateTimeOffset.UtcNow;
                    var claims = new Dictionary<string, object> { ["sub"] = sub ?? subject };
                    if (kind == "kubernetes") claims["kubernetes.io"] = new Dictionary<string, object> { ["namespace"] = "sdk", ["serviceaccount"] = new Dictionary<string, object> { ["name"] = "application", ["uid"] = "controlled-fixture-service-account" } };
                    return new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(new SecurityTokenDescriptor
                    { Issuer = kind == "kubernetes" ? externalIssuer ?? ProtocolWorkloadIssuer.KubernetesIssuer : null, Audience = aud ?? oidc.Issuer.AbsoluteUri,
                        IssuedAt = now.AddSeconds(expired ? -180 : 0).UtcDateTime, NotBefore = now.AddSeconds(expired ? -180 : -5).UtcDateTime, Expires = now.AddSeconds(expired ? -60 : 60).UtcDateTime,
                        SigningCredentials = new(new RsaSecurityKey(signingKey) { KeyId = kid }, "RS256"), Claims = claims });
                }
                string path = Path.Combine(directory, kind + ".jwt"); var projected = new ProjectedWorkloadToken(path);
                var authentication = kind == "kubernetes" ? OAuthClientAuthentication.FederatedAssertion(clientId, projected.ReadAsync) : OAuthClientAuthentication.SpiffeAssertion(clientId, projected.ReadAsync);
                async Task Write(string assertion) { string temporary = path + ".next"; await File.WriteAllTextAsync(temporary, assertion, ct); File.Move(temporary, path, true); }
                async Task<VerifiedAccessToken> Authenticate()
                {
                    var response = await oidc.ClientCredentialsAsync(authentication, cancellationToken: ct);
                    return await new KeycloakAccessTokenValidator(oidc, clientId).ValidateAsync(response.Json!.Value.GetProperty("access_token").GetString()!, ct);
                }
                string current = Assertion(key, "initial-key"); await Write(current); var token = await Authenticate();
                check(token.Subject == serviceUser.Id && token.Claims.GetProperty("azp").GetString() == clientId,
                    kind == "kubernetes" ? "Kubernetes provider validates a projected credential through controlled OIDC discovery and JWKS and authenticates only its mapped service account"
                    : "SPIFFE provider validates a projected JWT-SVID against the controlled trust-domain bundle using the distinct jwt-spiffe assertion type");
                // These upstream providers permit workload credential reuse within its validity; no jti is required for JWT-SVIDs.
                check((await Authenticate()).Subject == serviceUser.Id, kind == "kubernetes" ? "Kubernetes projected credentials follow the upstream reusable bounded-lifetime assertion semantics" : "SPIFFE JWT-SVID reuse without a jti follows the upstream bounded-lifetime workload semantics");
                foreach (string invalid in new[] { Assertion(key, "initial-key", aud: "https://wrong-audience.invalid/"), Assertion(key, "initial-key", sub: subject + "-unmapped"),
                    Assertion(key, "initial-key", expired: true), Assertion(attackerKey, "initial-key") })
                {
                    await Write(invalid); bool denied = false;
                    try { await Authenticate(); } catch (KeycloakProtocolException error) when (error.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.BadRequest) { denied = true; }
                    if (!denied) throw new InvalidDataException("Workload provider accepted an invalid assertion.");
                }
                check(true, kind == "kubernetes" ? "Kubernetes federation rejects foreign audience unmapped subjects expiry and untrusted signatures" : "SPIFFE federation rejects foreign audience unmapped SPIFFE identities expiry and untrusted signatures");
                if (kind == "kubernetes")
                {
                    await Write(Assertion(key, "initial-key", externalIssuer: "https://untrusted.invalid/")); bool denied = false;
                    try { await Authenticate(); } catch (KeycloakProtocolException error) when (error.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.BadRequest) { denied = true; }
                    check(denied, "Kubernetes federation rejects an assertion issuer that differs from the configured discovery issuer");
                }
                issuer.Publish(rotatedKey, "rotated-key"); await admin.ClearKeysCache.ClearKeysCacheAsync(realm, cancellationToken: ct); await Write(Assertion(rotatedKey, "rotated-key"));
                check((await Authenticate()).Subject == serviceUser.Id, kind == "kubernetes" ? "Kubernetes credential file replacement and issuer key rotation are read on the next authentication request" : "SPIFFE credential file replacement and trust-bundle key rotation are read on the next authentication request");
                await Write(Assertion(key, "initial-key")); bool retired = false;
                try { await Authenticate(); } catch (KeycloakProtocolException error) when (error.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.BadRequest) { retired = true; }
                check(retired, kind == "kubernetes" ? "Kubernetes federation refuses a fresh assertion from the retired issuer key" : "SPIFFE federation refuses a fresh JWT-SVID from the retired bundle key");
                await Write(Assertion(rotatedKey, "rotated-key")); provider.Enabled = false; await admin.IdentityProvider.UpdateAsync(realm, alias, provider, ct); bool disabled = false;
                try { await Authenticate(); } catch (KeycloakProtocolException error) when (error.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.BadRequest) { disabled = true; }
                check(disabled, kind == "kubernetes" ? "Disabling the Kubernetes trust provider immediately prevents new client authentication" : "Disabling the SPIFFE trust provider immediately prevents new client authentication");
            }
        }
        finally
        {
            string target = Path.GetFullPath(directory), parent = Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            if (!target.StartsWith(parent, StringComparison.Ordinal)) throw new IOException("Workload fixture cleanup escaped its owned temporary directory.");
            Directory.Delete(target, true);
        }
    }
}
