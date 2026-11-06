using System.Security.Cryptography;
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Protocols;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

internal static class ProtocolJwtGrantWorkflows
{
    internal static async Task RunAsync(KeycloakAdminClient admin, ProtocolTransport transport, string realm, string secret, Action<bool, string> check, CancellationToken ct)
    {
        using var key = RSA.Create(2048); using var attackerKey = RSA.Create(2048);
        const string externalIssuer = "https://trusted.invalid/authorization-grants", alias = "assertion-issuer";
        var publicKey = new RsaSecurityKey(key) { KeyId = "assertion-key" };
        var idp = new IdentityProviderRepresentation { Alias = alias, ProviderId = "jwt-authorization-grant", Enabled = true,
            Config = new() { ["issuer"] = externalIssuer, ["jwtAuthorizationGrantEnabled"] = "true", ["useJwksUrl"] = "false",
                ["publicKeySignatureVerifier"] = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()), ["publicKeySignatureVerifierKeyId"] = publicKey.KeyId,
                ["jwtAuthorizationGrantAssertionSignatureAlg"] = "RS256", ["jwtAuthorizationGrantMaxAllowedAssertionExpiration"] = "120", ["jwtAuthorizationGrantLimitAccessTokenExp"] = "true" } };
        await admin.IdentityProviders.CreateAsync(realm, idp, ct);
        var actual = (await admin.Users.GetUsersAsync(realm, username: "account-user", exact: true, cancellationToken: ct)).Body!.Single();
        await admin.User.AddFederatedIdentityAsync(realm, actual.Id!, alias, new() { IdentityProvider = alias, UserId = "external-user", UserName = "external-user" }, ct);
        await admin.Clients.CreateClientAsync(realm, new ClientRepresentation { ClientId = "jwt-grant-client", Protocol = "openid-connect", Enabled = true, PublicClient = false, Secret = secret,
            Attributes = new() { ["oauth2.jwt.authorization.grant.enabled"] = "true", ["oauth2.jwt.authorization.grant.idp"] = alias },
            ProtocolMappers = [new() { Name = "audience", Protocol = "openid-connect", ProtocolMapper = "oidc-audience-mapper", Config = new() { ["included.client.audience"] = "jwt-grant-client", ["access.token.claim"] = "true" } }] }, cancellationToken: ct);
        var oidc = new OidcClient(transport); var auth = OAuthClientAuthentication.SecretBasic("jwt-grant-client", _ => ValueTask.FromResult(secret));
        string Assertion(string? issuer = null, string? audience = null, string? subject = null, bool expired = false, bool attacker = false,
            bool identityAssertion = false, string? relyingParty = null, bool missingIssuedAt = false)
        {
            var now = DateTimeOffset.UtcNow;
            var claims = new Dictionary<string, object> { ["sub"] = subject ?? "external-user", ["jti"] = Guid.NewGuid().ToString("N") };
            if (identityAssertion && relyingParty != "") claims["client_id"] = relyingParty ?? "jwt-grant-client";
            return new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(new SecurityTokenDescriptor { Issuer = issuer ?? externalIssuer, Audience = audience ?? oidc.Issuer.AbsoluteUri,
                TokenType = identityAssertion ? "oauth-id-jag+jwt" : "JWT", IssuedAt = missingIssuedAt ? null : now.AddSeconds(expired ? -180 : 0).UtcDateTime,
                NotBefore = now.AddSeconds(expired ? -180 : -5).UtcDateTime, Expires = now.AddSeconds(expired ? -60 : 60).UtcDateTime,
                SigningCredentials = new(attacker ? new RsaSecurityKey(attackerKey) { KeyId = publicKey.KeyId } : publicKey, "RS256"), Claims = claims });
        }
        string assertion = Assertion(); var result = await oidc.JwtGrantAsync(auth, assertion, "openid", ct);
        var verified = await new KeycloakAccessTokenValidator(oidc, "jwt-grant-client").ValidateAsync(result.Json!.Value.GetProperty("access_token").GetString()!, ct);
        check(verified.Subject == actual.Id && verified.ExpiresAt.ToUnixTimeSeconds() <= new JsonWebToken(assertion).ValidTo.ToUniversalTime().Subtract(DateTime.UnixEpoch).TotalSeconds,
            "JWT authorization grant maps a trusted signed external assertion to the linked local user and limits the verified access-token lifetime");
        bool replay = false;
        try { await oidc.JwtGrantAsync(auth, assertion, cancellationToken: ct); } catch (KeycloakProtocolException error) when (error.Error == OAuthError.InvalidGrant) { replay = true; }
        check(replay, "JWT authorization grant rejects reuse of the same signed assertion jti");
        foreach (var (invalid, proof) in new[] {
            (Assertion(issuer: "https://untrusted.invalid/"), "JWT authorization grant rejects an untrusted external issuer"),
            (Assertion(audience: "https://foreign.invalid/"), "JWT authorization grant rejects an assertion for a foreign audience"),
            (Assertion(expired: true), "JWT authorization grant rejects a real expired assertion"),
            (Assertion(attacker: true), "JWT authorization grant rejects a signature from an unconfigured key"),
            (Assertion(subject: "unlinked-user"), "JWT authorization grant refuses to invent a local identity for an unlinked external subject") })
        {
            bool denied = false;
            try { await oidc.JwtGrantAsync(auth, invalid, cancellationToken: ct); } catch (KeycloakProtocolException error) when (error.Error == OAuthError.InvalidGrant) { denied = true; }
            check(denied, proof);
        }
        idp.Config!["jwtAuthorizationGrantAssertionReuseAllowed"] = "true"; await admin.IdentityProvider.UpdateAsync(realm, alias, idp, ct);
        string identityAssertion = Assertion(identityAssertion: true);
        var identityResult = await oidc.IdentityAssertionGrantAsync(auth, identityAssertion, "openid", ct);
        check((await new KeycloakAccessTokenValidator(oidc, "jwt-grant-client").ValidateAsync(identityResult.Json!.Value.GetProperty("access_token").GetString()!, ct)).Subject == actual.Id,
            "ID-JAG consumption preserves the trusted external subject and authenticates the exact client_id relying party in the signed identity assertion");
        bool identityReplay = false;
        try { await oidc.IdentityAssertionGrantAsync(auth, identityAssertion, cancellationToken: ct); } catch (KeycloakProtocolException error) when (error.Error == OAuthError.InvalidGrant) { identityReplay = true; }
        check(identityReplay, "ID-JAG refuses assertion replay even when the external provider permits ordinary JWT assertion reuse");
        foreach (string invalid in new[] { Assertion(identityAssertion: true, relyingParty: "unrelated-client"), Assertion(identityAssertion: true, relyingParty: ""), Assertion(identityAssertion: true, missingIssuedAt: true) })
        {
            bool rejected = false;
            try { await oidc.IdentityAssertionGrantAsync(auth, invalid, cancellationToken: ct); } catch (KeycloakProtocolException error) when (error.Error == OAuthError.InvalidGrant) { rejected = true; }
            if (!rejected) throw new InvalidDataException("ID-JAG accepted an invalid relying-party binding or missing issued-at claim.");
        }
        check(true, "ID-JAG rejects a foreign or missing client_id and a missing iat instead of falling back to ordinary JWT grant semantics");
        idp.Enabled = false; await admin.IdentityProvider.UpdateAsync(realm, alias, idp, ct); bool disabled = false;
        try { await oidc.JwtGrantAsync(auth, Assertion(), cancellationToken: ct); } catch (KeycloakProtocolException error) when (error.Error == OAuthError.InvalidGrant) { disabled = true; }
        check(disabled, "Disabling the trusted assertion provider prevents subsequent JWT authorization grants");
        await admin.User.RemoveFederatedIdentityAsync(realm, actual.Id!, alias, ct); await admin.IdentityProvider.DeleteAsync(realm, alias, ct);
    }
}
