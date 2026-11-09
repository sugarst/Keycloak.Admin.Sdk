using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Protocols;
using Microsoft.IdentityModel.Tokens;

internal static class ProtocolCibaWorkflows
{
    internal static async Task RunAsync(KeycloakAdminClient admin, ProtocolTransport transport, string realm, string secret, Action<bool, string> check, CancellationToken ct)
    {
        await using var receiver = new ProtocolCallbackReceiver(); var oidc = new OidcClient(transport);
        var actualUser = (await admin.Users.GetUsersAsync(realm, username: "account-user", exact: true, cancellationToken: ct)).Body!.Single();
        var settings = (await admin.RealmAdmin.GetRealmAsync(realm, cancellationToken: ct)).Body!; settings.Attributes ??= []; settings.Attributes["cibaInterval"] = "1";
        await admin.RealmAdmin.UpdateRealmAsync(realm, settings, ct);
        async Task<OAuthClientAuthentication> Client(string id, string mode, Dictionary<string, string>? extra = null)
        {
            var attributes = extra ?? []; attributes["oidc.ciba.grant.enabled"] = "true"; attributes["ciba.backchannel.token.delivery.mode"] = mode;
            if (mode == "ping") attributes["ciba.backchannel.client.notification.endpoint"] = "http://127.0.0.1:18081/ping";
            await admin.Clients.CreateClientAsync(realm, new ClientRepresentation { ClientId = id, Protocol = "openid-connect", Enabled = true, PublicClient = false, Secret = secret,
                Attributes = attributes, ProtocolMappers = [new ProtocolMapperRepresentation { Name = "own-audience", Protocol = "openid-connect", ProtocolMapper = "oidc-audience-mapper",
                    Config = new() { ["included.client.audience"] = id, ["access.token.claim"] = "true" } }] }, cancellationToken: ct);
            return OAuthClientAuthentication.SecretBasic(id, _ => ValueTask.FromResult(secret));
        }
        async Task<string> ChannelCredential(string binding)
        {
            var channel = await receiver.NextAsync("/authenticate", ct); using var body = JsonDocument.Parse(channel.Body);
            if (body.RootElement.GetProperty("login_hint").GetString() != "account-user" || body.RootElement.GetProperty("binding_message").GetString() != binding)
                throw new InvalidDataException("Authentication device received mismatched request context.");
            var header = AuthenticationHeaderValue.Parse(channel.Authorization);
            if (header.Scheme != "Bearer" || header.Parameter is null) throw new InvalidDataException("Authentication device did not receive a distinct channel credential.");
            var identity = await new KeycloakAccessTokenValidator(oidc, oidc.Issuer.AbsoluteUri).ValidateAsync(header.Parameter, ct);
            if (identity.Subject != actualUser.Id) throw new InvalidDataException("Authentication channel credential identifies the wrong user.");
            return header.Parameter;
        }
        var pollClient = await Client("ciba-poll", "poll");
        var request = await oidc.RequestBackchannelAuthenticationAsync(pollClient, new CibaAuthenticationRequest { LoginHint = "account-user", BindingMessage = "POLL-123", RequestedExpirySeconds = 120 }, "openid", ct);
        var lease = OAuthPollingLease.FromCibaResponse(request); string channelToken = await ChannelCredential("POLL-123");
        bool pending = false;
        try { await oidc.RedeemBackchannelAuthenticationAsync(pollClient, lease.Identifier, ct); }
        catch (KeycloakProtocolException e) when (e.Error == OAuthError.AuthorizationPending) { pending = true; }
        check(pending, "CIBA poll remains pending until a separately authenticated device approves the bound user request");
        bool incorrect = false;
        try { await oidc.CompleteBackchannelAuthenticationAsync("invalid-channel-token", CibaAuthenticationResult.Approved, ct); }
        catch (KeycloakProtocolException e) when (e.StatusCode == HttpStatusCode.Forbidden) { incorrect = true; }
        await oidc.CompleteBackchannelAuthenticationAsync(channelToken, CibaAuthenticationResult.Approved, ct);
        var tokens = await oidc.PollBackchannelAsync(pollClient, lease, cancellationToken: ct);
        var verified = await new KeycloakAccessTokenValidator(oidc, "ciba-poll").ValidateAsync(tokens.Json!.Value.GetProperty("access_token").GetString()!, ct);
        check(incorrect && verified.Subject == actualUser.Id, "CIBA rejects an invalid authentication-device credential and issues a verified user token after valid approval");
        bool reused = false;
        try { await oidc.RedeemBackchannelAuthenticationAsync(pollClient, lease.Identifier, ct); }
        catch (KeycloakProtocolException e) when (e.Error is OAuthError.InvalidGrant or OAuthError.ExpiredToken) { reused = true; }
        check(reused, "CIBA authentication request credentials cannot be redeemed twice");
        foreach (var status in new[] { CibaAuthenticationResult.Denied, CibaAuthenticationResult.Cancelled })
        {
            var denied = await oidc.RequestBackchannelAuthenticationAsync(pollClient, new CibaAuthenticationRequest { LoginHint = "account-user", BindingMessage = "DENY-123" }, "openid", ct);
            string credential = await ChannelCredential("DENY-123"); await oidc.CompleteBackchannelAuthenticationAsync(credential, status, ct);
            bool refused = false;
            try { await oidc.RedeemBackchannelAuthenticationAsync(pollClient, OAuthPollingLease.FromCibaResponse(denied).Identifier, ct); }
            catch (KeycloakProtocolException e) when (e.Error == OAuthError.AccessDenied) { refused = true; }
            check(refused, status == CibaAuthenticationResult.Denied ? "CIBA user denial yields access_denied without issuing credentials" : "CIBA authentication-device cancellation yields access_denied without issuing credentials");
        }
        // 26.8.1 stores/returns the realm policy lifetime even when requested_expiry is shorter.
        settings.Attributes["cibaExpiresIn"] = "1"; await admin.RealmAdmin.UpdateRealmAsync(realm, settings, ct);
        var expiring = await oidc.RequestBackchannelAuthenticationAsync(pollClient, new CibaAuthenticationRequest { LoginHint = "account-user", BindingMessage = "EXPIRE", RequestedExpirySeconds = 1 }, "openid", ct);
        await ChannelCredential("EXPIRE"); await Task.Delay(TimeSpan.FromSeconds(2), ct); bool expired = false;
        try { await oidc.RedeemBackchannelAuthenticationAsync(pollClient, OAuthPollingLease.FromCibaResponse(expiring).Identifier, ct); }
        catch (KeycloakProtocolException e) when (e.Error == OAuthError.ExpiredToken) { expired = true; }
        check(expired, "CIBA rejects a server-expired authentication request");
        settings.Attributes["cibaExpiresIn"] = "120"; await admin.RealmAdmin.UpdateRealmAsync(realm, settings, ct);
        var pingClient = await Client("ciba-ping", "ping"); string notificationToken = CibaPingNotificationValidator.CreateNotificationToken();
        var ping = await oidc.RequestBackchannelAuthenticationAsync(pingClient, new CibaAuthenticationRequest { LoginHint = "account-user", BindingMessage = "PING-123", ClientNotificationToken = notificationToken }, "openid", ct);
        var pingLease = OAuthPollingLease.FromCibaResponse(ping); string pingChannel = await ChannelCredential("PING-123");
        await oidc.CompleteBackchannelAuthenticationAsync(pingChannel, CibaAuthenticationResult.Approved, ct);
        var notification = await receiver.NextAsync("/ping", ct); using var notificationJson = JsonDocument.Parse(notification.Body);
        var validator = new CibaPingNotificationValidator(transport, pingLease, notificationToken, new InMemoryDpopReplayStore());
        bool badNotification = false, repeated = false;
        try { await validator.ValidateAsync("Bearer incorrect-secret", notificationJson.RootElement, ct); } catch (InvalidDataException) { badNotification = true; }
        await validator.ValidateAsync(notification.Authorization, notificationJson.RootElement, ct);
        try { await validator.ValidateAsync(notification.Authorization, notificationJson.RootElement, ct); } catch (InvalidDataException) { repeated = true; }
        var pingTokens = await oidc.RedeemBackchannelAuthenticationAsync(pingClient, pingLease.Identifier, ct);
        check(badNotification && repeated && (await new KeycloakAccessTokenValidator(oidc, "ciba-ping").ValidateAsync(pingTokens.Json!.Value.GetProperty("access_token").GetString()!, ct)).Subject == actualUser.Id,
            "CIBA ping authenticates the notification secret correlates auth_req_id rejects replay and then redeems the approved user credential");
        using var signingKey = RSA.Create(2048);
        using var certificate = new CertificateRequest("CN=ciba-request", signingKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
        var signedClient = await Client("ciba-signed", "poll", new() { ["ciba.backchannel.auth.request.signing.alg"] = "RS256", ["jwt.credential.certificate"] = Convert.ToBase64String(certificate.RawData) });
        var signer = new CibaRequestSigner("ciba-signed", oidc, new(new RsaSecurityKey(signingKey), "RS256"));
        string signed = await signer.CreateAsync(new() { LoginHint = "account-user", BindingMessage = "SIGNED-123", RequestedExpirySeconds = 60 }, "openid", ct);
        var signedResponse = await oidc.RequestBackchannelAuthenticationAsync(signedClient, new CibaAuthenticationRequest { SignedRequest = signed }, cancellationToken: ct);
        string signedChannel = await ChannelCredential("SIGNED-123"); await oidc.CompleteBackchannelAuthenticationAsync(signedChannel, CibaAuthenticationResult.Approved, ct);
        var signedTokens = await oidc.PollBackchannelAsync(signedClient, OAuthPollingLease.FromCibaResponse(signedResponse), cancellationToken: ct);
        check((await new KeycloakAccessTokenValidator(oidc, "ciba-signed").ValidateAsync(signedTokens.Json!.Value.GetProperty("access_token").GetString()!, ct)).Subject == actualUser.Id,
            "CIBA accepts a signed authentication request bound to the configured client realm audience and numeric expiry");
    }
}
