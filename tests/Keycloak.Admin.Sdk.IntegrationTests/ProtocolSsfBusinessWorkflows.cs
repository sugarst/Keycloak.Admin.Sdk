using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Protocols;

internal static class ProtocolSsfBusinessWorkflows
{
    private const string Caep = "https://schemas.openid.net/secevent/caep/event-type/";
    private const string Risc = "https://schemas.openid.net/secevent/risc/event-type/";
    internal static async Task RunAsync(KeycloakAdminClient admin, ProtocolTransport transport, string realm, string secret, SsfClient ssf, string streamId,
        string receiverToken, string[] types, Action<bool, string> check, CancellationToken ct)
    {
        JsonElement Element(JsonNode value) { using var doc = JsonDocument.Parse(value.ToJsonString()); return doc.RootElement.Clone(); }
        string path = Path.Combine(Path.GetTempPath(), "sdk-ssf-" + Guid.NewGuid().ToString("N") + ".json");
        var oidc = new OidcClient(transport);
        await admin.Clients.CreateClientAsync(realm, new() { ClientId = "ssf-user-app", Protocol = "openid-connect", Enabled = true, PublicClient = false, Secret = secret, DirectAccessGrantsEnabled = true,
            ProtocolMappers = [new() { Name = "own-audience", Protocol = "openid-connect", ProtocolMapper = "oidc-audience-mapper", Config = new() { ["included.client.audience"] = "ssf-user-app", ["access.token.claim"] = "true" } },
                new() { Name = "notification-state", Protocol = "openid-connect", ProtocolMapper = "oidc-usermodel-attribute-mapper", Config = new() { ["user.attribute"] = "ssf.notify.ssf-receiver", ["claim.name"] = "ssf_notification", ["jsonType.label"] = "String", ["access.token.claim"] = "true" } },
                new() { Name = "notification-removal", Protocol = "openid-connect", ProtocolMapper = "oidc-usermodel-attribute-mapper", Config = new() { ["user.attribute"] = "ssf.notifyRemovedAt.ssf-receiver", ["claim.name"] = "ssf_removed_at", ["jsonType.label"] = "String", ["access.token.claim"] = "true" } }] }, cancellationToken: ct);
        var auth = OAuthClientAuthentication.SecretBasic("ssf-user-app", _ => ValueTask.FromResult(secret));
        async Task<JsonElement> Attributes(UserRepresentation user)
        {
            var token = await oidc.PasswordGrantAsync(auth, user.Username!, secret, cancellationToken: ct);
            var verified = await new KeycloakAccessTokenValidator(oidc, "ssf-user-app").ValidateAsync(token.Json!.Value.GetProperty("access_token").GetString()!, ct);
            if (verified.Subject != user.Id) throw new InvalidDataException("Wrong subject for SSF notification attribute mapping."); return verified.Claims;
        }
        async Task<UserRepresentation> User(string name)
        {
            await admin.Users.CreateUserAsync(realm, new() { Username = name, FirstName = "SSF", LastName = "User", Email = name + "@example.invalid", EmailVerified = true, Enabled = true,
                Credentials = [new() { Type = "password", Value = secret, Temporary = false }] }, cancellationToken: ct);
            return (await admin.Users.GetUsersAsync(realm, username: name, exact: true, cancellationToken: ct)).Body!.Single();
        }
        try
        {
            var user = await User("ssf-event-user");
            var receiverClient = (await admin.Clients.GetClientsAsync(realm, clientId: "ssf-receiver", cancellationToken: ct)).Body!.Single();
            receiverClient.Attributes!["ssf.defaultSubjects"] = "NONE";
            await admin.Client.UpdateAsync(realm, receiverClient.Id!, receiverClient, ct);
            JsonElement Subject(string issuer) => Element(new JsonObject { ["stream_id"] = streamId, ["subject"] = new JsonObject { ["format"] = "iss_sub", ["iss"] = issuer, ["sub"] = user.Id }, ["verified"] = true });
            bool foreignSubject = false;
            try { await ssf.AddSubjectAsync(Subject("https://untrusted.invalid/realms/other"), receiverToken, ct); }
            catch (KeycloakProtocolException e) when (e.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.NotFound) { }
            // Default privacy mode returns 200 even for an unknown subject. Verify absence of the effect, not a revealing status.
            foreignSubject = !(await Attributes(user)).TryGetProperty("ssf_notification", out _);
            await ssf.AddSubjectAsync(Subject(transport.Issuer.AbsoluteUri), receiverToken, ct);
            check(foreignSubject && (await Attributes(user)).GetProperty("ssf_notification").GetString() == "true",
                "SSF receiver subject subscription rejects a foreign issuer and persists the exact local subject notification attribute");
            await ssf.RemoveSubjectAsync(Subject(transport.Issuer.AbsoluteUri), receiverToken, ct);
            var removedSubject = await Attributes(user);
            check(!removedSubject.TryGetProperty("ssf_notification", out _) && removedSubject.TryGetProperty("ssf_removed_at", out _),
                "SSF receiver removal clears the explicit subscription and persists the server's removal-grace timestamp without claiming immediate revocation");
            await ssf.AddSubjectAsync(Subject(transport.Issuer.AbsoluteUri), receiverToken, ct);
            var readded = await Attributes(user);
            check(readded.GetProperty("ssf_notification").GetString() == "true" && !readded.TryGetProperty("ssf_removed_at", out _),
                "Re-subscribing an SSF subject restores its persisted notification and clears the previous removal-grace timestamp");
            var grant = await oidc.PasswordGrantAsync(auth, user.Username!, secret, cancellationToken: ct);
            var identity = await new KeycloakAccessTokenValidator(oidc, "ssf-user-app").ValidateAsync(grant.Json!.Value.GetProperty("access_token").GetString()!, ct);
            string sessionId = identity.Claims.GetProperty("sid").GetString()!;
            await oidc.LogoutAsync(auth, grant.Json.Value.GetProperty("refresh_token").GetString()!, ct);
            var inbox = new ProtocolSsfInbox(path, transport.Issuer.AbsoluteUri) { FailNext = true };
            var processor = new SecurityEventProcessor(transport, "sdk-ssf-receiver", types, inbox);
            ProtocolResponse? first = null;
            for (int attempt = 0; attempt < 40; attempt++)
            {
                first = await ssf.PollAsync("ssf-receiver", streamId, Element(new JsonObject { ["maxEvents"] = 100 }), receiverToken, ct);
                if (first.Json!.Value.GetProperty("sets").EnumerateObject().Any()) break;
                await Task.Delay(250, ct);
            }
            bool storageFailed = false;
            try { await processor.ProcessPollResponseAsync(first!, ct); } catch (IOException) { storageFailed = true; }
            check(storageFailed && inbox.ReadEvents().Count == 0, "SSF storage failure does not reserve the signed event or acknowledge an uncommitted local business effect");
            var ack = await processor.ProcessPollResponseAsync(first!, ct);
            var persisted = inbox.ReadEvents();
            check(persisted.Any(e => e!["type"]!.GetValue<string>() == Caep + "session-revoked" && e["subject"]!["user"]!["sub"]!.GetValue<string>() == user.Id
                && e["subject"]!["session"]!["id"]!.GetValue<string>() == sessionId),
                "A real Keycloak CAEP logout event binds its verified issuer user and exact revoked session before the application persists its effect");
            var reopened = new ProtocolSsfInbox(path, transport.Issuer.AbsoluteUri);
            processor = new(transport, "sdk-ssf-receiver", types, reopened);
            await processor.ProcessPollResponseAsync(first!, ct);
            check(reopened.ReadEvents().Count == persisted.Count, "Reopening the receiver's persisted inbox prevents duplicate business effects when the same signed SET is retried before acknowledgement");
            await admin.User.ResetPasswordAsync(realm, user.Id!, new() { Type = "password", Value = secret + "changed", Temporary = false }, ct);
            await admin.User.UpdateUserAsync(realm, user.Id!, new() { Enabled = false }, ct);
            await admin.User.UpdateUserAsync(realm, user.Id!, new() { Enabled = true }, ct);
            await admin.User.DeleteUserAsync(realm, user.Id!, ct);
            string[] required = [Caep + "credential-change", Risc + "account-disabled", Risc + "account-enabled", Risc + "account-purged"];
            bool complete = false;
            for (int attempt = 0; attempt < 60; attempt++)
            {
                var response = await ssf.PollAsync("ssf-receiver", streamId, Element(new JsonObject { ["maxEvents"] = 100, ["ack"] = new JsonArray(ack.Select(a => (JsonNode)JsonValue.Create(a)!).ToArray()) }), receiverToken, ct);
                ack = await processor.ProcessPollResponseAsync(response, ct);
                var events = reopened.ReadEvents();
                complete = required.All(type => events.Any(e => e!["type"]!.GetValue<string>() == type));
                if (complete && ack.Count == 0) break; // The previous batch was acknowledged; no newly delivered events were discarded.
                await Task.Delay(250, ct);
            }
            check(complete && required.All(type => reopened.ReadEvents().Any(e => e!["type"]!.GetValue<string>() == type && (e["subject"]?["user"] ?? e["subject"])!["sub"]!.GetValue<string>() == user.Id)),
                "Real password reset disable enable and purge operations deliver independently verified CAEP and RISC events for the exact persisted subject before poll acknowledgement");
            var credential = reopened.ReadEvents().First(e => e!["type"]!.GetValue<string>() == Caep + "credential-change")!["payload"]!;
            check(credential["credential_type"]?.GetValue<string>() == "password" && !string.IsNullOrWhiteSpace(credential["change_type"]?.GetValue<string>()),
                "The verified CAEP credential-change payload identifies the actual changed password credential without exposing credential material");

            var pushClient = new ClientRepresentation { ClientId = "ssf-push", Protocol = "openid-connect", Enabled = true, PublicClient = false, Secret = secret, ServiceAccountsEnabled = true,
                Attributes = new() { ["ssf.enabled"] = "true", ["ssf.profile"] = "SSE_CAEP", ["ssf.autoVerifyStream"] = "true", ["ssf.streamAudience"] = "sdk-ssf-push",
                    ["ssf.supportedEvents"] = "CaepSessionRevoked", ["ssf.defaultSubjects"] = "ALL", ["ssf.validPushUrls"] = "http://127.0.0.1:18084/events" } };
            await admin.Clients.CreateClientAsync(realm, pushClient, cancellationToken: ct);
            pushClient = (await admin.Clients.GetClientsAsync(realm, clientId: "ssf-push", cancellationToken: ct)).Body!.Single();
            foreach (var scope in (await admin.ClientScopes.GetClientScopesAsync(realm, ct)).Body!.Where(s => s.Name is "ssf.read" or "ssf.manage")) await admin.Client.AddDefaultClientScopeAsync(realm, pushClient.Id!, scope.Id!, ct);
            string pushToken = (await oidc.ClientCredentialsAsync(OAuthClientAuthentication.SecretBasic("ssf-push", _ => ValueTask.FromResult(secret)), "ssf.read ssf.manage", ct)).Json!.Value.GetProperty("access_token").GetString()!;
            const string verification = "https://schemas.openid.net/secevent/ssf/event-type/verification";
            var pushProcessor = new SecurityEventProcessor(transport, "sdk-ssf-push", [Caep + "session-revoked", verification], reopened);
            await using var receiver = new ProtocolSsfReceiver(pushProcessor, "Bearer " + secret);
            var push = (await ssf.CreateStreamAsync(Element(new JsonObject { ["events_requested"] = new JsonArray(Caep + "session-revoked"),
                ["delivery"] = new JsonObject { ["method"] = "urn:ietf:rfc:8935", ["endpoint_url"] = "http://127.0.0.1:18084/events", ["authorization_header"] = "Bearer " + secret } }), pushToken, ct)).Json!.Value;
            var pushUser = await User("ssf-push-user"); await oidc.PasswordGrantAsync(auth, pushUser.Username!, secret, cancellationToken: ct);
            await admin.User.LogoutAsync(realm, pushUser.Id!, ct);
            VerifiedSecurityEventToken pushed;
            do { pushed = await receiver.NextAsync(ct); } while (!pushed.Events.TryGetProperty(Caep + "session-revoked", out _));
            check(!pushed.Claims.TryGetProperty("sub_id", out _) && pushed.Events.GetProperty(Caep + "session-revoked").GetProperty("subject").GetProperty("user").GetProperty("sub").GetString() == pushUser.Id
                && reopened.ReadEvents().Any(e => e!["id"]!.GetValue<string>() == pushed.Id),
                "SSF push validates and commits a real SSE-CAEP compatibility event before HTTP success while preserving the exact issuer and subject namespace");
            bool unapproved = false;
            try { await ssf.UpdateStreamAsync(Element(new JsonObject { ["stream_id"] = push.GetProperty("stream_id").GetString(), ["delivery"] = new JsonObject { ["method"] = "urn:ietf:rfc:8935", ["endpoint_url"] = "http://127.0.0.1:18084/unapproved" } }), pushToken, ct); }
            catch (KeycloakProtocolException e) when (e.StatusCode == HttpStatusCode.BadRequest) { unapproved = true; }
            check(unapproved, "The transmitter refuses a push delivery URL outside the receiver's exact configured allow-list");
            await ssf.DeleteStreamAsync(push.GetProperty("stream_id").GetString()!, pushToken, ct);
        }
        finally { File.Delete(path); File.Delete(path + ".pending"); }
    }
}
