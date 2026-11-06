using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Protocols;

internal static class FeatureSsfWorkflows
{
    internal static async Task RunAsync(KeycloakAdminClient wire, KeycloakAdminClient sdk, HttpClient http, Uri server, string realm, Action<string, int, string> proof, CancellationToken ct)
    {
        const string receiver = "feature-ssf", audience = "sdk-feature-ssf";
        const string revoked = "https://schemas.openid.net/secevent/caep/event-type/session-revoked";
        const string verification = "https://schemas.openid.net/secevent/ssf/event-type/verification";
        string secret = Guid.NewGuid().ToString("N") + "aA1!";
        HttpContent Body(JsonObject value) => new StringContent(value.ToJsonString(), Encoding.UTF8, "application/json");
        void Require(bool condition, string name) { if (!condition) throw new InvalidDataException("SSF Admin business verification failed: " + name); }
        void Proof(string name, AdminResponse response, string message) => proof("SsfAdmin." + name + "Async", (int)response.StatusCode, message);
        await wire.RealmAdmin.UpdateRealmAsync(realm, new() { Attributes = new() { ["ssf.transmitterEnabled"] = "true", ["frontendUrl"] = server.AbsoluteUri } }, ct);
        await wire.Clients.CreateClientAsync(realm, new() { ClientId = receiver, Enabled = true, Protocol = "openid-connect", PublicClient = false, Secret = secret, ServiceAccountsEnabled = true,
            DirectAccessGrantsEnabled = true, Attributes = new() { ["ssf.enabled"] = "true", ["ssf.supportedEvents"] = "CaepSessionRevoked", ["ssf.defaultSubjects"] = "NONE",
                ["ssf.streamAudience"] = audience, ["ssf.autoVerifyStream"] = "false", ["ssf.minVerificationInterval"] = "0" }, ProtocolMappers = [
                    new() { Name = "notification-state", Protocol = "openid-connect", ProtocolMapper = "oidc-usermodel-attribute-mapper", Config = new() {
                        ["user.attribute"] = "ssf.notify." + receiver, ["claim.name"] = "ssf_notification", ["jsonType.label"] = "String", ["access.token.claim"] = "true" } },
                    new() { Name = "own-audience", Protocol = "openid-connect", ProtocolMapper = "oidc-audience-mapper", Config = new() { ["included.client.audience"] = receiver, ["access.token.claim"] = "true" } }] }, cancellationToken: ct);
        var client = (await wire.Clients.GetClientsAsync(realm, clientId: receiver, cancellationToken: ct)).Body!.Single();
        foreach (string name in new[] { "ssf.read", "ssf.manage" })
        {
            if (!(await wire.ClientScopes.GetClientScopesAsync(realm, ct)).Body!.Any(s => s.Name == name))
                await wire.ClientScopes.CreateClientScopeAsync(realm, new() { Name = name, Protocol = "openid-connect", Attributes = new() { ["include.in.token.scope"] = "true" } }, ct);
            var scope = (await wire.ClientScopes.GetClientScopesAsync(realm, ct)).Body!.Single(s => s.Name == name);
            await wire.Client.AddDefaultClientScopeAsync(realm, client.Id!, scope.Id!, ct);
        }
        await wire.Users.CreateUserAsync(realm, new() { Username = "ssf-subject", FirstName = "SSF", LastName = "Subject", Email = "ssf-subject@example.invalid", EmailVerified = true, Enabled = true,
            Credentials = [new() { Type = "password", Value = secret, Temporary = false }] }, cancellationToken: ct);
        var user = (await wire.Users.GetUsersAsync(realm, username: "ssf-subject", exact: true, cancellationToken: ct)).Body!.Single();
        var transport = new ProtocolTransport(http, server, realm); var oidc = new OidcClient(transport); var ssf = new SsfClient(transport);
        var authentication = OAuthClientAuthentication.SecretBasic(receiver, _ => ValueTask.FromResult(secret));
        string token = (await oidc.ClientCredentialsAsync(authentication, "ssf.read ssf.manage", ct)).Json!.Value.GetProperty("access_token").GetString()!;
        async Task<JsonElement> Attributes()
        {
            var userToken = await oidc.PasswordGrantAsync(authentication, user.Username!, secret, cancellationToken: ct);
            var verified = await new KeycloakAccessTokenValidator(oidc, receiver).ValidateAsync(userToken.Json!.Value.GetProperty("access_token").GetString()!, ct);
            Require(verified.Subject == user.Id, "independent subject attribute mapping"); return verified.Claims;
        }
        var config = await sdk.SsfAdmin.GetConfigAsync(realm, ct);
        Require(config.Body.GetProperty("availableSupportedEvents").EnumerateArray().Any(e => e.GetString() == "CaepSessionRevoked"), "event registry discovery");
        Proof("GetConfig", config, "The fixed server advertises the native CAEP event alias and its actual receiver configuration defaults.");
        var created = await sdk.SsfAdmin.CreateClientStreamAsync(realm, receiver, Body(new() { ["description"] = "Admin-created", ["events_requested"] = new JsonArray(revoked),
            ["delivery"] = new JsonObject { ["method"] = "urn:ietf:rfc:8936" } }), ct);
        string streamId = created.Body.GetProperty("streamId").GetString()!;
        Require((await ssf.GetStreamAsync(streamId, token, ct)).Json!.Value.GetProperty("stream_id").GetString() == streamId, "independent receiver read of Admin-created stream");
        Proof("CreateClientStream", created, "Admin creation persists a receiver-owned poll stream independently readable through the SSF protocol API.");
        var updated = await sdk.SsfAdmin.UpdateClientStreamAsync(realm, receiver, Body(new() { ["description"] = "Admin-patched" }), ct);
        var read = await sdk.SsfAdmin.GetClientStreamAsync(realm, receiver, ct);
        Require(read.Body.GetProperty("description").GetString() == "Admin-patched" && read.Body.GetProperty("streamId").GetString() == streamId, "persisted stream patch");
        Proof("UpdateClientStream", updated, "A description-only PATCH persists without changing the stream identity or poll delivery configuration.");
        Proof("GetClientStream", read, "Admin reads the exact created and patched receiver stream independently confirmed by the SSF protocol API.");
        JsonObject Subject() => new() { ["type"] = "user-id", ["value"] = user.Id };
        var added = await sdk.SsfAdmin.AddSubjectAsync(realm, receiver, Body(Subject()), ct);
        var checkedSubject = await sdk.SsfAdmin.CheckSubjectAsync(realm, receiver, Body(Subject()), ct);
        Require(checkedSubject.Body.GetProperty("status").GetString() == "notified" && (await Attributes()).GetProperty("ssf_notification").GetString() == "true", "subject subscription persisted");
        Proof("AddSubject", added, "Adding a subject persists its receiver-specific notification attribute on the independently read user.");
        Proof("CheckSubject", checkedSubject, "Subject lookup resolves the exact user and reports the persisted receiver-specific notified state.");
        var ignored = await sdk.SsfAdmin.IgnoreSubjectAsync(realm, receiver, Body(Subject()), ct);
        Require((await Attributes()).GetProperty("ssf_notification").GetString() == "false", "subject exclusion persisted");
        Proof("IgnoreSubject", ignored, "Ignoring a subject persists an explicit exclusion on the actual user, distinct from removal.");
        var removed = await sdk.SsfAdmin.RemoveSubjectAsync(realm, receiver, Body(Subject()), ct);
        Require(!(await Attributes()).TryGetProperty("ssf_notification", out _), "subject removal persisted");
        Proof("RemoveSubject", removed, "Removal clears the persisted receiver-specific notification attribute without inventing an explicit exclusion.");
        await sdk.SsfAdmin.AddSubjectAsync(realm, receiver, Body(Subject()), ct);
        async Task<AdminResponse<JsonElement>> Emit()
            => await sdk.SsfAdmin.EmitEventAsync(realm, receiver, Body(new() { ["eventType"] = "CaepSessionRevoked", ["sub_id"] = new JsonObject { ["format"] = "complex",
                ["user"] = new JsonObject { ["format"] = "iss_sub", ["iss"] = transport.Issuer.AbsoluteUri, ["sub"] = user.Id }, ["session"] = new JsonObject { ["format"] = "opaque", ["id"] = "sdk-admin-event-session" } },
                ["event"] = new JsonObject { ["event_timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), ["initiating_entity"] = "admin" } }), ct);
        var emitted = await Emit(); string jti = emitted.Body.GetProperty("jti").GetString()!;
        var pending = await sdk.SsfAdmin.GetPendingEventAsync(realm, receiver, jti, ct);
        Require(pending.Body.GetProperty("jti").GetString() == jti && pending.Body.GetProperty("status").GetString() == "PENDING", "persisted synthetic event");
        Proof("GetPendingEvent", pending, "The emitted signed-event identifier resolves to the receiver-owned pending outbox record with the expected state.");
        var verified = await sdk.SsfAdmin.VerifyClientStreamAsync(realm, receiver, Body(new()), ct);
        var validation = new SecurityEventTokenValidator(oidc, audience, [revoked, verification], new InMemoryDpopReplayStore());
        bool actualEvent = false, actualVerification = false;
        for (int attempt = 0; attempt < 30 && (!actualEvent || !actualVerification); attempt++)
        {
            using var pollBody = JsonDocument.Parse("{\"maxEvents\":100}");
            var events = (await ssf.PollAsync(receiver, streamId, pollBody.RootElement, token, ct)).Json!.Value.GetProperty("sets");
            foreach (var entry in events.EnumerateObject())
            {
                // Pending poll rows intentionally remain unacknowledged for the administrative cleanup assertions.
                if ((entry.Name == jti && actualEvent) || (entry.Name != jti && actualVerification)) continue;
                var securityEvent = await validation.ValidateAsync(entry.Value.GetString()!, ct);
                actualEvent |= securityEvent.Id == jti && securityEvent.Events.TryGetProperty(revoked, out _);
                actualVerification |= securityEvent.Events.TryGetProperty(verification, out _);
            }
            if (!actualEvent || !actualVerification) await Task.Delay(250, ct);
        }
        Require(actualEvent && actualVerification, "signed receiver-visible synthetic and verification events");
        Proof("EmitEvent", emitted, "Admin synthetic emission persists a pending SET and independently delivers a signature issuer audience and event-type verified token to its receiver.");
        Proof("VerifyClientStream", verified, "Admin verification produces an actual signed verification SET delivered through the receiver poll protocol.");
        var clientStats = await sdk.SsfAdmin.GetClientEventStatsAsync(realm, receiver, ct); var realmStats = await sdk.SsfAdmin.GetEventStatsAsync(realm, ct);
        Require(clientStats.Body.GetProperty("statuses").GetProperty("PENDING").GetProperty("count").GetInt64() >= 2
            && realmStats.Body.GetProperty("statuses").GetProperty("PENDING").GetProperty("count").GetInt64() >= 2, "event counts reflect pending rows");
        Proof("GetClientEventStats", clientStats, "Receiver statistics count the actually persisted pending synthetic and verification events.");
        Proof("GetEventStats", realmStats, "Realm statistics include the independently observed pending receiver events.");
        var paused = await sdk.SsfAdmin.UpdateClientStreamStatusAsync(realm, receiver, Body(new() { ["status"] = "paused", ["reason"] = "SDK acceptance" }), ct);
        Require((await ssf.GetStatusAsync(streamId, token, ct)).Json!.Value.GetProperty("status").GetString() == "paused", "receiver observes paused status");
        Proof("UpdateClientStreamStatus", paused, "Admin pause persists and the independent SSF receiver immediately observes the paused status.");
        var clientQueued = await sdk.SsfAdmin.DeleteClientQueuedEventsAsync(realm, receiver, ct);
        Require(clientQueued.Body.GetProperty("deleted").GetInt32() >= 2, "client queued cleanup deleted actual rows");
        async Task Missing(string id)
        {
            try { await sdk.SsfAdmin.GetPendingEventAsync(realm, receiver, id, ct); throw new InvalidDataException("Deleted event still exists."); }
            catch (KeycloakAdminException e) when (e.StatusCode == HttpStatusCode.NotFound) { }
        }
        await Missing(jti); Proof("DeleteClientQueuedEvents", clientQueued, "Receiver queued cleanup removes the actual pending records; subsequent lookup of the known event returns 404.");
        await sdk.SsfAdmin.UpdateClientStreamStatusAsync(realm, receiver, Body(new() { ["status"] = "enabled" }), ct);
        string next = (await Emit()).Body.GetProperty("jti").GetString()!;
        var queued = await sdk.SsfAdmin.DeleteQueuedEventsAsync(realm, ct); Require(queued.Body.GetProperty("deleted").GetInt32() > 0, "realm queued cleanup"); await Missing(next);
        Proof("DeleteQueuedEvents", queued, "Realm queued cleanup removes a newly persisted receiver event, confirmed absent by its exact signed identifier.");
        next = (await Emit()).Body.GetProperty("jti").GetString()!;
        var clientDeleted = await sdk.SsfAdmin.DeleteClientEventsAsync(realm, receiver, status: "PENDING", cancellationToken: ct); Require(clientDeleted.Body.GetProperty("deleted").GetInt32() > 0, "client status-filtered cleanup"); await Missing(next);
        Proof("DeleteClientEvents", clientDeleted, "Receiver status-filtered deletion removes the actual pending event and a subsequent exact lookup returns 404.");
        next = (await Emit()).Body.GetProperty("jti").GetString()!;
        var deleted = await sdk.SsfAdmin.DeleteEventsAsync(realm, status: "PENDING", cancellationToken: ct); Require(deleted.Body.GetProperty("deleted").GetInt32() > 0, "realm status-filtered cleanup"); await Missing(next);
        Proof("DeleteEvents", deleted, "Realm status-filtered deletion removes the newly emitted pending record with independent absence verification.");
        string ordinaryToken = (await oidc.PasswordGrantAsync(authentication, user.Username!, secret, cancellationToken: ct)).Json!.Value.GetProperty("access_token").GetString()!;
        var ordinary = new KeycloakAdminClient(http, server, new StaticAccessTokenProvider(ordinaryToken));
        foreach (Func<Task> forbidden in new Func<Task>[] { () => ordinary.SsfAdmin.GetConfigAsync(realm, ct), () => ordinary.SsfAdmin.GetClientStreamAsync(realm, receiver, ct), () => ordinary.SsfAdmin.EmitEventAsync(realm, receiver, Body(new()), ct) })
        {
            try { await forbidden(); throw new InvalidDataException("Ordinary user unexpectedly accessed privileged SSF administration."); }
            catch (KeycloakAdminException e) when (e.StatusCode == HttpStatusCode.Forbidden) { }
        }
        var streamDeleted = await sdk.SsfAdmin.DeleteClientStreamAsync(realm, receiver, ct);
        try { await ssf.GetStreamAsync(streamId, token, ct); throw new InvalidDataException("Deleted stream still exists."); }
        catch (KeycloakProtocolException e) when (e.StatusCode == HttpStatusCode.NotFound) { }
        Proof("DeleteClientStream", streamDeleted, "Admin deletion removes the receiver-visible stream; ordinary users cannot read its configuration stream or emit privileged events.");
    }
}
