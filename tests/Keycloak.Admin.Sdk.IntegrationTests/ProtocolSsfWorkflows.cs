using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Protocols;

internal static class ProtocolSsfWorkflows
{
    private const string Verification = "https://schemas.openid.net/secevent/ssf/event-type/verification";
    private const string Revoked = "https://schemas.openid.net/secevent/caep/event-type/session-revoked";
    private const string Credential = "https://schemas.openid.net/secevent/caep/event-type/credential-change";
    private const string Disabled = "https://schemas.openid.net/secevent/risc/event-type/account-disabled";
    private const string Enabled = "https://schemas.openid.net/secevent/risc/event-type/account-enabled";
    private const string Purged = "https://schemas.openid.net/secevent/risc/event-type/account-purged";
    internal static async Task RunAsync(KeycloakAdminClient admin, ProtocolTransport transport, string realm, string secret, string unrelatedToken, Action<bool, string> check, CancellationToken ct)
    {
        JsonElement Element(JsonNode value) { using var document = JsonDocument.Parse(value.ToJsonString()); return document.RootElement.Clone(); }
        var config = (await admin.RealmAdmin.GetRealmAsync(realm, cancellationToken: ct)).Body!; config.Attributes ??= []; config.Attributes["ssf.transmitterEnabled"] = "true";
        // Async event delivery has no incoming request from which to derive the public issuer.
        config.Attributes["frontendUrl"] = transport.Issuer.AbsoluteUri[..transport.Issuer.AbsoluteUri.LastIndexOf("/realms/", StringComparison.Ordinal)] + "/";
        config.AdminEventsEnabled = true; config.AdminEventsDetailsEnabled = true;
        await admin.RealmAdmin.UpdateRealmAsync(realm, config, ct);
        await admin.Clients.CreateClientAsync(realm, new ClientRepresentation { ClientId = "ssf-receiver", Protocol = "openid-connect", PublicClient = false, Enabled = true, Secret = secret, ServiceAccountsEnabled = true,
            Attributes = new() { ["ssf.enabled"] = "true", ["ssf.profile"] = "SSF_1_0", ["ssf.autoVerifyStream"] = "false", ["ssf.streamAudience"] = "sdk-ssf-receiver",
                ["ssf.supportedEvents"] = "CaepSessionRevoked,CaepCredentialChange,RiscAccountDisabled,RiscAccountEnabled,RiscAccountPurged", ["ssf.defaultSubjects"] = "ALL", ["ssf.minVerificationInterval"] = "0" } }, cancellationToken: ct);
        var client = (await admin.Clients.GetClientsAsync(realm, clientId: "ssf-receiver", cancellationToken: ct)).Body!.Single();
        foreach (string scope in new[] { "ssf.read", "ssf.manage" })
        {
            if (!(await admin.ClientScopes.GetClientScopesAsync(realm, ct)).Body!.Any(s => s.Name == scope))
                await admin.ClientScopes.CreateClientScopeAsync(realm, new ClientScopeRepresentation { Name = scope, Protocol = "openid-connect", Attributes = new() { ["include.in.token.scope"] = "true" } }, ct);
            var created = (await admin.ClientScopes.GetClientScopesAsync(realm, ct)).Body!.Single(s => s.Name == scope);
            await admin.Client.AddDefaultClientScopeAsync(realm, client.Id!, created.Id!, ct);
        }
        var oidc = new OidcClient(transport); var auth = OAuthClientAuthentication.SecretBasic("ssf-receiver", _ => ValueTask.FromResult(secret));
        string token = (await oidc.ClientCredentialsAsync(auth, "ssf.read ssf.manage", ct)).Json!.Value.GetProperty("access_token").GetString()!;
        var ssf = new SsfClient(transport); var metadata = (await ssf.DiscoverAsync(ct)).Json!.Value;
        check(metadata.GetProperty("issuer").GetString() == oidc.Issuer.AbsoluteUri && metadata.GetProperty("configuration_endpoint").GetString() == oidc.Issuer.AbsoluteUri + "/ssf/transmitter/streams",
            "SSF discovery binds the transmitter issuer and stream endpoint to the pinned realm");
        var input = new JsonObject { ["description"] = "Before", ["events_requested"] = new JsonArray(Revoked, Credential, Disabled, Enabled, Purged), ["delivery"] = new JsonObject { ["method"] = "urn:ietf:rfc:8936" } };
        var stream = (await ssf.CreateStreamAsync(Element(input), token, ct)).Json!.Value; string streamId = stream.GetProperty("stream_id").GetString()!;
        check((await ssf.GetStreamAsync(streamId, token, ct)).Json!.Value.GetProperty("description").GetString() == "Before"
            && stream.GetProperty("aud").EnumerateArray().Any(a => a.GetString() == "sdk-ssf-receiver") && stream.GetProperty("delivery").GetProperty("endpoint_url").GetString()!.EndsWith("/receivers/ssf-receiver/streams/" + streamId + "/poll", StringComparison.Ordinal),
            "SSF receiver stream creation persists with transmitter-assigned identity audience and poll endpoint");
        await ssf.UpdateStreamAsync(Element(new JsonObject { ["stream_id"] = streamId, ["description"] = "Patched" }), token, ct);
        var patched = (await ssf.GetStreamAsync(streamId, token, ct)).Json!.Value;
        check(patched.GetProperty("description").GetString() == "Patched" && patched.GetProperty("delivery").GetProperty("method").GetString() == "urn:ietf:rfc:8936", "SSF PATCH preserves unspecified stream delivery configuration");
        input["stream_id"] = streamId; input["description"] = "Replaced";
        await ssf.ReplaceStreamAsync(Element(input), token, ct);
        check((await ssf.GetStreamsAsync(token, ct)).Json!.Value.EnumerateArray().Single().GetProperty("description").GetString() == "Replaced", "SSF PUT reconciles the receiver stream and collection read reflects the persisted replacement");
        bool wrongOwner = false, unrelated = false, immutable = false;
        try { await ssf.PollAsync("another-client", streamId, Element(new JsonObject()), token, ct); }
        catch (KeycloakProtocolException e) when (e.StatusCode == HttpStatusCode.NotFound) { wrongOwner = true; }
        try { await ssf.GetStreamAsync(streamId, unrelatedToken, ct); }
        catch (KeycloakProtocolException e) when (e.StatusCode == HttpStatusCode.Unauthorized) { unrelated = true; }
        try { await ssf.UpdateStreamAsync(Element(new JsonObject { ["stream_id"] = streamId, ["iss"] = "https://attacker.invalid" }), token, ct); }
        catch (KeycloakProtocolException e) when (e.StatusCode == HttpStatusCode.BadRequest) { immutable = true; }
        check(wrongOwner && unrelated && immutable && (await ssf.GetStreamAsync(streamId, token, ct)).Json!.Value.GetProperty("iss").GetString() == oidc.Issuer.AbsoluteUri,
            "SSF refuses cross-client polling unauthorized receivers and mutations to transmitter-owned identity");
        await ssf.VerifyAsync(Element(new JsonObject { ["stream_id"] = streamId, ["state"] = "sdk-verification" }), token, ct);
        JsonElement sets = default;
        for (int attempt = 0; attempt < 20; attempt++)
        {
            sets = (await ssf.PollAsync("ssf-receiver", streamId, Element(new JsonObject { ["maxEvents"] = 100 }), token, ct)).Json!.Value.GetProperty("sets");
            if (sets.EnumerateObject().Any()) break;
            await Task.Delay(TimeSpan.FromMilliseconds(250), ct);
        }
        var types = stream.GetProperty("events_delivered").EnumerateArray().Select(e => e.GetString()!).Append(Verification).Distinct().ToArray();
        var validator = new SecurityEventTokenValidator(oidc, "sdk-ssf-receiver", types, new InMemoryDpopReplayStore());
        bool verified = false, replayDenied = false; var acknowledgements = new JsonArray();
        foreach (var entry in sets.EnumerateObject())
        {
            string signed = entry.Value.GetString()!; var securityEvent = await validator.ValidateAsync(signed, ct);
            check(securityEvent.Id == entry.Name, "SSF polled SET identifier agrees with its independently verified signed jti");
            if (securityEvent.Events.TryGetProperty(Verification, out var verification)) verified |= verification.GetProperty("state").GetString() == "sdk-verification";
            try { await validator.ValidateAsync(signed, ct); }
            catch (InvalidDataException) { replayDenied = true; }
            acknowledgements.Add((JsonNode)entry.Name);
        }
        check(verified && replayDenied, "SSF poll delivers a signature issuer audience and state-verified SET whose replay is rejected");
        var afterAck = (await ssf.PollAsync("ssf-receiver", streamId, Element(new JsonObject { ["ack"] = acknowledgements }), token, ct)).Json!.Value;
        check(!afterAck.GetProperty("sets").EnumerateObject().Any(), "SSF acknowledges processed SETs and does not redeliver acknowledged verification events");
        await ProtocolSsfBusinessWorkflows.RunAsync(admin, transport, realm, secret, ssf, streamId, token, types, check, ct);
        await ssf.UpdateStatusAsync(Element(new JsonObject { ["stream_id"] = streamId, ["status"] = "paused", ["reason"] = "SDK validation" }), token, ct);
        check((await ssf.GetStatusAsync(streamId, token, ct)).Json!.Value.GetProperty("status").GetString() == "paused", "SSF status updates persist and can pause delivery");
        await ssf.DeleteStreamAsync(streamId, token, ct);
        check(!(await ssf.GetStreamsAsync(token, ct)).Json!.Value.EnumerateArray().Any(), "SSF stream deletion removes the receiver-owned stream");
    }
}
