using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Protocols;

internal static class ProtocolRegistrationWorkflows
{
    internal static async Task RunAsync(KeycloakAdminClient admin, ProtocolTransport transport, string realm, Action<bool, string> check, CancellationToken ct)
    {
        JsonElement Element(JsonNode value) { using var doc = JsonDocument.Parse(value.ToJsonString()); return doc.RootElement.Clone(); }
        async Task<string> InitialToken()
        { var reply = await admin.ClientInitialAccess.CreateAsync(realm, new() { Count = 1, Expiration = 120 }, ct); using var doc = JsonDocument.Parse(reply.Content); return doc.RootElement.GetProperty("token").GetString()!; }
        foreach (bool oidc in new[] { true, false })
        {
            var client = oidc ? RealmResourceClient.ClientRegistration(transport) : RealmResourceClient.DefaultClientRegistration(transport);
            var body = oidc ? new JsonObject { ["client_name"] = "registration-before", ["redirect_uris"] = new JsonArray("https://app.invalid/callback") }
                : new JsonObject { ["clientId"] = "default-registration-app", ["name"] = "registration-before", ["publicClient"] = true, ["redirectUris"] = new JsonArray("https://app.invalid/callback") };
            var created = (await client.CreateAsync(Element(body), await InitialToken(), ct)).Json!.Value;
            string idProperty = oidc ? "client_id" : "clientId", ratProperty = oidc ? "registration_access_token" : "registrationAccessToken";
            string id = created.GetProperty(idProperty).GetString()!, token = created.GetProperty(ratProperty).GetString()!;
            var read = (await client.GetAsync(id, token, ct)).Json!.Value;
            if (read.TryGetProperty(ratProperty, out var rotated)) token = rotated.GetString()!;
            body[oidc ? "client_id" : "clientId"] = id; body[oidc ? "client_name" : "name"] = "registration-after";
            var updated = (await client.ReplaceAsync(id, Element(body), token, ct)).Json!.Value;
            if (updated.TryGetProperty(ratProperty, out rotated)) token = rotated.GetString()!;
            var persisted = (await client.GetAsync(id, token, ct)).Json!.Value;
            if (persisted.TryGetProperty(ratProperty, out rotated)) token = rotated.GetString()!;
            check(persisted.GetProperty(oidc ? "client_name" : "name").GetString() == "registration-after"
                && (await admin.Clients.GetClientsAsync(realm, clientId: id, cancellationToken: ct)).Body!.Single().Name == "registration-after",
                oidc ? "OIDC registration read update and rotated registration-token lifecycle persist" : "Default compatibility registration read update and registration-token lifecycle persist");
            if (!oidc)
                check((await new ClientRegistrationClient(transport).GetInstallationAsync(id, token, ct)).Json!.Value.GetProperty("resource").GetString() == id,
                    "Adapter installation compatibility provider returns the registered client's configuration");
            bool denied = false;
            try { await client.DeleteAsync(id, "not-a-registration-token", ct); }
            catch (KeycloakProtocolException e) when (e.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden) { denied = true; }
            check(denied && (await admin.Clients.GetClientsAsync(realm, clientId: id, cancellationToken: ct)).Body!.Count == 1,
                oidc ? "OIDC registration refuses an unrelated token without deleting the client" : "Default registration refuses an unrelated token without deleting the client");
            await client.DeleteAsync(id, token, ct);
            check((await admin.Clients.GetClientsAsync(realm, clientId: id, cancellationToken: ct)).Body!.Count == 0,
                oidc ? "OIDC registration lifecycle cleanup removes the updated client" : "Default registration lifecycle cleanup removes the updated client");
        }
        var registration = new ClientRegistrationClient(transport);
        const string descriptor = """<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="urn:sdk:registered-saml-sp"><SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://app.invalid/saml/acs" index="0"/></SPSSODescriptor></EntityDescriptor>""";
        var saml = (await registration.RegisterSamlDescriptorAsync(descriptor, await InitialToken(), ct)).Json!.Value;
        string samlId = saml.GetProperty("clientId").GetString()!, samlToken = saml.GetProperty("registrationAccessToken").GetString()!;
        var stored = (await admin.Clients.GetClientsAsync(realm, clientId: samlId, cancellationToken: ct)).Body!.Single();
        check(samlId == "urn:sdk:registered-saml-sp" && stored.Protocol == "saml" && stored.RedirectUris!.Contains("https://app.invalid/saml/acs"),
            "SAML descriptor compatibility registration stores the declared SP and assertion-consumer endpoint");
        await RealmResourceClient.DefaultClientRegistration(transport).DeleteAsync(samlId, samlToken, ct);
        check((await admin.Clients.GetClientsAsync(realm, clientId: samlId, cancellationToken: ct)).Body!.Count == 0,
            "SAML descriptor registration credentials authorize only its own client cleanup");
    }
}
