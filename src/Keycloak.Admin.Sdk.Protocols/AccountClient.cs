using System.Text;
using System.Text.Json;

namespace Keycloak.Admin.Sdk.Protocols;

/// <summary>Self-service account calls authenticated by the current user's token, never an implicit admin credential.</summary>
public sealed class AccountClient(ProtocolTransport transport)
{
    private readonly ProtocolTransport transport = transport ?? throw new ArgumentNullException(nameof(transport));
    private const string Feature = "KeycloakSdk.Protocols.Account";
    public Task<ProtocolResponse> GetProfileAsync(string token, CancellationToken cancellationToken = default)
        => GetAsync("account/", "Account.Profile", token, cancellationToken);
    public Task<ProtocolResponse> GetProfileAsync(string token, IEnumerable<KeyValuePair<string, string>> query, CancellationToken cancellationToken = default)
        => GetAsync("account/", "Account.Profile", token, query, cancellationToken);
    public Task<ProtocolResponse> UpdateProfileAsync(string token, JsonElement body, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);
        return transport.SendAsync(HttpMethod.Post, "account/", "Account.UpdateProfile", Feature,
            new StringContent(body.GetRawText(), Encoding.UTF8, "application/json"), token, null, null, cancellationToken);
    }
    public Task<ProtocolResponse> GetSessionsAsync(string token, CancellationToken cancellationToken = default)
        => GetAsync("account/sessions", "Account.Sessions", token, cancellationToken);
    public Task<ProtocolResponse> GetApplicationsAsync(string token, CancellationToken cancellationToken = default)
        => GetAsync("account/applications", "Account.Applications", token, cancellationToken);
    public Task<ProtocolResponse> GetApplicationsAsync(string token, IEnumerable<KeyValuePair<string, string>> query, CancellationToken cancellationToken = default)
        => GetAsync("account/applications", "Account.Applications", token, query, cancellationToken);
    public Task<ProtocolResponse> GetCredentialsAsync(string token, CancellationToken cancellationToken = default)
        => GetAsync("account/credentials", "Account.Credentials", token, cancellationToken);
    public Task<ProtocolResponse> GetCredentialsAsync(string token, IEnumerable<KeyValuePair<string, string>> query, CancellationToken cancellationToken = default)
        => GetAsync("account/credentials", "Account.Credentials", token, query, cancellationToken);
    public Task<ProtocolResponse> GetLinkedAccountsAsync(string token, CancellationToken cancellationToken = default)
        => GetAsync("account/linked-accounts", "Account.LinkedAccounts", token, cancellationToken);
    public Task<ProtocolResponse> GetLinkedAccountsAsync(string token, IEnumerable<KeyValuePair<string, string>> query, CancellationToken cancellationToken = default)
        => GetAsync("account/linked-accounts", "Account.LinkedAccounts", token, query, cancellationToken);
    public Task<ProtocolResponse> GetOrganizationsAsync(string token, CancellationToken cancellationToken = default)
        => GetAsync("account/organizations", "Account.Organizations", token, cancellationToken);
    public Task<ProtocolResponse> GetGroupsAsync(string token, CancellationToken cancellationToken = default)
        => GetAsync("account/groups", "Account.Groups", token, cancellationToken);
    public Task<ProtocolResponse> GetDevicesAsync(string token, CancellationToken cancellationToken = default)
        => GetAsync("account/sessions/devices", "Account.Devices", token, cancellationToken);
    public Task<ProtocolResponse> GetSupportedLocalesAsync(string token, CancellationToken cancellationToken = default)
        => GetAsync("account/supportedLocales", "Account.Locales", token, cancellationToken);
    public Task<ProtocolResponse> GetConsentAsync(string clientId, string token, CancellationToken cancellationToken = default)
        => GetAsync("account/applications/" + ProtocolTransport.Segment(clientId) + "/consent", "Account.Consent", token, cancellationToken);
    public Task<ProtocolResponse> UpdateConsentAsync(string clientId, JsonElement consent, string token, CancellationToken cancellationToken = default)
        => SendAsync(HttpMethod.Put, "account/applications/" + ProtocolTransport.Segment(clientId) + "/consent", "Account.UpdateConsent", token,
            new StringContent(consent.GetRawText(), Encoding.UTF8, "application/json"), cancellationToken);
    public Task<ProtocolResponse> RevokeConsentAsync(string clientId, string token, CancellationToken cancellationToken = default)
        => SendAsync(HttpMethod.Delete, "account/applications/" + ProtocolTransport.Segment(clientId) + "/consent", "Account.RevokeConsent", token, null, cancellationToken);
    public Task<ProtocolResponse> RevokeApplicationSessionsAsync(string clientId, string token, CancellationToken cancellationToken = default)
        => SendAsync(HttpMethod.Delete, "account/applications/" + ProtocolTransport.Segment(clientId) + "/sessions", "Account.RevokeApplicationSessions", token, null, cancellationToken);
    public Task<ProtocolResponse> DeleteSessionAsync(string sessionId, string token, CancellationToken cancellationToken = default)
        => SendAsync(HttpMethod.Delete, "account/sessions/" + ProtocolTransport.Segment(sessionId), "Account.DeleteSession", token, null, cancellationToken);
    public Task<ProtocolResponse> DeleteSessionsAsync(bool includeCurrent, string token, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);
        return transport.SendAsync(HttpMethod.Delete, "account/sessions", "Account.DeleteSessions", Feature, null, token,
            [new("current", includeCurrent ? "true" : "false")], null, cancellationToken);
    }
    public Task<ProtocolResponse> UnlinkAccountAsync(string providerAlias, string token, CancellationToken cancellationToken = default)
        => SendAsync(HttpMethod.Delete, "account/linked-accounts/" + ProtocolTransport.Segment(providerAlias), "Account.Unlink", token, null, cancellationToken);
    public Task<ProtocolResponse> SetCredentialLabelAsync(string credentialId, string label, string token, CancellationToken cancellationToken = default)
        => SendAsync(HttpMethod.Put, "account/credentials/" + ProtocolTransport.Segment(credentialId) + "/label", "Account.CredentialLabel", token,
            new StringContent(System.Text.Json.Nodes.JsonValue.Create(label)!.ToJsonString(), Encoding.UTF8, "application/json"), cancellationToken);
    /// <summary>Deprecated upstream endpoint. Prefer application initiated actions for credential removal.</summary>
    public Task<ProtocolResponse> DeleteCredentialAsync(string credentialId, string token, CancellationToken cancellationToken = default)
        => SendAsync(HttpMethod.Delete, "account/credentials/" + ProtocolTransport.Segment(credentialId), "Account.DeleteCredential", token, null, cancellationToken);
    private Task<ProtocolResponse> SendAsync(HttpMethod method, string path, string operation, string token, HttpContent? body, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);
        return transport.SendAsync(method, path, operation, Feature, body, token, null, null, ct);
    }
    private Task<ProtocolResponse> GetAsync(string path, string operation, string token, CancellationToken ct)
        => GetAsync(path, operation, token, null, ct);
    private Task<ProtocolResponse> GetAsync(string path, string operation, string token, IEnumerable<KeyValuePair<string, string>>? query, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);
        return transport.SendAsync(HttpMethod.Get, path, operation, Feature, null, token, query, null, ct);
    }
}
