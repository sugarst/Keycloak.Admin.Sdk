using System.Net.Http.Headers;
using System.Text;

namespace Keycloak.Admin.Sdk.Protocols;

/// <summary>Per-request authentication. Assertion generation, signing keys and mTLS handlers belong to the host.
/// Secrets and assertions are never cached across users or logged.</summary>
public sealed class OAuthClientAuthentication
{
    public string ClientId { get; }
    private readonly Func<CancellationToken, ValueTask<string>>? credential;
    private readonly string method;
    private readonly string assertionType;
    private readonly Func<Uri, CancellationToken, ValueTask<OAuthClientAttestation>>? attestation;
    internal string[] RequiredFeatures { get; }

    private OAuthClientAuthentication(string clientId, string method, Func<CancellationToken, ValueTask<string>>? credential,
        string[]? requiredFeatures = null, string assertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", Func<Uri, CancellationToken, ValueTask<OAuthClientAttestation>>? attestation = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);
        ClientId = clientId; this.method = method; this.credential = credential;
        this.assertionType = assertionType; RequiredFeatures = requiredFeatures ?? []; this.attestation = attestation;
    }

    public static OAuthClientAuthentication Public(string clientId) => new(clientId, "none", null);
    public static OAuthClientAuthentication SecretBasic(string clientId, Func<CancellationToken, ValueTask<string>> secret)
        => new(clientId, "basic", secret ?? throw new ArgumentNullException(nameof(secret)));
    public static OAuthClientAuthentication SecretPost(string clientId, Func<CancellationToken, ValueTask<string>> secret)
        => new(clientId, "post", secret ?? throw new ArgumentNullException(nameof(secret)));
    public static OAuthClientAuthentication JwtAssertion(string clientId, Func<CancellationToken, ValueTask<string>> assertion)
        => new(clientId, "assertion", assertion ?? throw new ArgumentNullException(nameof(assertion)));
    /// <summary>RFC 8705 authentication. The host configures the dedicated HttpClient's authenticated TLS client certificate.</summary>
    public static OAuthClientAuthentication MutualTls(string clientId)
        => new(clientId, "none", null, ["KeycloakSdk.Protocols.MutualTls"]);
    /// <summary>A federated JWT from a trusted workload credential source, distinct from a self-signed client assertion.</summary>
    public static OAuthClientAuthentication FederatedAssertion(string clientId, Func<CancellationToken, ValueTask<string>> assertion)
        => new(clientId, "assertion", assertion ?? throw new ArgumentNullException(nameof(assertion)), ["KeycloakSdk.Protocols.FederatedClientAuth"]);
    /// <summary>SPIFFE JWT-SVID with Keycloak's distinct assertion type. The configured server verifies trust domain and subject mapping.</summary>
    public static OAuthClientAuthentication SpiffeAssertion(string clientId, Func<CancellationToken, ValueTask<string>> assertion)
        => new(clientId, "assertion", assertion ?? throw new ArgumentNullException(nameof(assertion)), ["KeycloakSdk.Protocols.SpiffeClientAuth"], "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe");
    /// <summary>Experimental attestation-based authentication. Generate a fresh PoP for every request; the server separately trusts the attester.</summary>
    public static OAuthClientAuthentication Attestation(string clientId, Func<Uri, CancellationToken, ValueTask<OAuthClientAttestation>> attestation)
        => new(clientId, "none", null, ["KeycloakSdk.Protocols.WalletAttestation"], attestation: attestation ?? throw new ArgumentNullException(nameof(attestation)));
    public static OAuthClientAuthentication ClientMetadata(CimdClientMetadata metadata, Func<CancellationToken, ValueTask<string>>? assertion = null)
    {
        ArgumentNullException.ThrowIfNull(metadata);
        bool confidential = metadata.AuthenticationMethod == "private_key_jwt";
        if (confidential != (assertion is not null)) throw new ArgumentException("Only private_key_jwt metadata requires a per-request assertion callback.", nameof(assertion));
        string[] features = metadata.AuthenticationMethod is "tls_client_auth" or "self_signed_tls_client_auth"
            ? ["KeycloakSdk.Protocols.OidcClientMetadata", "KeycloakSdk.Protocols.MutualTls"] : ["KeycloakSdk.Protocols.OidcClientMetadata"];
        return new(metadata.ClientId, confidential ? "assertion" : "none", assertion, features);
    }

    internal async ValueTask ApplyAsync(HttpRequestMessage request, Dictionary<string, string> form, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        form.Add("client_id", ClientId);
        if (attestation is not null)
        {
            var pair = await attestation(request.RequestUri!, ct).ConfigureAwait(false); ct.ThrowIfCancellationRequested();
            ArgumentNullException.ThrowIfNull(pair);
            request.Headers.Add("OAuth-Client-Attestation", pair.Attestation);
            request.Headers.Add("OAuth-Client-Attestation-PoP", pair.ProofOfPossession);
        }
        if (credential is null) return;
        string value = await credential(ct).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested();
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if (method == "basic")
        {
            static string Encode(string text) => Uri.EscapeDataString(text).Replace("%20", "+", StringComparison.Ordinal);
            request.Headers.Authorization = new AuthenticationHeaderValue("Basic",
                Convert.ToBase64String(Encoding.UTF8.GetBytes(Encode(ClientId) + ":" + Encode(value))));
        }
        else if (method == "post") form.Add("client_secret", value);
        else
        {
            form.Add("client_assertion_type", assertionType);
            form.Add("client_assertion", value);
        }
    }
}

/// <summary>Sensitive attestation and its fresh client PoP. Neither is included in ToString.</summary>
public sealed class OAuthClientAttestation
{
    public string Attestation { get; }
    public string ProofOfPossession { get; }
    public OAuthClientAttestation(string attestation, string proofOfPossession)
    {
        WalletJson.Credential(attestation); WalletJson.Credential(proofOfPossession);
        Attestation = attestation; ProofOfPossession = proofOfPossession;
    }
}
