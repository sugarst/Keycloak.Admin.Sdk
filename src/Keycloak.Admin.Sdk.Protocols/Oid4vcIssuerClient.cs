using System.Collections.Frozen;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Keycloak.Admin.Sdk.Protocols;

/// <summary>Issuer metadata fetched from the pinned Keycloak realm. Advertised endpoints never redirect SDK credentials.</summary>
public sealed class Oid4vcIssuerMetadata
{
    public Uri Issuer { get; }
    public JsonElement Document { get; }
    public IReadOnlyDictionary<string, Oid4vcCredentialConfiguration> Configurations { get; }
    internal Oid4vcIssuerMetadata(Uri issuer, JsonElement document)
    {
        WalletJson.Object(document); Issuer = issuer;
        if (WalletJson.String(document, "credential_issuer") != issuer.AbsoluteUri
            || WalletJson.String(document, "credential_endpoint") != issuer.AbsoluteUri + "/protocol/oid4vc/credential"
            || WalletJson.String(document, "nonce_endpoint") != issuer.AbsoluteUri + "/protocol/oid4vc/nonce")
            throw new InvalidDataException("Credential metadata must describe the pinned realm endpoints.");
        var servers = document.GetProperty("authorization_servers");
        if (servers.ValueKind != JsonValueKind.Array || servers.GetArrayLength() != 1 || servers[0].GetString() != issuer.AbsoluteUri)
            throw new InvalidDataException("Credential metadata must use the pinned authorization server.");
        var configurations = document.GetProperty("credential_configurations_supported"); WalletJson.Object(configurations);
        Configurations = configurations.EnumerateObject().ToFrozenDictionary(p => p.Name,
            p => new Oid4vcCredentialConfiguration(issuer, p.Name, p.Value), StringComparer.Ordinal);
        Document = document.Clone();
    }
}

/// <summary>An exact configuration from issuer metadata, including the independently gated mdoc format.</summary>
public sealed class Oid4vcCredentialConfiguration
{
    internal Uri Issuer { get; }
    public string Id { get; }
    public string Format { get; }
    public JsonElement Document { get; }
    internal Oid4vcCredentialConfiguration(Uri issuer, string id, JsonElement document)
    {
        WalletJson.Text(id); WalletJson.Object(document); Issuer = issuer; Id = id;
        Format = WalletJson.String(document, "format");
        if (Format is not ("jwt_vc_json" or "dc+sd-jwt" or "mso_mdoc")) throw new InvalidDataException("Unsupported Keycloak credential format.");
        Document = document.Clone();
    }
}

public enum Oid4vcOfferResponseType { Uri, UriWithQr, Qr }

/// <summary>OID4VCI wallet requests. Offers, proofs, access tokens and issued credentials are sensitive.
/// Issuance responses are unverified credentials; use a trusted credential verifier before relying on their claims.</summary>
public sealed class Oid4vcIssuerClient(ProtocolTransport transport)
{
    private readonly ProtocolTransport transport = transport ?? throw new ArgumentNullException(nameof(transport));
    internal const string Feature = "KeycloakSdk.Protocols.Wallet";
    private const string Path = "protocol/oid4vc/";
    public Uri Issuer => transport.Issuer;

    public async Task<Oid4vcIssuerMetadata> GetIssuerMetadataAsync(CancellationToken cancellationToken = default)
    {
        var response = await MetadataAsync(false, cancellationToken).ConfigureAwait(false);
        return new(Issuer, response.Json ?? throw new InvalidDataException("Empty credential metadata."));
    }
    /// <summary>Signed metadata remains unverified until its signature, issuer and lifetime are checked against independently trusted keys.</summary>
    public Task<ProtocolResponse> GetSignedIssuerMetadataAsync(CancellationToken cancellationToken = default) => MetadataAsync(true, cancellationToken);
    private Task<ProtocolResponse> MetadataAsync(bool signed, CancellationToken ct)
        => transport.SendServerAsync(HttpMethod.Get, ".well-known/openid-credential-issuer/realms/" + transport.RealmSegment,
            "Wallet.Metadata", Feature, null, null, null, ct, signed ? "application/jwt" : null);

    public Task<ProtocolResponse> GetJwtIssuerMetadataAsync(CancellationToken cancellationToken = default)
        => transport.SendServerAsync(HttpMethod.Get, ".well-known/jwt-vc-issuer/realms/" + transport.RealmSegment,
            "Wallet.JwtIssuerMetadata", Feature, null, null, null, cancellationToken);
    public Task<ProtocolResponse> RequestNonceAsync(CancellationToken cancellationToken = default)
        => transport.SendAsync(HttpMethod.Post, Path + "nonce", "Wallet.Nonce", Feature, null, null, null, null, cancellationToken);

    /// <summary>Only retrieves an offer from this exact issuer and endpoint. Arbitrary wallet URLs cannot receive a token or trigger SSRF.</summary>
    public Task<ProtocolResponse> GetOfferAsync(Uri offerUri, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(offerUri);
        string prefix = Issuer.AbsoluteUri + "/" + Path + "credential-offer/";
        if (!offerUri.IsAbsoluteUri || !offerUri.AbsoluteUri.StartsWith(prefix, StringComparison.Ordinal) || offerUri.Query.Length != 0
            || offerUri.Fragment.Length != 0) throw new ArgumentException("An offer URI at the pinned issuer is required.", nameof(offerUri));
        string handle = Uri.UnescapeDataString(offerUri.AbsoluteUri[prefix.Length..]); WalletJson.Text(handle);
        if (handle.Contains('/', StringComparison.Ordinal)) throw new ArgumentException("A single offer handle is required.", nameof(offerUri));
        return transport.SendAsync(HttpMethod.Get, Path + "credential-offer/" + ProtocolTransport.Segment(handle), "Wallet.Offer", Feature, null, null, null, null, cancellationToken);
    }

    /// <summary>Experimental REST offer creation. Deliver any tx_code separately from the offer; do not log either value.</summary>
    public Task<ProtocolResponse> CreateOfferAsync(string configurationId, string accessToken, bool preAuthorized = false, string? targetUser = null,
        DateTimeOffset? expires = null, Oid4vcOfferResponseType responseType = Oid4vcOfferResponseType.Uri, int width = 200, int height = 200,
        CancellationToken cancellationToken = default)
    {
        WalletJson.Text(configurationId); ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);
        string type = responseType switch { Oid4vcOfferResponseType.Uri => "uri", Oid4vcOfferResponseType.UriWithQr => "uri_qr", Oid4vcOfferResponseType.Qr => "qr", _ => throw new ArgumentOutOfRangeException(nameof(responseType)) };
        if (width is < 1 or > 800 || height is < 1 or > 800) throw new ArgumentOutOfRangeException(nameof(width));
        var query = new List<KeyValuePair<string, string>> { new("credential_configuration_id", configurationId), new("pre_authorized", preAuthorized ? "true" : "false"),
            new("type", type), new("width", width.ToString(CultureInfo.InvariantCulture)), new("height", height.ToString(CultureInfo.InvariantCulture)) };
        if (targetUser is not null) { WalletJson.Text(targetUser); query.Add(new("target_user", targetUser)); }
        if (expires is not null) query.Add(new("expire", expires.Value.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture)));
        return transport.SendAsync(HttpMethod.Get, Path + "create-credential-offer", "Wallet.CreateOffer", Feature, null, accessToken, query, null, cancellationToken,
            preAuthorized ? ["KeycloakSdk.Protocols.WalletOffers", "KeycloakSdk.Protocols.WalletPreAuthorized"] : ["KeycloakSdk.Protocols.WalletOffers"], responseType == Oid4vcOfferResponseType.Qr ? "image/png" : null);
    }

    /// <summary>Requests one or a batch of credentials. The configuration pins the format and its stage gates.
    /// Supply credential_identifier from the token authorization_details when present; otherwise the configuration ID is used.</summary>
    public Task<ProtocolResponse> RequestCredentialAsync(Oid4vcCredentialConfiguration configuration, string accessToken, IReadOnlyList<string>? jwtProofs = null,
        string? credentialIdentifier = null, JsonElement? attestationProofs = null, Oid4vcCredentialEncryption? encryption = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(configuration); ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);
        if (configuration.Issuer != Issuer) throw new ArgumentException("Credential configuration belongs to another issuer.", nameof(configuration));
        var body = new JsonObject();
        if (credentialIdentifier is not null) { WalletJson.Text(credentialIdentifier); body["credential_identifier"] = credentialIdentifier; }
        else body["credential_configuration_id"] = configuration.Id;
        if (jwtProofs is not null && attestationProofs is not null) throw new ArgumentException("Choose one proof type.");
        if (jwtProofs is not null)
        {
            if (jwtProofs.Count is < 1 or > 100) throw new ArgumentException("A bounded nonempty proof batch is required.", nameof(jwtProofs));
            var proofs = new JsonArray(); foreach (string proof in jwtProofs) { WalletJson.Credential(proof); proofs.Add((JsonNode)JsonValue.Create(proof)!); }
            body["proofs"] = new JsonObject { ["jwt"] = proofs };
        }
        if (attestationProofs is not null)
        {
            var values = attestationProofs.Value;
            if (values.ValueKind != JsonValueKind.Array || values.GetArrayLength() is < 1 or > 100) throw new ArgumentException("A bounded nonempty key-attestation array is required.", nameof(attestationProofs));
            foreach (var value in values.EnumerateArray()) WalletJson.Credential(value.GetString()!);
            body["proofs"] = new JsonObject { ["attestation"] = JsonNode.Parse(values.GetRawText()) };
        }
        string payload = encryption?.CreateRequest(body) ?? body.ToJsonString();
        return transport.SendAsync(HttpMethod.Post, Path + "credential", "Wallet.Credential", Feature,
            new StringContent(payload, Encoding.UTF8, encryption is not null ? "application/jwt" : "application/json"), accessToken, null, null, cancellationToken,
            configuration.Format == "mso_mdoc" ? ["KeycloakSdk.Protocols.WalletMdoc"] : [], encryption?.EncryptsResponse == true ? "application/jwt" : null);
    }
}

internal static class WalletJson
{
    internal static void Object(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.Object || value.EnumerateObject().GroupBy(p => p.Name, StringComparer.Ordinal).Any(g => g.Count() != 1))
            throw new InvalidDataException("A JSON object without duplicate properties is required.");
    }
    internal static string String(JsonElement value, string name)
    {
        if (!value.TryGetProperty(name, out var item) || item.ValueKind != JsonValueKind.String) throw new InvalidDataException("A required protocol string is missing.");
        string text = item.GetString()!; Text(text); return text;
    }
    internal static void Text(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 2048 || value.Any(char.IsControl)) throw new ArgumentException("A bounded protocol value without control characters is required.", nameof(value));
    }
    internal static void Credential(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 65536 || value.Any(c => c is < '!' or > '~')) throw new ArgumentException("A bounded compact credential is required.", nameof(value));
    }
}
