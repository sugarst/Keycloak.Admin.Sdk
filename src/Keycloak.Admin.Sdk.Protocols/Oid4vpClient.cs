using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Keycloak.Admin.Sdk.Protocols;

/// <summary>A verified presentation request from an explicitly trusted verifier certificate fingerprint.
/// The host must show the verifier and requested claims and obtain the user's consent before presenting a credential.</summary>
public sealed class Oid4vpRequest
{
    public string ClientId { get; }
    public string Nonce { get; }
    public string State { get; }
    public Uri ResponseUri { get; }
    public string ResponseMode { get; }
    public DateTimeOffset Expires { get; }
    public JsonElement DcqlQuery { get; }
    public JsonElement ClientMetadata { get; }
    internal string Endpoint { get; }
    internal int Consumed;
    internal Oid4vpRequest(JsonElement claims, string endpoint)
    {
        WalletJson.Object(claims); Endpoint = endpoint;
        ClientId = WalletJson.String(claims, "client_id"); Nonce = WalletJson.String(claims, "nonce"); State = WalletJson.String(claims, "state");
        ResponseUri = new(WalletJson.String(claims, "response_uri")); ResponseMode = WalletJson.String(claims, "response_mode");
        if (WalletJson.String(claims, "response_type") != "vp_token" || ResponseMode is not ("direct_post" or "direct_post.jwt")) throw new InvalidDataException("Unsupported presentation response contract.");
        Expires = DateTimeOffset.FromUnixTimeSeconds(claims.GetProperty("exp").GetInt64());
        DcqlQuery = claims.GetProperty("dcql_query").Clone(); WalletJson.Object(DcqlQuery);
        ClientMetadata = claims.GetProperty("client_metadata").Clone(); WalletJson.Object(ClientMetadata);
    }
}

/// <summary>Keycloak 26.8.1's x509_hash verifier profile, signed request_uri, DCQL and direct_post/direct_post.jwt.
/// Pin expectedVerifierClientId from independently trusted verifier configuration, never from the incoming wallet link.
/// Login completion remains bound to the original browser; a wallet response alone cannot authenticate a host session.</summary>
public sealed class Oid4vpClient
{
    private const string Feature = "KeycloakSdk.Protocols.WalletPresentation";
    private readonly ProtocolTransport transport;
    private readonly string endpoint, verifierId;
    private readonly TimeProvider clock;
    public Oid4vpClient(ProtocolTransport transport, string identityProviderAlias, string expectedVerifierClientId, TimeProvider? clock = null)
    {
        this.transport = transport ?? throw new ArgumentNullException(nameof(transport)); WalletJson.Text(expectedVerifierClientId);
        if (!expectedVerifierClientId.StartsWith("x509_hash:", StringComparison.Ordinal) || expectedVerifierClientId.Length != 53) throw new ArgumentException("An explicitly trusted x509_hash verifier client identifier is required.", nameof(expectedVerifierClientId));
        endpoint = "broker/" + ProtocolTransport.Segment(identityProviderAlias) + "/endpoint"; verifierId = expectedVerifierClientId; this.clock = clock ?? TimeProvider.System;
    }
    public async Task<Oid4vpRequest> GetRequestAsync(Uri requestUri, CancellationToken cancellationToken = default)
    {
        var (path, query) = RequestPath(requestUri);
        var response = await transport.SendAsync(HttpMethod.Get, path, "Wallet.PresentationRequest", Feature, null, null, query, null, cancellationToken, responseMediaType: "application/oauth-authz-req+jwt").ConfigureAwait(false);
        string compact = new UTF8Encoding(false, true).GetString(response.RawBody.Span); WalletJson.Credential(compact);
        var token = new JsonWebToken(compact);
        if (token.IsEncrypted || token.Alg != "ES256" || token.Typ != "oauth-authz-req+jwt" || !token.TryGetHeaderValue<JsonElement>("x5c", out var certificates)
            || certificates.ValueKind != JsonValueKind.Array || certificates.GetArrayLength() is < 1 or > 8)
            throw new InvalidDataException("A signed verifier request and its pinned certificate are required.");
        using var certificate = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(certificates[0].GetString()!));
        string id = "x509_hash:" + Base64UrlEncoder.Encode(SHA256.HashData(certificate.RawData));
        var now = clock.GetUtcNow();
        if (id != verifierId || certificate.NotBefore.ToUniversalTime() > now.UtcDateTime || certificate.NotAfter.ToUniversalTime() <= now.UtcDateTime)
            throw new InvalidDataException("Untrusted or expired verifier certificate.");
        using var verificationKey = certificate.GetECDsaPublicKey() ?? throw new InvalidDataException("An EC verifier certificate is required.");
        var result = await new JsonWebTokenHandler { MaximumTokenSizeInBytes = 65536, MapInboundClaims = false }.ValidateTokenAsync(compact, new TokenValidationParameters
        {
            RequireSignedTokens = true, ValidateIssuerSigningKey = true, IssuerSigningKey = new ECDsaSecurityKey(verificationKey), ValidAlgorithms = ["ES256"],
            ValidateIssuer = true, ValidIssuer = verifierId, ValidateAudience = true, ValidAudience = "https://self-issued.me/v2", IgnoreTrailingSlashWhenValidatingAudience = false,
            ValidateLifetime = true, RequireExpirationTime = true, ClockSkew = TimeSpan.FromSeconds(30), IncludeTokenOnFailedValidation = false, LogTokenId = false, LogValidationExceptions = false,
            // The certificate's public key is owned by this call; a cached verifier must not retain it after disposal.
            CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false }
        }).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (!result.IsValid) throw new InvalidDataException("Invalid verifier request signature or security claims.");
        using var payload = JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(token.EncodedPayload)); var claims = payload.RootElement; WalletJson.Object(claims);
        var request = new Oid4vpRequest(claims, transport.Target(endpoint).AbsoluteUri);
        string expectedResponse = transport.Target(endpoint).AbsoluteUri + (query.Length == 0 ? "" : "?" + ProtocolTransport.Query(query));
        if (request.ClientId != verifierId || request.ResponseUri.AbsoluteUri != expectedResponse
            || !claims.TryGetProperty("iat", out var iat) || iat.ValueKind != JsonValueKind.Number || !iat.TryGetInt64(out long issued)
            || issued > now.AddSeconds(30).ToUnixTimeSeconds() || request.Expires <= now || request.Expires.ToUnixTimeSeconds() - issued is <= 0 or > 1800)
            throw new InvalidDataException("Presentation request does not bind the expected client destination or bounded lifetime.");
        return request;
    }

    /// <summary>Posts only explicitly selected, verified disclosures. A failed attempt consumes the local request; restart rather than replay a presentation.</summary>
    public async Task<ProtocolResponse> PresentAsync(Oid4vpRequest request, VerifiedOid4vcCredential credential, IEnumerable<string> disclosures, Oid4vcProofKey holder,
        string credentialQueryId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request); ArgumentNullException.ThrowIfNull(credential); ArgumentNullException.ThrowIfNull(disclosures); ArgumentNullException.ThrowIfNull(holder);
        WalletJson.Text(credentialQueryId);
        await transport.EnsureEnabledAsync([Feature], cancellationToken).ConfigureAwait(false);
        if (request.Endpoint != transport.Target(endpoint).AbsoluteUri || request.ClientId != verifierId || request.Expires <= clock.GetUtcNow()
            || credential.Claims.GetProperty("exp").GetInt64() <= clock.GetUtcNow().ToUnixTimeSeconds()) throw new InvalidDataException("Presentation request or credential expired or belongs to another verifier.");
        string[] selected = disclosures.ToArray(); var presented = credential.SelectClaims(selected);
        Oid4vpDcql.Require(request.DcqlQuery, credentialQueryId, presented);
        var formats = request.ClientMetadata.GetProperty("vp_formats_supported").GetProperty("dc+sd-jwt");
        if (!formats.GetProperty("sd-jwt_alg_values").EnumerateArray().Any(v => v.GetString() == credential.SignatureAlgorithm)
            || !formats.GetProperty("kb-jwt_alg_values").EnumerateArray().Any(v => v.GetString() == holder.Algorithm)) throw new InvalidDataException("Verifier does not accept the credential or holder signature algorithm.");
        if (Interlocked.Exchange(ref request.Consumed, 1) != 0) throw new InvalidDataException("Presentation request already consumed.");
        string presentation = credential.CreateSdJwtPresentation(selected, request.ClientId, request.Nonce, holder);
        var vp = new JsonObject { [credentialQueryId] = new JsonArray((JsonNode)JsonValue.Create(presentation)!) };
        Dictionary<string, string> fields;
        if (request.ResponseMode == "direct_post.jwt")
        {
            var keys = request.ClientMetadata.GetProperty("jwks").GetProperty("keys");
            if (keys.GetArrayLength() != 1 || !request.ClientMetadata.GetProperty("encrypted_response_enc_values_supported").EnumerateArray().Any(v => v.GetString() == "A256GCM")) throw new InvalidDataException("A single supported ephemeral verifier encryption key is required.");
            fields = new() { ["response"] = WalletEcdhJwe.Encrypt(new JsonObject { ["vp_token"] = vp, ["state"] = request.State }.ToJsonString(), keys[0]) };
        }
        else fields = new() { ["vp_token"] = vp.ToJsonString(), ["state"] = request.State };
        var query = request.ResponseUri.Query.Length == 0 ? Array.Empty<KeyValuePair<string, string>>() : [new KeyValuePair<string, string>("flow", "cross_device")];
        return await transport.SendAsync(HttpMethod.Post, endpoint, "Wallet.Presentation", Feature, new FormUrlEncodedContent(fields), null, query, null, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Polling belongs to the original bound browser. Do not turn a remote wallet's completion into a new browser login.</summary>
    public Task<ProtocolResponse> GetStatusAsync(string state, CancellationToken cancellationToken = default)
    {
        WalletJson.Text(state);
        return transport.SendAsync(HttpMethod.Get, endpoint + "/status", "Wallet.PresentationStatus", Feature, null, null, [new("state", state)], null, cancellationToken);
    }
    private (string Path, KeyValuePair<string, string>[] Query) RequestPath(Uri uri)
    {
        ArgumentNullException.ThrowIfNull(uri);
        string prefix = transport.Target(endpoint + "/request-object/").AbsoluteUri;
        if (!uri.IsAbsoluteUri || !uri.AbsoluteUri.StartsWith(prefix, StringComparison.Ordinal) || uri.Fragment.Length != 0
            || (uri.Query.Length != 0 && uri.Query != "?flow=cross_device")) throw new ArgumentException("A request URI at the pinned verifier endpoint is required.", nameof(uri));
        string handle = Uri.UnescapeDataString(uri.GetLeftPart(UriPartial.Path)[prefix.Length..]); WalletJson.Text(handle);
        if (handle.Contains('/', StringComparison.Ordinal)) throw new ArgumentException("A single presentation request handle is required.", nameof(uri));
        return (endpoint + "/request-object/" + ProtocolTransport.Segment(handle), uri.Query.Length == 0 ? [] : [new("flow", "cross_device")]);
    }
}
