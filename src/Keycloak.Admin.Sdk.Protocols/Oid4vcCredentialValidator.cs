using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Keycloak.Admin.Sdk.Protocols;

/// <summary>Verified issuer claims and holder binding. This is a credential, not a browser login or an authorization decision.</summary>
public sealed class VerifiedOid4vcCredential
{
    public JsonElement Claims { get; }
    public string Format { get; }
    public string SignatureAlgorithm { get; }
    public string? HolderThumbprint { get; }
    public IReadOnlyList<string> Disclosures { get; }
    private readonly string signedJwt;
    private readonly JsonElement signedClaims;
    internal VerifiedOid4vcCredential(string jwt, JsonElement signedClaims, JsonElement claims, string format, string? holder, string[] disclosures)
    {
        signedJwt = jwt; SignatureAlgorithm = new JsonWebToken(jwt).Alg; this.signedClaims = signedClaims.Clone(); Claims = claims.Clone(); Format = format; HolderThumbprint = holder;
        Disclosures = Array.AsReadOnly(disclosures);
    }
    /// <summary>Explicitly select the disclosures the verifier requested. No claims are silently disclosed.
    /// audience and nonce must come from a verified presentation request; the host binds it to the user's consent.</summary>
    public string CreateSdJwtPresentation(IEnumerable<string> disclosures, string audience, string nonce, Oid4vcProofKey holder)
    {
        ArgumentNullException.ThrowIfNull(disclosures); ArgumentNullException.ThrowIfNull(holder); WalletJson.Text(audience); WalletJson.Text(nonce);
        if (Format != "dc+sd-jwt" || HolderThumbprint != holder.Thumbprint) throw new InvalidDataException("The presentation must use this SD-JWT credential's holder key.");
        var selected = disclosures.ToArray();
        if (selected.Any(d => !Disclosures.Contains(d, StringComparer.Ordinal))) throw new InvalidDataException("A disclosure does not belong to this credential.");
        SdJwtDisclosures.Resolve(signedClaims, selected);
        string compact = signedJwt + "~" + (selected.Length == 0 ? "" : string.Join('~', selected) + "~");
        string algorithm = signedClaims.TryGetProperty("_sd_alg", out var alg) ? alg.GetString()! : "sha-256";
        return compact + holder.CreatePresentationProof(audience, nonce, SdJwtDisclosures.Hash(algorithm, compact));
    }
    internal JsonElement SelectClaims(IReadOnlyList<string> selected)
    {
        if (Format != "dc+sd-jwt" || selected.Any(d => !Disclosures.Contains(d, StringComparer.Ordinal))) throw new InvalidDataException("Selected SD-JWT disclosures must belong to this credential.");
        return SdJwtDisclosures.Resolve(signedClaims, selected);
    }
}

/// <summary>Microsoft IdentityModel verifies JWT signatures with keys from the pinned realm, never token jku, x5u or embedded certificates.
/// The expected credential issuer can explicitly be a configured DID; its keys still come from that realm.</summary>
public sealed class Oid4vcCredentialValidator
{
    private readonly OidcClient oidc;
    private readonly string expectedIssuer;
    private readonly string[] algorithms;
    public Oid4vcCredentialValidator(OidcClient oidc, string? expectedCredentialIssuer = null, IEnumerable<string>? allowedAlgorithms = null)
    {
        this.oidc = oidc ?? throw new ArgumentNullException(nameof(oidc)); expectedIssuer = expectedCredentialIssuer ?? oidc.Issuer.AbsoluteUri; WalletJson.Text(expectedIssuer);
        algorithms = (allowedAlgorithms ?? ["RS256"]).Distinct(StringComparer.Ordinal).ToArray();
        if (algorithms.Length == 0 || algorithms.Any(a => !JwtAlgorithms.Asymmetric.Contains(a, StringComparer.Ordinal))) throw new ArgumentException("Explicit asymmetric credential signing algorithms are required.", nameof(allowedAlgorithms));
    }
    public async Task<Oid4vcIssuerMetadata> ValidateSignedMetadataAsync(ProtocolResponse response, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(response);
        if (response.BodyMediaType != "application/jwt") throw new InvalidDataException("Signed credential metadata is required.");
        await oidc.EnsureFeaturesAsync([Oid4vcIssuerClient.Feature], cancellationToken).ConfigureAwait(false);
        var claims = await VerifyAsync(new UTF8Encoding(false, true).GetString(response.RawBody.Span), "openidvci-issuer-metadata+jwt", oidc.Issuer.AbsoluteUri, cancellationToken).ConfigureAwait(false);
        if (WalletJson.String(claims, "sub") != oidc.Issuer.AbsoluteUri) throw new InvalidDataException("Signed metadata subject does not match the issuer.");
        return new(oidc.Issuer, claims);
    }
    public async Task<VerifiedOid4vcCredential> ValidateAsync(string credential, Oid4vcCredentialConfiguration configuration, string? expectedHolderThumbprint,
        CancellationToken cancellationToken = default)
    {
        WalletJson.Credential(credential); ArgumentNullException.ThrowIfNull(configuration); cancellationToken.ThrowIfCancellationRequested();
        if (configuration.Issuer != oidc.Issuer || configuration.Format == "mso_mdoc") throw new ArgumentException("Use the matching issuer and the format-specific credential verifier.", nameof(configuration));
        await oidc.EnsureFeaturesAsync([Oid4vcIssuerClient.Feature], cancellationToken).ConfigureAwait(false);
        string[] parts = credential.Split('~'); bool sd = configuration.Format == "dc+sd-jwt";
        if (sd ? parts.Length < 2 || parts[^1].Length != 0 : parts.Length != 1) throw new InvalidDataException("An issued credential cannot include a presentation proof.");
        var claims = await VerifyAsync(parts[0], sd ? "dc+sd-jwt" : "vc+jwt", expectedIssuer, cancellationToken).ConfigureAwait(false);
        string? holder = null;
        if (claims.TryGetProperty("cnf", out var cnf))
        {
            WalletJson.Object(cnf); var key = DpopProofKey.ReadPublicJwk(cnf.GetProperty("jwk")); holder = Base64UrlEncoder.Encode(key.ComputeJwkThumbprint());
        }
        if (expectedHolderThumbprint is not null && holder != expectedHolderThumbprint) throw new InvalidDataException("Credential holder binding does not match the requesting wallet.");
        string[] disclosures = sd ? parts[1..^1] : [];
        var disclosed = sd ? SdJwtDisclosures.Resolve(claims, disclosures) : claims;
        if (sd && WalletJson.String(claims, "vct") != WalletJson.String(configuration.Document, "vct")) throw new InvalidDataException("Credential type does not match the authorized configuration.");
        if (!sd) WalletJson.Object(claims.GetProperty("vc"));
        return new(parts[0], claims, disclosed, configuration.Format, holder, disclosures);
    }
    private async Task<JsonElement> VerifyAsync(string jwt, string type, string issuer, CancellationToken ct)
    {
        WalletJson.Credential(jwt); ct.ThrowIfCancellationRequested();
        var keys = await oidc.GetSigningKeysAsync(ct).ConfigureAwait(false);
        var keySet = new JsonWebKeySet(keys.Json?.GetRawText() ?? throw new InvalidDataException("Empty issuer JWKS."));
        var result = await new JsonWebTokenHandler { MaximumTokenSizeInBytes = 65536, MapInboundClaims = false }.ValidateTokenAsync(jwt, new TokenValidationParameters
        {
            ValidateIssuer = true, ValidIssuer = issuer, ValidateAudience = false, ValidateLifetime = true, RequireExpirationTime = true,
            RequireSignedTokens = true, ValidateIssuerSigningKey = true, IssuerSigningKeys = keySet.GetSigningKeys(), ValidAlgorithms = algorithms,
            ValidTypes = [type], ClockSkew = TimeSpan.FromSeconds(30), IncludeTokenOnFailedValidation = false, LogTokenId = false, LogValidationExceptions = false
        }).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested();
        if (!result.IsValid) throw new InvalidDataException("Invalid signed credential or metadata.");
        // JsonWebTokenHandler returns JsonWebToken on success. No decryption key is configured, so
        // an encrypted token cannot validate through this signed-credential path.
        var token = (JsonWebToken)result.SecurityToken;
        using var document = JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(token.EncodedPayload)); WalletJson.Object(document.RootElement);
        foreach (string name in new[] { "exp", "nbf" })
            if (document.RootElement.TryGetProperty(name, out var time) && (time.ValueKind != JsonValueKind.Number || !time.TryGetInt64(out _)))
                throw new InvalidDataException("Invalid numeric credential lifetime.");
        if (document.RootElement.TryGetProperty("iat", out var issued) && (issued.ValueKind != JsonValueKind.Number || !issued.TryGetInt64(out long seconds) || seconds > DateTimeOffset.UtcNow.AddSeconds(30).ToUnixTimeSeconds()))
            throw new InvalidDataException("Invalid credential issue time.");
        return document.RootElement.Clone();
    }
}
