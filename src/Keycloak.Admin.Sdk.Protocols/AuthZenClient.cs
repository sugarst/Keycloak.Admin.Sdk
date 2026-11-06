using System.Text;
using System.Text.Json;

namespace Keycloak.Admin.Sdk.Protocols;

/// <summary>AuthZen PDP requests use an explicit confidential service-account token. A false decision is a denial, not an HTTP failure.</summary>
public sealed class AuthZenClient(ProtocolTransport transport)
{
    private readonly ProtocolTransport transport = transport ?? throw new ArgumentNullException(nameof(transport));
    private const string Feature = "KeycloakSdk.Protocols.AuthZen";
    public Task<ProtocolResponse> DiscoverAsync(CancellationToken cancellationToken = default)
        => transport.SendAsync(HttpMethod.Get, ".well-known/authzen-configuration", "AuthZen.Discover", Feature, null, null, null, null, cancellationToken);
    public async Task<bool> EvaluateAsync(JsonElement evaluation, string token, CancellationToken cancellationToken = default)
    {
        var response = await SendAsync("evaluation", evaluation, token, cancellationToken).ConfigureAwait(false);
        return (response.Json ?? throw new InvalidDataException("Empty AuthZen decision.")).GetProperty("decision").GetBoolean();
    }
    /// <summary>Returns individual decisions. The host must apply the requested batch semantics without treating omitted results as permits.</summary>
    public Task<ProtocolResponse> EvaluateBatchAsync(JsonElement evaluations, string token, CancellationToken cancellationToken = default)
        => SendAsync("evaluations", evaluations, token, cancellationToken);
    private Task<ProtocolResponse> SendAsync(string operation, JsonElement body, string token, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);
        return transport.SendAsync(HttpMethod.Post, "authzen/access/v1/" + operation, "AuthZen." + operation, Feature,
            new StringContent(body.GetRawText(), Encoding.UTF8, "application/json"), token, null, null, ct);
    }
}
