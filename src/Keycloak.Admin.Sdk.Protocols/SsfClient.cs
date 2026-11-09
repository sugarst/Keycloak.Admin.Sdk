using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Keycloak.Admin.Sdk.Protocols;

/// <summary>Keycloak SSF transmitter API. Receiver tokens are per-call. Poll acknowledgements must follow successful signature validation and durable event processing.</summary>
public sealed class SsfClient(ProtocolTransport transport)
{
    private readonly ProtocolTransport transport = transport ?? throw new ArgumentNullException(nameof(transport));
    private const string Prefix = "ssf/transmitter/";
    public Task<ProtocolResponse> DiscoverAsync(CancellationToken cancellationToken = default)
        => Send(HttpMethod.Get, ".well-known/ssf-configuration", null, null, null, cancellationToken);
    public Task<ProtocolResponse> CreateStreamAsync(JsonElement configuration, string receiverToken, CancellationToken cancellationToken = default)
        => Auth(HttpMethod.Post, "streams", configuration, receiverToken, null, cancellationToken);
    public Task<ProtocolResponse> GetStreamsAsync(string receiverToken, CancellationToken cancellationToken = default)
        => Auth(HttpMethod.Get, "streams", null, receiverToken, null, cancellationToken);
    public Task<ProtocolResponse> GetStreamAsync(string streamId, string receiverToken, CancellationToken cancellationToken = default)
        => Auth(HttpMethod.Get, "streams", null, receiverToken, Id(streamId), cancellationToken);
    public Task<ProtocolResponse> UpdateStreamAsync(JsonElement configuration, string receiverToken, CancellationToken cancellationToken = default)
        => WriteStreamAsync(HttpMethod.Patch, configuration, receiverToken, cancellationToken);
    public Task<ProtocolResponse> ReplaceStreamAsync(JsonElement configuration, string receiverToken, CancellationToken cancellationToken = default)
        => WriteStreamAsync(HttpMethod.Put, configuration, receiverToken, cancellationToken);
    public Task<ProtocolResponse> DeleteStreamAsync(string streamId, string receiverToken, CancellationToken cancellationToken = default)
        => Auth(HttpMethod.Delete, "streams", null, receiverToken, Id(streamId), cancellationToken);
    public Task<ProtocolResponse> GetStatusAsync(string streamId, string receiverToken, CancellationToken cancellationToken = default)
        => Auth(HttpMethod.Get, "streams/status", null, receiverToken, Id(streamId), cancellationToken);
    public Task<ProtocolResponse> UpdateStatusAsync(JsonElement status, string receiverToken, CancellationToken cancellationToken = default)
        => Auth(HttpMethod.Post, "streams/status", status, receiverToken, null, cancellationToken);
    public Task<ProtocolResponse> VerifyAsync(JsonElement verification, string receiverToken, CancellationToken cancellationToken = default)
        => Auth(HttpMethod.Post, "verify", verification, receiverToken, null, cancellationToken);
    public Task<ProtocolResponse> AddSubjectAsync(JsonElement subject, string receiverToken, CancellationToken cancellationToken = default)
        => Auth(HttpMethod.Post, "subjects/add", subject, receiverToken, null, cancellationToken);
    public Task<ProtocolResponse> RemoveSubjectAsync(JsonElement subject, string receiverToken, CancellationToken cancellationToken = default)
        => Auth(HttpMethod.Post, "subjects/remove", subject, receiverToken, null, cancellationToken);
    public Task<ProtocolResponse> PollAsync(string clientId, string streamId, JsonElement pollRequest, string receiverToken, CancellationToken cancellationToken = default)
        => Auth(HttpMethod.Post, "receivers/" + ProtocolTransport.Segment(clientId) + "/streams/" + ProtocolTransport.Segment(streamId) + "/poll", pollRequest, receiverToken, null, cancellationToken);
    private static KeyValuePair<string, string>[] Id(string id) { ArgumentException.ThrowIfNullOrWhiteSpace(id); return [new("stream_id", id)]; }
    private async Task<ProtocolResponse> WriteStreamAsync(HttpMethod method, JsonElement configuration, string token, CancellationToken ct)
    {
        // 26.8.1 only regenerates the poll endpoint when delivery.method changes. Replacing delivery with the same
        // poll method otherwise drops endpoint_url, and subsequent SETs lose aud. Preserve the transmitter's pinned
        // poll endpoint when changing other delivery fields. Never navigate to a delivery URL or retry a mutation.
        if (configuration.ValueKind == JsonValueKind.Object && configuration.TryGetProperty("delivery", out var delivery) && delivery.ValueKind == JsonValueKind.Object
            && delivery.TryGetProperty("method", out var deliveryMethod) && deliveryMethod.ValueKind == JsonValueKind.String
            && deliveryMethod.GetString() is "urn:ietf:rfc:8936" or "https://schemas.openid.net/secevent/risc/delivery-method/poll"
            && !delivery.TryGetProperty("endpoint_url", out _))
        {
            if (!configuration.TryGetProperty("stream_id", out var streamId) || streamId.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(streamId.GetString()))
                throw new ArgumentException("A stream_id is required.", nameof(configuration));
            string id = streamId.GetString()!;
            var current = (await GetStreamAsync(id, token, ct).ConfigureAwait(false)).Json ?? throw new InvalidDataException("Empty SSF stream.");
            var existing = current.GetProperty("delivery");
            if (existing.GetProperty("method").GetString() == deliveryMethod.GetString())
            {
                string endpoint = existing.GetProperty("endpoint_url").GetString() ?? throw new InvalidDataException("Missing SSF poll endpoint.");
                if (!endpoint.StartsWith(transport.Target(Prefix + "receivers/").AbsoluteUri, StringComparison.Ordinal)
                    || !endpoint.EndsWith("/streams/" + ProtocolTransport.Segment(id) + "/poll", StringComparison.Ordinal)) throw new InvalidDataException("Unpinned SSF poll endpoint.");
                var copy = JsonNode.Parse(configuration.GetRawText())!; copy["delivery"]!["endpoint_url"] = endpoint;
                using var document = JsonDocument.Parse(copy.ToJsonString()); configuration = document.RootElement.Clone();
            }
        }
        return await Auth(method, "streams", configuration, token, null, ct).ConfigureAwait(false);
    }
    private Task<ProtocolResponse> Auth(HttpMethod method, string path, JsonElement? body, string token, IEnumerable<KeyValuePair<string, string>>? query, CancellationToken ct)
    { ArgumentException.ThrowIfNullOrWhiteSpace(token); return Send(method, Prefix + path, body, token, query, ct); }
    private Task<ProtocolResponse> Send(HttpMethod method, string path, JsonElement? body, string? token, IEnumerable<KeyValuePair<string, string>>? query, CancellationToken ct)
        => transport.SendAsync(method, path, "Ssf.Transmitter", "KeycloakSdk.Protocols.Signals", body is null ? null : new StringContent(body.Value.GetRawText(), Encoding.UTF8, "application/json"), token, query, null, ct);
}
