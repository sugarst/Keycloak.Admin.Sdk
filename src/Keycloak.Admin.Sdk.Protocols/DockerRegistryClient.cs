using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.RegularExpressions;

namespace Keycloak.Admin.Sdk.Protocols;

/// <summary>Docker registry token flow against one pinned Keycloak realm. Registry challenges cannot redirect credentials to another authority or realm.</summary>
public sealed partial class DockerRegistryClient(ProtocolTransport transport)
{
    private readonly ProtocolTransport transport = transport ?? throw new ArgumentNullException(nameof(transport));
    private const string Path = "protocol/docker-v2/auth";
    public Task<ProtocolResponse> AuthenticateChallengeAsync(string challenge, Func<CancellationToken, ValueTask<NetworkCredential>> credential,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(challenge);
        if (challenge.Length > 8192 || challenge.Contains('\r') || challenge.Contains('\n')
            || !AuthenticationHeaderValue.TryParse(challenge, out var header) || !header.Scheme.Equals("Bearer", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Expected a bounded registry Bearer challenge.", nameof(challenge));
        string parameters = header.Parameter ?? "";
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase); int end = 0;
        foreach (Match match in Parameters().Matches(parameters))
        {
            if (!values.TryAdd(match.Groups[1].Value, match.Groups[2].Value)) throw new ArgumentException("Duplicate registry challenge parameter.", nameof(challenge));
            end += match.Length;
        }
        if (end != parameters.Length || !values.TryGetValue("realm", out string? realm)
            || realm != transport.Target(Path).AbsoluteUri || !values.TryGetValue("service", out string? service) || string.IsNullOrWhiteSpace(service))
            throw new ArgumentException("Registry challenge must identify the pinned Keycloak token endpoint and service.", nameof(challenge));
        return RequestTokenAsync(service, values.TryGetValue("scope", out string? scope) ? [scope] : [], credential, cancellationToken);
    }

    public Task<ProtocolResponse> RequestTokenAsync(string service, IEnumerable<string> scopes, Func<CancellationToken, ValueTask<NetworkCredential>> credential,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(service); ArgumentNullException.ThrowIfNull(scopes); ArgumentNullException.ThrowIfNull(credential);
        var query = new List<KeyValuePair<string, string>> { new("service", service) };
        foreach (string scope in scopes) { ArgumentException.ThrowIfNullOrWhiteSpace(scope); query.Add(new("scope", scope)); }
        return transport.SendAsync(HttpMethod.Get, Path, "Docker.Token", "KeycloakSdk.Protocols.Docker", null, null, query,
            async (request, ct) =>
            {
                var identity = await credential(ct).ConfigureAwait(false); ct.ThrowIfCancellationRequested();
                ArgumentNullException.ThrowIfNull(identity); ArgumentException.ThrowIfNullOrWhiteSpace(identity.UserName);
                if (identity.UserName.Contains(':')) throw new ArgumentException("A Basic-auth username cannot contain a colon.");
                request.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(identity.UserName + ":" + identity.Password)));
            }, cancellationToken);
    }

    [GeneratedRegex("\\G\\s*([a-zA-Z_]+)\\s*=\\s*\"([^\"\\\\\\r\\n]*)\"\\s*(?:,|$)", RegexOptions.CultureInvariant)]
    private static partial Regex Parameters();
}
