namespace Keycloak.Admin.Sdk.Protocols;

internal static class OidcCallbackParameters
{
    internal static Dictionary<string, string> Read(Uri actual, Uri expected, OidcAuthorizationResponseMode mode)
    {
        ArgumentNullException.ThrowIfNull(actual);
        if (mode.Post() || !actual.IsAbsoluteUri || actual.GetLeftPart(UriPartial.Path) != expected.GetLeftPart(UriPartial.Path)
            || (mode.Fragment() ? actual.Query.Length != 0 : actual.Fragment.Length != 0)) throw new InvalidDataException("Unexpected OIDC callback destination.");
        string parameters = mode.Fragment() ? actual.Fragment.TrimStart('#') : actual.Query.TrimStart('?');
        if (parameters.Length > 32768) throw new InvalidDataException("OIDC callback exceeds its bound.");
        return Fields(parameters.Split('&', StringSplitOptions.RemoveEmptyEntries).Select(pair =>
        {
            string[] parts = pair.Split('=', 2);
            return KeyValuePair.Create(Uri.UnescapeDataString(parts[0].Replace('+', ' ')), parts.Length == 2 ? Uri.UnescapeDataString(parts[1].Replace('+', ' ')) : "");
        }));
    }
    internal static Dictionary<string, string> ReadForm(Uri actual, Uri expected, OidcAuthorizationResponseMode mode, IEnumerable<KeyValuePair<string, string>> fields)
    {
        ArgumentNullException.ThrowIfNull(actual); ArgumentNullException.ThrowIfNull(fields);
        if (!mode.Post() || actual != expected) throw new InvalidDataException("Unexpected OIDC form-post destination or response mode.");
        return Fields(fields);
    }
    private static Dictionary<string, string> Fields(IEnumerable<KeyValuePair<string, string>> fields)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal); long size = 0;
        foreach (var pair in fields)
        {
            if (string.IsNullOrEmpty(pair.Key) || pair.Value is null || !values.TryAdd(pair.Key, pair.Value)) throw new InvalidDataException("Duplicate or invalid OIDC callback parameter.");
            size += pair.Key.Length + pair.Value.Length;
            if (values.Count > 32 || size > 131072) throw new InvalidDataException("OIDC callback exceeds its bound.");
        }
        return values;
    }
    internal static async Task<Dictionary<string, string>> UnwrapAsync(Dictionary<string, string> values, OidcAuthorizationResponseMode mode, OidcTokenValidator validator, CancellationToken ct)
    {
        if (!mode.Signed())
        {
            if (values.ContainsKey("response")) throw new InvalidDataException("An unsolicited signed authorization response is not accepted.");
            return values;
        }
        if (values.Count != 1 || !values.TryGetValue("response", out string? credential)) throw new InvalidDataException("A signed authorization response is required.");
        var signed = await validator.ValidateAuthorizationResponseAsync(credential, ct).ConfigureAwait(false);
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string name in new[] { "state", "code", "error", "iss", "id_token", "access_token", "token_type" })
            if (signed.TryGetProperty(name, out var value))
            {
                if (value.ValueKind != System.Text.Json.JsonValueKind.String) throw new InvalidDataException("Invalid signed authorization response parameter.");
                result.Add(name, value.GetString()!);
            }
        return result;
    }
}
