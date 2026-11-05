using System.Globalization;
using System.Text.RegularExpressions;

namespace Keycloak.Admin.Sdk;

internal static partial class AdminUri
{
    public static IEnumerable<KeyValuePair<string, string?>> Query(KeyValuePair<string, object?>[] values)
    {
        foreach (var value in values)
        {
            if (value.Value is IEnumerable<string> list)
            {
                foreach (var item in list) yield return new(value.Key, item);
            }
            else yield return new(value.Key, QueryValue(value.Value));
        }
    }

    public static string Path(string template, string[] values) => Placeholder().Replace(template, m =>
    {
        var value = values[int.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture)];
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if (value is "." or "..") throw new ArgumentException("Dot path segments are not permitted.", nameof(values));
        return Uri.EscapeDataString(value);
    });

    public static string? QueryValue(object? value) => value switch
    {
        null => null,
        bool b => b ? "true" : "false",
        string s => s,
        IFormattable f => f.ToString(null, CultureInfo.InvariantCulture),
        _ => throw new ArgumentException("Unsupported query value type.", nameof(value))
    };

    public static Uri Base(Uri server)
    {
        ArgumentNullException.ThrowIfNull(server);
        if (!server.IsAbsoluteUri || server.Scheme is not ("https" or "http") || server.Query.Length != 0 || server.Fragment.Length != 0 || server.UserInfo.Length != 0)
            throw new ArgumentException("An absolute HTTP(S) server URI without credentials, query or fragment is required.", nameof(server));
        return new Uri(server.AbsoluteUri.TrimEnd('/') + "/");
    }

    public static Uri Combine(Uri server, string path, IEnumerable<KeyValuePair<string, string?>> query)
    {
        if (!path.StartsWith("/admin/", StringComparison.Ordinal) && !path.StartsWith("/realms/", StringComparison.Ordinal))
            throw new ArgumentException("Only server-relative admin or token paths are permitted.", nameof(path));
        string suffix = string.Join("&", query.Where(x => x.Value is not null).Select(x => Uri.EscapeDataString(x.Key) + "=" + Uri.EscapeDataString(x.Value!)));
        return new Uri(server.AbsoluteUri + path.TrimStart('/') + (suffix.Length == 0 ? "" : "?" + suffix));
    }

    [GeneratedRegex(@"\{(\d+)\}")]
    private static partial Regex Placeholder();
}
