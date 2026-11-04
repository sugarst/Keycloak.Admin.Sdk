using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

namespace Keycloak.Admin.Sdk;

internal static class AdminJson
{
    public static JsonTypeInfo<T> TypeInfo<T>() => KeycloakJsonContext.Default.GetTypeInfo(typeof(T)) as JsonTypeInfo<T>
        ?? throw new NotSupportedException($"No source-generated JSON contract for {typeof(T)}.");

    public static HttpContent Content<T>(T body, JsonTypeInfo<T> typeInfo)
    {
        var content = new ByteArrayContent(JsonSerializer.SerializeToUtf8Bytes(body, typeInfo));
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        return content;
    }
}
