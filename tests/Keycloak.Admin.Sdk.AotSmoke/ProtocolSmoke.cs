using System.Net;
using System.Text.Json;
using Keycloak.Admin.Sdk.Protocols;

internal static class ProtocolSmoke
{
    public static async Task RunAsync(CancellationToken cancellationToken = default)
    {
        using var handler = new Handler(); using var http = new HttpClient(handler);
        var transport = new ProtocolTransport(http, new Uri("https://identity.invalid/"), "realm");
        var oidc = new OidcClient(transport);
        var response = await oidc.ClientCredentialsAsync(OAuthClientAuthentication.SecretBasic("client", _ => ValueTask.FromResult("secret")), cancellationToken: cancellationToken);
        if (response.Json!.Value.GetProperty("value").GetInt32() != 1) throw new InvalidOperationException("AOT protocol JSON contract failed.");
        await oidc.ExchangeAsync(OAuthClientAuthentication.Public("client"), "subject", cancellationToken: cancellationToken);
        using var document = JsonDocument.Parse("""{"schemas":[],"active":false}""");
        await RealmResourceClient.ScimUsers(transport).CreateAsync(document.RootElement, "user", cancellationToken);
        if (handler.Calls != 3) throw new InvalidOperationException("AOT protocol transport calls failed.");
        Console.WriteLine("PASS Native AOT application protocol transport contracts; not full protocol/business coverage.");
    }
    private sealed class Handler : HttpMessageHandler
    {
        public int Calls;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested(); Calls++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("""{"value":1}""") });
        }
    }
}
