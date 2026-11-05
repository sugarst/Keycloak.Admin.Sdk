using System.Net;
using Keycloak.Admin.Sdk;

public static class InterfaceContracts
{
    public static async Task RawTransportsAsync()
    {
        using var cancellation = new CancellationTokenSource();
        using var handler = new ReplyHandler(cancellation.Token);
        using var http = new HttpClient(handler);
        IKeycloakAdminClient sdk = new KeycloakAdminClient(http, new Uri("https://keycloak.invalid/"));
        const string path = "/admin/serverinfo";
        var options = new KeycloakRequestOptions { AllowUnauthorizedReplay = true };
        await sdk.SendAsync(HttpMethod.Get, path, cancellationToken: cancellation.Token);
        await sdk.SendAsync(options, HttpMethod.Get, path, cancellationToken: cancellation.Token);
        var first = await sdk.SendJsonAsync(HttpMethod.Get, path, null, null,
            KeycloakJsonContext.Default.UserRepresentation, cancellation.Token);
        var second = await sdk.SendJsonAsync(options, HttpMethod.Get, path, null, null,
            KeycloakJsonContext.Default.UserRepresentation, cancellation.Token);
        if (!first.HasBody || first.Body?.Username != "interface" || second.Body?.Username != "interface")
            throw new InvalidOperationException("Interface JSON metadata or response mismatch.");
        using (var stream = await sdk.OpenStreamAsync(HttpMethod.Get, path, cancellationToken: cancellation.Token))
        using (var reader = new StreamReader(stream.Content))
            if (!(await reader.ReadToEndAsync(cancellation.Token)).Contains("interface", StringComparison.Ordinal))
                throw new InvalidOperationException("Interface stream response mismatch.");
        using (var stream = await sdk.OpenStreamAsync(options, HttpMethod.Get, path, cancellationToken: cancellation.Token))
            if (stream.StatusCode != HttpStatusCode.OK) throw new InvalidOperationException("Interface stream status mismatch.");
        if (handler.Calls != 6) throw new InvalidOperationException("Every raw interface overload must send exactly once.");
    }

    private sealed class ReplyHandler(CancellationToken expected) : HttpMessageHandler
    {
        public int Calls { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            if (!cancellationToken.CanBeCanceled || expected.IsCancellationRequested ||
                request.Method != HttpMethod.Get || request.RequestUri!.AbsolutePath != "/admin/serverinfo")
                throw new InvalidOperationException("Interface request mismatch.");
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"username\":\"interface\"}")
            });
        }
    }
}
