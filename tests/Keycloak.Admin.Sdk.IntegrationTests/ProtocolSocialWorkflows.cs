using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Protocols;

internal static class ProtocolSocialWorkflows
{
    internal static async Task RunAsync(KeycloakAdminClient admin, ProtocolTransport transport, string realm, Uri server, string secret, Action<bool, string> check, CancellationToken ct)
    {
        string directory = Environment.GetEnvironmentVariable("KC_TEST_MTLS_DIRECTORY") ?? throw new InvalidDataException("Owned social TLS trust is required.");
        using var ca = X509Certificate2.CreateFromPem(await File.ReadAllTextAsync(Path.Combine(directory, "ca.pem"), ct));
        await using var upstream = new ProtocolSocialCounterpart(directory, secret, transport.Issuer);
        var oidc = new OidcClient(transport); var client = OAuthClientAuthentication.Public("sdk-authentication"); var callback = new Uri("http://127.0.0.1:18089/authentication-callback");
        foreach (var (provider, capability, externalId) in new[] { ("twitter", KeycloakAuthenticationCapability.Twitter, "42"), ("instagram", KeycloakAuthenticationCapability.Instagram, "graph_42") })
        {
            string alias = "sdk-" + provider;
            await admin.IdentityProviders.CreateAsync(realm, new() { Alias = alias, ProviderId = provider, Enabled = true, StoreToken = false,
                Config = new() { ["clientId"] = "social-fixture", ["clientSecret"] = secret, ["clientAuthMethod"] = "client_secret_post" } }, ct);
            await admin.Users.CreateUserAsync(realm, new() { Username = provider + "-local", FirstName = "Social", LastName = "Fixture", Email = provider + "-local@example.invalid", EmailVerified = true, Enabled = true }, ct);
            string user = (await admin.Users.GetUsersAsync(realm, username: provider + "-local", exact: true, cancellationToken: ct)).Body!.Single().Id!;
            await admin.User.AddFederatedIdentityAsync(realm, user, alias, new() { IdentityProvider = alias, UserId = externalId, UserName = provider + "-user" }, ct);
            async Task<OidcLoginResult> Login()
            {
                var transaction = await OidcLoginTransaction.StartAsync(oidc, client, callback, options: new() { IdentityProvider = alias, RequiredAuthenticationCapabilities = [capability] }, cancellationToken: ct);
                using var handler = new SocketsHttpHandler { AllowAutoRedirect = false, UseCookies = true, UseProxy = false,
                    ConnectCallback = async (context, token) =>
                    {
                        bool social = context.DnsEndPoint.Host is "api.twitter.com" or "api.instagram.com" or "graph.instagram.com";
                        if (!social && (context.DnsEndPoint.Host != server.Host || context.DnsEndPoint.Port != server.Port)) throw new InvalidDataException("Controlled browser attempted an external connection.");
                        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
                        try { await socket.ConnectAsync(IPAddress.Loopback, social ? 443 : context.DnsEndPoint.Port, token); return new NetworkStream(socket, true); } catch { socket.Dispose(); throw; }
                    } };
                handler.SslOptions.RemoteCertificateValidationCallback = (_, certificate, _, errors) =>
                {
                    if (certificate is null || (errors & (SslPolicyErrors.RemoteCertificateNameMismatch | SslPolicyErrors.RemoteCertificateNotAvailable)) != 0) return false;
                    using var chain = new X509Chain(); chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust; chain.ChainPolicy.CustomTrustStore.Add(ca);
                    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck; chain.ChainPolicy.DisableCertificateDownloads = true;
                    using var leaf = new X509Certificate2(certificate); return chain.Build(leaf);
                };
                using var browser = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(15) }; browser.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Version/18.0 Safari/605.1.15");
                Uri current = transaction.AuthorizationUri;
                for (int step = 0; step < 10; step++)
                {
                    if (current.GetLeftPart(UriPartial.Path) == callback.AbsoluteUri) return await transaction.CompleteAsync(current, client, new(oidc, client.ClientId), ct);
                    using var response = await browser.GetAsync(current, ct);
                    Console.WriteLine("Social browser fixture: " + provider + " " + (int)response.StatusCode + " " + current.Host + current.AbsolutePath);
                    if ((int)response.StatusCode is not (>= 300 and < 400) || response.Headers.Location is null) throw new InvalidDataException("Controlled social federation did not return a protocol redirect.");
                    current = new(current, response.Headers.Location);
                }
                throw new InvalidDataException("Controlled social federation exceeded its redirect bound.");
            }
            upstream.CorruptState = true; bool invalidState = false; int previousCorruptions = upstream.CorruptedStateCallbacks;
            try { await Login(); } catch (InvalidDataException) { invalidState = true; }
            check(invalidState && upstream.CorruptedStateCallbacks == previousCorruptions + 1 && (await admin.User.GetFederatedIdentityAsync(realm, user, ct)).Body!.Single(i => i.IdentityProvider == alias).UserId == externalId,
                "Controlled " + provider + " federation rejects a corrupted broker state without replacing the persisted external identity association");
            upstream.CorruptState = false;
            var login = await Login();
            check(login.Identity.Subject == user && (provider == "twitter" ? upstream.ValidatedOAuth1Requests >= 3 : upstream.ValidatedOAuth2Requests >= 1)
                && (await admin.User.GetFederatedIdentityAsync(realm, user, ct)).Body!.Single(i => i.IdentityProvider == alias).UserId == externalId,
                "Controlled " + provider + " federation completes the pinned upstream wire contract and independently verifies only its exact linked local application subject");
        }
    }
}
