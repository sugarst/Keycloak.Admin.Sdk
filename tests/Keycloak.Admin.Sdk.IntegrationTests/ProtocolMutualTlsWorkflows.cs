using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Protocols;

internal static class ProtocolMutualTlsWorkflows
{
    internal static async Task RunAsync(KeycloakAdminClient admin, string realm, Action<bool, string> check, CancellationToken ct)
    {
        string directory = Environment.GetEnvironmentVariable("KC_TEST_MTLS_DIRECTORY") ?? throw new InvalidOperationException("TLS fixture directory is required.");
        using var ca = X509Certificate2.CreateFromPem(await File.ReadAllTextAsync(Path.Combine(directory, "ca.pem"), ct));
        using var certificate = X509Certificate2.CreateFromPemFile(Path.Combine(directory, "client.pem"), Path.Combine(directory, "client.key"));
        using var other = X509Certificate2.CreateFromPemFile(Path.Combine(directory, "other-client.pem"), Path.Combine(directory, "other-client.key"));
        HttpClient Client(X509Certificate2? peer, X509Certificate2? root = null)
        {
            var handler = new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false, ClientCertificateOptions = ClientCertificateOption.Manual };
            if (peer is not null) handler.ClientCertificates.Add(peer);
            handler.ServerCertificateCustomValidationCallback = (_, actual, _, errors) =>
            {
                if (actual is null || (errors & (SslPolicyErrors.RemoteCertificateNameMismatch | SslPolicyErrors.RemoteCertificateNotAvailable)) != 0) return false;
                using var chain = new X509Chain(); chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust; chain.ChainPolicy.CustomTrustStore.Add(root ?? ca);
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck; chain.ChainPolicy.ApplicationPolicy.Add(new("1.3.6.1.5.5.7.3.1")); return chain.Build(actual);
            };
            return new HttpClient(handler);
        }
        await admin.Clients.CreateClientAsync(realm, new ClientRepresentation { ClientId = "mtls-client", Protocol = "openid-connect", Enabled = true, PublicClient = false,
            ServiceAccountsEnabled = true, ClientAuthenticatorType = "client-x509", Attributes = new() { ["x509.subjectdn"] = certificate.Subject, ["x509.casubjectdn"] = ca.Subject,
                ["x509.allow.regex.pattern.comparison"] = "false", ["tls.client.certificate.bound.access.tokens"] = "true" },
            ProtocolMappers = [new() { Name = "audience", Protocol = "openid-connect", ProtocolMapper = "oidc-audience-mapper", Config = new() { ["included.client.audience"] = "mtls-client", ["access.token.claim"] = "true" } }] }, cancellationToken: ct);
        var client = OAuthClientAuthentication.MutualTls("mtls-client"); var server = new Uri("https://127.0.0.1:8443/");
        using var http = Client(certificate); var oidc = new OidcClient(new(http, server, realm, mutualTls: true));
        var result = await oidc.ClientCredentialsAsync(client, "openid", ct); string token = result.Json!.Value.GetProperty("access_token").GetString()!;
        var identity = await new KeycloakAccessTokenValidator(oidc, "mtls-client").ValidateAsync(token, ct);
        check(identity.Subject.Length != 0 && MutualTlsTokenBinding.Matches(identity, certificate) && !MutualTlsTokenBinding.Matches(identity, other),
            "mTLS client authentication uses a trusted real TLS certificate and issues a signature-verified token bound to that exact certificate thumbprint");
        var userinfo = await oidc.GetUserInfoAsync(token, ct);
        check(userinfo.Json!.Value.GetProperty("sub").GetString() == identity.Subject, "Keycloak userinfo accepts a certificate-bound token only on the matching authenticated TLS connection");
        using var wrongHttp = Client(other); using var anonymousHttp = Client(null);
        foreach (var (connection, proof) in new[] { (wrongHttp, "mTLS client authentication rejects a trusted certificate with the wrong configured subject"), (anonymousHttp, "mTLS client authentication rejects a request without a client certificate") })
        {
            bool denied = false;
            try { await new OidcClient(new(connection, server, realm, mutualTls: true)).ClientCredentialsAsync(client, cancellationToken: ct); }
            catch (KeycloakProtocolException e) when (e.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.Unauthorized) { denied = true; }
            check(denied, proof);
        }
        bool wrongBinding = false, absentBinding = false;
        try { await new OidcClient(new(wrongHttp, server, realm, mutualTls: true)).GetUserInfoAsync(token, ct); } catch (KeycloakProtocolException e) when (e.StatusCode == HttpStatusCode.Unauthorized) { wrongBinding = true; }
        try { await new OidcClient(new(anonymousHttp, server, realm, mutualTls: true)).GetUserInfoAsync(token, ct); } catch (KeycloakProtocolException e) when (e.StatusCode == HttpStatusCode.Unauthorized) { absentBinding = true; }
        check(wrongBinding && absentBinding, "Keycloak refuses a copied certificate-bound access token on another trusted certificate or a connection without a client certificate");
        using var untrustedServer = Client(certificate, other); bool serverTrust = false;
        try { await new OidcClient(new(untrustedServer, server, realm, mutualTls: true)).DiscoverAsync(ct); } catch (HttpRequestException) { serverTrust = true; }
        check(serverTrust, "mTLS test client validates the actual server certificate chain and rejects an untrusted TLS server root");
    }
}
