using System.Net;
using Keycloak.Admin.Sdk;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

public static class DependencyInjectionContracts
{
    public static async Task RunAsync()
    {
        var services = new ServiceCollection();
        services.AddKeycloakAdminSdk(o => Configure(o, "default", false))
            .ConfigurePrimaryHttpMessageHandler(() => new Handler("default"));
        services.AddKeycloakAdminSdk("other", o => Configure(o, "other", true))
            .ConfigurePrimaryHttpMessageHandler(() => new Handler("other"));
        using var container = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true, ValidateOnBuild = true });
        var sdk = container.GetRequiredService<KeycloakAdminClient>();
        var other = container.GetRequiredKeyedService<KeycloakAdminClient>("other");
        await sdk.Users.GetUsersAsync("target");
        await other.Users.GetUsersAsync("target");
        using (var scope = container.CreateScope())
            Check(ReferenceEquals(sdk, scope.ServiceProvider.GetRequiredService<KeycloakAdminClient>()), "singleton SDK lifetime");
        Check(!ReferenceEquals(sdk, other), "named clients isolated");
        Check(await container.GetRequiredKeyedService<ClientCredentialsTokenProvider>("other").GetAccessTokenAsync() == "other-token", "named token cache");

        var invalid = new ServiceCollection();
        invalid.AddKeycloakAdminSdk(_ => { });
        using var bad = invalid.BuildServiceProvider();
        try { bad.GetRequiredService<KeycloakAdminClient>(); throw new InvalidOperationException("Expected invalid options"); }
        catch (OptionsValidationException e) { Check(!e.Message.Contains("client-secret-value"), "validation has no credentials"); }
    }

    private static void Configure(KeycloakAdminSdkOptions options, string identity, bool recovery)
    {
        options.Server = new Uri("https://" + identity + ".invalid/auth/");
        options.AuthenticationRealm = "auth-" + identity;
        options.ClientId = identity;
        options.ClientSecret = (_, _) => ValueTask.FromResult("client-secret-value");
        options.Client = new() { EnableUnauthorizedRecovery = recovery };
        options.Token = new() { FailureCooldown = TimeSpan.Zero };
    }
    private static void Check(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
    private sealed class Handler(string identity) : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Check(request.RequestUri!.Host == identity + ".invalid", "named address");
            if (request.Method == HttpMethod.Post)
            {
                var form = await request.Content!.ReadAsStringAsync(cancellationToken);
                Check(request.RequestUri.AbsolutePath == "/auth/realms/auth-" + identity + "/protocol/openid-connect/token" && form.Contains("client_id=" + identity), "named credentials");
                return new(HttpStatusCode.OK) { Content = new StringContent("{\"access_token\":\"" + identity + "-token\",\"expires_in\":60,\"token_type\":\"Bearer\"}") };
            }
            Check(request.Headers.Authorization?.Parameter == identity + "-token", "token isolation");
            return new(HttpStatusCode.OK) { Content = new StringContent("[]") };
        }
    }
}
