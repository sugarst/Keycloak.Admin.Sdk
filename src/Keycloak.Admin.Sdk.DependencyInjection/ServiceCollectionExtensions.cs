using Keycloak.Admin.Sdk;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Microsoft.Extensions.DependencyInjection;

public static class KeycloakAdminSdkServiceCollectionExtensions
{
    private const string DefaultName = "Keycloak.Admin.Sdk";

    /// <summary>Registers a singleton SDK client and cached service-account provider. The container owns their lifetimes.</summary>
    public static IHttpClientBuilder AddKeycloakAdminSdk(this IServiceCollection services, Action<KeycloakAdminSdkOptions> configure)
    {
        var builder = services.AddKeycloakAdminSdk(DefaultName, configure);
        services.AddSingleton(sp => sp.GetRequiredKeyedService<KeycloakAdminClient>(DefaultName));
        return builder;
    }

    /// <summary>Registers an isolated named identity. Resolve with GetRequiredKeyedService&lt;KeycloakAdminClient&gt;(name).</summary>
    public static IHttpClientBuilder AddKeycloakAdminSdk(this IServiceCollection services, string name, Action<KeycloakAdminSdkOptions> configure)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentNullException.ThrowIfNull(configure);
        services.AddOptions<KeycloakAdminSdkOptions>(name).Configure(configure)
            .Validate(o => o.Server is { IsAbsoluteUri: true } && o.Server.Scheme is "http" or "https"
                && o.Server.Query.Length == 0 && o.Server.Fragment.Length == 0 && o.Server.UserInfo.Length == 0,
                "Server must be an absolute HTTP(S) base URI without credentials, query or fragment.")
            .Validate(o => !string.IsNullOrWhiteSpace(o.AuthenticationRealm) && !string.IsNullOrWhiteSpace(o.ClientId), "AuthenticationRealm and ClientId are required.")
            .Validate(o => o.ClientSecret is not null && o.Client is not null && o.Token is not null, "Secret resolver and client/token options are required.")
            .ValidateOnStart();
        services.TryAddSingleton(TimeProvider.System);
        var builder = services.AddHttpClient(name).ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            PooledConnectionLifetime = TimeSpan.FromMinutes(5)
        });
        services.AddKeyedSingleton<HttpClient>(name, (sp, _) => sp.GetRequiredService<IHttpClientFactory>().CreateClient(name));
        services.AddKeyedSingleton<ClientCredentialsTokenProvider>(name, (sp, _) =>
        {
            var options = sp.GetRequiredService<IOptionsMonitor<KeycloakAdminSdkOptions>>().Get(name);
            return new(sp.GetRequiredKeyedService<HttpClient>(name), options.Server, options.AuthenticationRealm, options.ClientId,
                ct => options.ClientSecret(sp, ct), sp.GetRequiredService<TimeProvider>(), options.Token);
        });
        services.AddKeyedSingleton<KeycloakAdminClient>(name, (sp, _) =>
        {
            var options = sp.GetRequiredService<IOptionsMonitor<KeycloakAdminSdkOptions>>().Get(name);
            return new(sp.GetRequiredKeyedService<HttpClient>(name), options.Server,
                sp.GetRequiredKeyedService<ClientCredentialsTokenProvider>(name), options.Client);
        });
        return builder;
    }
}
