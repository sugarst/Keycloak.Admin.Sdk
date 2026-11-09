using System.Reflection;
using Keycloak.Admin.Sdk.Platform;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Microsoft.FeatureManagement;
using Keycloak.Admin.Sdk.Hosting;
using Keycloak.Admin.Sdk.Protocols;

// Intentionally a plain SDK consumer without a direct ASP.NET FrameworkReference.
// Its NuGet graph must retain patched XML/PKCS dependencies rather than depend on consumer-side pruning.
using var http = new HttpClient();
var resource = new KeycloakProtectedResource(new ProtocolTransport(http, new Uri("https://identity.invalid/"), "realm"), new Uri("https://api.invalid/mcp"), ["read"]);
if (resource.MetadataUri.AbsolutePath != "/.well-known/oauth-protected-resource/mcp") throw new InvalidOperationException("Invalid packaged resource metadata.");
foreach (var assembly in new[] { typeof(System.Security.Cryptography.Xml.SignedXml).Assembly, typeof(System.Security.Cryptography.Pkcs.SignedCms).Assembly })
{
    string version = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()!.InformationalVersion.Split('+')[0];
    if (!Version.TryParse(version, out var actual) || actual < new Version(10, 0, 14)) throw new InvalidOperationException("Hosting resolved an unpatched cryptography dependency.");
}
_ = typeof(ITfoxtec.Identity.Saml2.Saml2AuthnResponse).Assembly;
var services = new ServiceCollection();
services.AddSingleton<IConfiguration>(new ConfigurationBuilder().Build());
services.AddFeatureManagement().AddKeycloakApplicationInsightsTelemetry();
using var provider = services.BuildServiceProvider();
_ = provider.GetRequiredService<IVariantFeatureManager>();
Console.WriteLine("PASS Managed Hosting/Platform package consumer, optional telemetry disabled, and patched cryptography dependencies.");
