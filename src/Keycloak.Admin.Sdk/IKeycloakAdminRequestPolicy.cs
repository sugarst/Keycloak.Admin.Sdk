namespace Keycloak.Admin.Sdk;

/// <summary>Optional host policy evaluated once per logical request, before token acquisition and HTTP dispatch.
/// Implementations must support concurrent calls. The resolved target includes the server context path.</summary>
public interface IKeycloakAdminRequestPolicy
{
    ValueTask EnsureAllowedAsync(HttpMethod method, Uri target, string? operation, CancellationToken cancellationToken);
}
