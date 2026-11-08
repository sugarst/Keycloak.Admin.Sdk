# Keycloak.Admin.Sdk

[简体中文](README.md) | English

A **.NET 10 / Native AOT** client for the Keycloak Admin REST API, currently targeting **Keycloak 26.8.1** only. The main package references Microsoft.Extensions.Http **10.0.14** and Microsoft.Extensions.Http.Resilience **10.11.0**, and uses source-generated JSON metadata with reflection serialization disabled. This repository pins .NET SDK **10.0.403**.

Public APIs may change. For development, reference the [core project](src/Keycloak.Admin.Sdk/Keycloak.Admin.Sdk.csproj).

## Quick start

Configure a Keycloak service account with management permissions for the target realm, then register the SDK in ASP.NET Core or a Generic Host:

```csharp
using Keycloak.Admin.Sdk;
using Microsoft.Extensions.DependencyInjection;

var configuration = builder.Configuration;
builder.Services.AddKeycloakAdminSdk(options =>
{
    options.Server = new Uri("https://keycloak.example.com/auth/");
    options.AuthenticationRealm = "master";
    options.ClientId = "admin-service";
    options.ClientSecret = (_, ct) => ValueTask.FromResult(
        configuration["Keycloak:ClientSecret"]
        ?? throw new InvalidOperationException("Missing Keycloak client secret"));
});
```

Inject the client into an application service:

```csharp
using Keycloak.Admin.Sdk;

public sealed class UserService(IKeycloakAdminClient sdk)
{
    public Task<AdminResponse<List<UserRepresentation>>> GetUsersAsync(
        string realm, CancellationToken cancellationToken)
        => sdk.Users.GetUsersAsync(realm, first: 0, max: 20,
            cancellationToken: cancellationToken);
}
```

Provide `Keycloak:ClientSecret` through a secure host configuration source. DI manages the HTTP client and token provider lifetimes and disables automatic redirects by default. The authentication realm is independent of the target realm. Use realm names and internal client UUIDs in paths; a client UUID is different from the OIDC `clientId`. All network methods support cancellation. Pagination exposes server parameters without snapshot or total-count guarantees.

`IKeycloakAdminClient` exposes generated resource interfaces such as `IUsersApi` for business test doubles. DI supports both the interface and concrete type, resolving the same client instance for each name. See [interfaces and test doubles](docs/authentication-and-errors.md#接口与测试替身).

This DI registration creates the underlying client without installing a support policy. To enforce the supported stable scope before requests, obtain a trusted server capability snapshot and configure `options.Client.RequestPolicy`, or use the asynchronous `KeycloakSupportedClient.CreateAsync`. See [authentication and DI](docs/authentication-and-errors.md) and [capability policy](docs/capability-policy.md) for manual construction, existing token integration and policy initialization.

`AddKeycloakAdminSdk` exposes opt-in read resilience through `options.Resilience`:

```csharp
services.AddKeycloakAdminSdk(options =>
{
    options.Server = server;
    options.ClientId = "admin-service";
    options.ClientSecret = (_, ct) => secretStore.GetSecretAsync(ct);
    options.Resilience = new() { Enabled = true, MaxRetryAttempts = 2 };
});
```

Only bodyless GET/HEAD requests use transient retry, timeout and circuit-breaking strategies. Writes and token POST bypass the entire pipeline, including an open read circuit. Resilience is disabled by default; 401 recovery remains a separate option. With both enabled, the default upper bound is six physical admin requests per logical call. Use a cancellation token for the whole operation: pipeline timeouts exclude token acquisition, SDK 401 recovery and response body reading. See [configuration and exception details](docs/authentication-and-errors.md#http-弹性策略). Do not stack another retry/resilience handler on this named client.

## Client and feature flags

The feature package depends on Microsoft telemetry components; telemetry is opt-in.

`new KeycloakAdminClient(...)` provides the underlying API transport. Use `KeycloakSupportedClient.CreateAsync` to enforce the supported scope before sending requests, or `Keycloak.Admin.Sdk.Platform` / `KeycloakPlatformHost.CreateAsync` for one host switch surface. See [capability policy](docs/capability-policy.md), [platform feature gate](docs/platform-feature-gate.md), and [authentication, errors and DI](docs/authentication-and-errors.md).

## Request and response conventions

- The caller disposes the `HttpClient` and token provider. Each request consumes and disposes its `HttpContent`; create fresh content for every call. Dispose the response returned by `OpenStreamAsync`.
- Buffered responses retain the status code, Location, headers, raw content and optional typed `Body`. Use `HasBody` to distinguish an empty response. Location is never followed automatically.
- Null DTO properties are omitted; false, zero and empty collections are sent. Use `SendAsync` / `SendJsonAsync` for explicit JSON nulls, dynamic payloads or custom source-generated models. See [special contracts](docs/contracts/six-path-fixes.md) for media-type examples.
- Build explicit update requests to avoid writing back read-only fields, masked secrets or brief representations. **In 26.8.1, a client PUT that omits `authorizationServicesEnabled=true` disables that client's authorization services.**
- HTTP errors throw `KeycloakAdminException`. Optional 401 recovery is disabled by default and permits one safe read replay when enabled. A timed-out write may have an unknown outcome. See [authentication and errors](docs/authentication-and-errors.md) for details.

## Keycloak 26.8.1 capability boundaries

This development branch maintains two separate matrices: [Admin API operations](docs/contracts/admin-api-support-matrix.tsv) and [platform capabilities](docs/contracts/platform-capability-matrix.md), covering 80 pinned upstream feature flags and 52 application capability families. Application capabilities are independently verified for an exact version and runtime. Deployment, databases, clustering, server UI and Java SPI responsibilities are documented in the [implementation scope](docs/full-platform-coverage.md). The 520-operation count below applies only to the Admin API.

All 52 reviewed application families are promoted and the complete-coverage gate passes. Standard live workflows verify 434 Managed / 391 Linux Native AOT checks, plus 20 legacy checks per runtime. Support remains specific to the matrix's runtime, RID and current-input evidence.

| Package | Use |
| --- | --- |
| `Keycloak.Admin.Sdk` | Admin API, service-account authentication and support policy |
| `Keycloak.Admin.Sdk.Protocols` | Application OIDC/OAuth, Account, SCIM, authorization, wallets and identity brokering; Managed and verified Linux Native AOT |
| `Keycloak.Admin.Sdk.Hosting` | ASP.NET Core login, resource tokens, logout, MCP metadata and SAML; Managed only |
| `Keycloak.Admin.Sdk.Platform` | One host switch surface for Admin and protocol capabilities; Managed and Native AOT |

preview.3 is an unpublished development version. Use project references or locally built packages for the new modules. Published preview.2 capabilities remain documented in the [changelog](CHANGELOG.md). See [wallet integration](docs/wallet-integration.md) and [authentication integration](docs/authentication-integration.md) for the new application flows.

The main package generates 520 Admin API operations, counted by HTTP method and path. Supported areas include realms, users, groups, roles, clients, client scopes, identity providers, authentication flows, authorization policies, organizations, workflows and admin console extensions. Availability also depends on the declared FGAP route, server features and account permissions.

| Scope | Operations | Verification |
| --- | --- | --- |
| Full generated contract | 520 | One independent contract test per operation |
| `fgap-v2-stable` (default) | 478 | Real business acceptance in managed and Linux Native AOT modes |
| `fgap-v1-compat` | 492 | Real business acceptance in managed and Linux Native AOT modes |

The following APIs remain outside the default formal acceptance scope. Non-stable capabilities use separate, runtime-specific validation plans:

| Keycloak feature | Stage | Operations | Independent support scope |
| --- | --- | ---: | --- |
| `oid4vc-vci` | Preview | 7 | Independent v2 Managed / Linux Native AOT validation; requires an explicit per-capability Preview opt-in and host flag |
| `ssf` | Experimental | 19 | Independent v2 Managed / Linux Native AOT validation; requires an explicit per-capability Experimental opt-in and host flag |
| `client-types` | Experimental | 2 | Independent v2 Managed / Linux Native AOT validation; off by default, requiring a schema-2 opt-in and host flag |

Schema 2 supports Managed, NativeAot and Portable verification profiles. Managed and Native AOT applications share `KeycloakFeatureSnapshotGate` through `Keycloak.Admin.Sdk.Platform`. Host flags cannot override version, stage or evidence denials. Existing configurations retain their requirement for both managed and AOT evidence. See the [capability policy](docs/capability-policy.md) for configuration and per-operation promotion.

The default v2 route also excludes 14 FGAP v1-only operations; those have passed acceptance on the v1 compatibility route. **A generated method does not itself imply SDK support.** Use `KeycloakSupportedClient.CreateAsync` to check version, maturity, route, server features and verification before sending a request. Constructing `KeycloakAdminClient` directly provides the underlying transport without applying the support policy automatically.

The core package covers the Keycloak 26.8.1 Admin API. Standalone OAuth/OIDC, Account, SCIM and Client Admin API v2 are provided and independently promoted by Protocols / Hosting. Console static assets and third-party SPI implementations remain server responsibilities. Results do not automatically apply to other Keycloak versions or exhaust every permission and configuration combination.

See the [support matrix](docs/contracts/admin-api-support-matrix.tsv) for per-operation status and exclusion reasons, the [verification index](docs/contracts/admin-api-validation-list.md) for a summary, and [live acceptance](docs/contracts/full-live-acceptance.md) for tested environments and evidence. See [capability policy](docs/capability-policy.md) for integration.

## Development and verification

Run from the repository root. Live services and container-based native verification require Docker:

```shell
dotnet run --file tools/Verify.cs -- --skip-native-publish # Build, tests and coverage
dotnet run --file tools/Verify.cs -- --native-container    # Also verify Linux Native AOT
dotnet run --file local/keycloak/Service.cs                # Start local Keycloak + PostgreSQL
```

The local console is at <http://127.0.0.1:18080/admin/>. The default user is `admin`; a random password is stored in the generated `local/keycloak/.env`. See the [local environment guide](local/keycloak/README.md) for persistence and service commands, and the [testing guide](docs/testing.md) for test entry points and reports. Without options, `Verify.cs` verifies the current platform's native executable; compiler requirements are listed in the testing guide.

## Documentation

The detailed guides and generated reports below are maintained in Chinese; the endpoint inventory is in English.

- [Architecture and contract sources](docs/architecture.md)
- [Changelog](CHANGELOG.md) · [Release records and retention](docs/releases/README.md)
- [Support routes](docs/contracts/admin-api-routing.md) · [Verification index](docs/contracts/admin-api-validation-list.md)
- [Endpoints and source mapping](docs/contracts/endpoint-inventory.md) · [Source alignment audit](docs/contracts/keycloak-26.8.1-alignment-audit.md)

[Apache License 2.0](LICENSE). See [third-party notices](THIRD_PARTY_NOTICES.md) for contract provenance and attribution.
