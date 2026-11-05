# Keycloak.Admin.Sdk

[简体中文](README.md) | English

A **.NET 10 / Native AOT** client for the Keycloak Admin REST API, currently targeting **Keycloak 26.8.1** only. The main package references Microsoft.Extensions.Http **10.0.14** and Microsoft.Extensions.Http.Resilience **10.11.0**, and uses source-generated JSON metadata with reflection serialization disabled. This repository pins .NET SDK **10.0.403**.

The current package version is **0.1.0-preview.2**; public APIs may change. Reference the [core project](src/Keycloak.Admin.Sdk/Keycloak.Admin.Sdk.csproj), or consume the preview packages from the `artifacts/packages/0.1.0-preview.2` local NuGet feed produced by the verification tool.

## Quick start

Configure a Keycloak service account with management permissions for the target realm, then let the host manage HTTP clients and credentials:

```csharp
using Keycloak.Admin.Sdk;

var server = new Uri("https://keycloak.example.com/auth/");
using var http = new HttpClient(new SocketsHttpHandler { AllowAutoRedirect = false });
using var tokens = new ClientCredentialsTokenProvider(
    http, server, authenticationRealm: "master", clientId: "admin-service",
    secret: ct => ValueTask.FromResult(
        Environment.GetEnvironmentVariable("KEYCLOAK_CLIENT_SECRET")
        ?? throw new InvalidOperationException("Missing secret")));
var sdk = new KeycloakAdminClient(http, server, tokens);

var page = await sdk.Users.GetUsersAsync("target-realm", first: 0, max: 20);
foreach (var user in page.Body ?? []) Console.WriteLine(user.Username);

var created = await sdk.Users.CreateUserAsync("target-realm",
    new UserRepresentation { Username = "new-user", Enabled = true });
Console.WriteLine(created.Location);
```

The authentication realm is independent of the target realm. Use realm names and internal client UUIDs in paths; a client UUID is different from the OIDC `clientId`. Use `StaticAccessTokenProvider` or implement `IAccessTokenProvider` to reuse existing authentication. All network methods support cancellation. Pagination exposes server parameters without snapshot or total-count guarantees.

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

## NuGet packages and migration

| Package | Purpose | Native AOT |
| --- | --- | --- |
| `Keycloak.Admin.Sdk` | Admin client, authentication, capability policy, DI and HttpClientFactory | Supported |
| `Keycloak.Admin.Sdk.FeatureManagement` | Host feature flags and optional Application Insights evaluation telemetry | Managed only |

When upgrading from preview.1, replace the `.Capabilities` and `.DependencyInjection` package references with the main package, replace `.FeatureManagement.ApplicationInsights` with `.FeatureManagement`, and recompile. Existing namespaces and registration methods are preserved. Installing the feature package restores the Microsoft telemetry dependency. Telemetry is opt-in.

`new KeycloakAdminClient(...)` provides the underlying API transport. Use `KeycloakSupportedClient.CreateAsync` to enforce the supported scope before sending requests, or `KeycloakFeatureManagedClient.CreateAsync` for managed feature flags. See [capability policy](docs/capability-policy.md), [feature flags and telemetry](docs/feature-management.md), and [authentication, errors and DI](docs/authentication-and-errors.md).

## Request and response conventions

- The caller disposes the `HttpClient` and token provider. Each request consumes and disposes its `HttpContent`; create fresh content for every call. Dispose the response returned by `OpenStreamAsync`.
- Buffered responses retain the status code, Location, headers, raw content and optional typed `Body`. Use `HasBody` to distinguish an empty response. Location is never followed automatically.
- Null DTO properties are omitted; false, zero and empty collections are sent. Use `SendAsync` / `SendJsonAsync` for explicit JSON nulls, dynamic payloads or custom source-generated models. See [special contracts](docs/contracts/six-path-fixes.md) for media-type examples.
- Build explicit update requests to avoid writing back read-only fields, masked secrets or brief representations. **In 26.8.1, a client PUT that omits `authorizationServicesEnabled=true` disables that client's authorization services.**
- HTTP errors throw `KeycloakAdminException`. Optional 401 recovery is disabled by default and permits one safe read replay when enabled. A timed-out write may have an unknown outcome. See [authentication and errors](docs/authentication-and-errors.md) for details.

## Support and verification scope

| Scope | Operations | Verification |
| --- | --- | --- |
| Full generated contract | 520 | One independent contract test per operation |
| `fgap-v2-stable` (default) | 478 | Real business acceptance in managed and Linux Native AOT modes |
| `fgap-v1-compat` | 492 | Real business acceptance in managed and Linux Native AOT modes |

Both routes exclude 28 preview/experimental APIs; v2 also excludes 14 v1-only APIs. Excluded APIs retain generated methods and contract tests and are not counted as successful business acceptance. See the [coverage report](docs/contracts/test-coverage.md) for current test totals and coverage, and [live acceptance](docs/contracts/full-live-acceptance.md) for per-operation evidence. Results apply to the pinned baseline and recorded scenarios; see [verification status](docs/contracts/verification.md) for release limitations.

## Development and verification

Run from the repository root. Live services and container-based native verification require Docker:

```shell
dotnet run --file tools/Verify.cs -- --skip-native-publish # Build, tests, coverage and packages
dotnet run --file tools/Verify.cs -- --native-container    # Also verify Linux Native AOT
dotnet run --file local/keycloak/Service.cs                # Start local Keycloak + PostgreSQL
```

The local console is at <http://127.0.0.1:18080/admin/>. The default user is `admin`; a random password is stored in the generated `local/keycloak/.env`. See the [local environment guide](local/keycloak/README.md) for persistence and service commands, and the [testing guide](docs/testing.md) for test entry points and reports. Without options, `Verify.cs` verifies the current platform's native executable; compiler requirements are listed in the testing guide.

## Documentation

The detailed guides and generated reports below are maintained in Chinese; the endpoint inventory is in English.

- [Architecture and contract sources](docs/architecture.md)
- [Single-target upgrades and releases](docs/single-target-workflow.md)
- [Support routes](docs/contracts/admin-api-routing.md) · [Verification index](docs/contracts/admin-api-validation-list.md)
- [Endpoints and source mapping](docs/contracts/endpoint-inventory.md) · [Source alignment audit](docs/contracts/keycloak-26.8.1-alignment-audit.md)

[Apache License 2.0](LICENSE). See [third-party notices](THIRD_PARTY_NOTICES.md) for contract provenance and attribution.
