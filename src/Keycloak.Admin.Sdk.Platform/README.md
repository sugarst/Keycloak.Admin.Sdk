# Keycloak.Admin.Sdk.Platform

一个宿主开关面控制 SDK 暴露的全部能力：Admin API 与应用协议链共享同一份开关目录、同一次 `serverinfo` 引导和同一个 `IKeycloakFeatureGate` 实例。包内不依赖任何外部特性管理引擎，可声明 Native AOT 兼容。

## 安装

```shell
dotnet add package Keycloak.Admin.Sdk.Platform
```

引用本包会自动引用 `Keycloak.Admin.Sdk` 与 `Keycloak.Admin.Sdk.Protocols`。ASP.NET Core 宿主集成仍按需单独引用 `Keycloak.Admin.Sdk.Hosting`（该包不声明 Native AOT 支持）。

## 使用

```csharp
using Keycloak.Admin.Sdk.Capabilities;
using Keycloak.Admin.Sdk.Platform;
using Keycloak.Admin.Sdk.Protocols;

var flags = new KeycloakFeatureFlagCatalog().All.ToDictionary(id => id, _ => true);
flags["KeycloakSdk.Organizations"] = false;

var options = new KeycloakPlatformOptions
{
    Support = new KeycloakSupportConfiguration(KeycloakTarget.Version, KeycloakRuntimeProfile.Managed),
    ProtocolSupport = new ApplicationSupportConfiguration(KeycloakRuntimeProfile.Managed),
    Flags = flags
};

var host = await KeycloakPlatformHost.CreateAsync(http, server, tokens, options, ct);
var users = await host.Admin.Users.GetUsersAsync("master", cancellationToken: ct);
var transport = host.CreateProtocolTransport(http, "master");
```

`CreateAsync` 仅执行一次受认证的 `admin/serverinfo` 读取，并在返回前对该元数据请求本身执行能力与开关检查；后续所有业务请求都经过 `KeycloakFeatureGatePolicy`。`CreateProtocolTransport` 复用同一份 `KeycloakServerCapabilities` 和同一个 gate，不会重复引导。

## 开关规则

- 目录来自生成的 `contracts/feature-flag-catalog.json`，由 `tools/Generate-FeatureCatalog.cs --check` 与能力矩阵校验一致。
- 两个总闸：`KeycloakSdk.AdminApi`（Admin 链）与 `KeycloakSdk.Protocols`（协议链）。Admin 链还检查目标端点的 `FeatureId`，协议链检查 `KeycloakSdk.Protocols.*`。
- `KeycloakFeatureFlagCatalog.EnsureComplete` 采用 fail-closed：未知开关或不完整的开关集合都会在启动时拒绝，避免能力被静默关闭。
- 配置变化通过 `KeycloakPlatformGate.Replace` 原子替换整份快照，影响后续请求，不撤销已发送的请求，也不改变上游阶段或服务端 feature。

## 边界

本包不控制 Keycloak 服务端的 `KC_FEATURES`；`serverinfo.features[]` 只读入并用于能力校验。遥测、配置提供与刷新机制由宿主负责；宿主若仍要接微软特性管理引擎，自行实现主包的 `IKeycloakFeatureGate` 即可。
