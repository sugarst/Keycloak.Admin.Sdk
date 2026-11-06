# Keycloak.Admin.Sdk.FeatureManagement

适用于 .NET 10 托管应用的 Keycloak Admin SDK 功能开关扩展，安装时自动引用 `Keycloak.Admin.Sdk`。支持通过宿主开关管理功能灰度开放和关闭，并可按需启用 Application Insights 功能评估遥测。

## 安装

```shell
dotnet add package Keycloak.Admin.Sdk.FeatureManagement
```

## 接入示例

宿主提供 `HttpClient http`、服务器地址 `Uri server`、认证提供方 `IAccessTokenProvider tokens` 和 `CancellationToken cancellationToken`。服务器须匹配 SDK 的精确目标版本、FGAP 路线，认证身份须有读取 serverinfo 及目标管理接口的权限。

```csharp
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Capabilities;
using Keycloak.Admin.Sdk.FeatureManagement;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.FeatureManagement;

var configuration = new ConfigurationBuilder().AddInMemoryCollection(
    new Dictionary<string, string?>
    {
        ["feature_management:feature_flags:0:id"] = "KeycloakSdk.AdminApi",
        ["feature_management:feature_flags:0:enabled"] = "true"
    }).Build();
using var configurationLifetime = (IDisposable)configuration;
var services = new ServiceCollection();
services.AddSingleton<IConfiguration>(configuration);
services.AddFeatureManagement();
using var provider = services.BuildServiceProvider();

var support = new KeycloakSupportConfiguration(
    KeycloakTarget.Version, KeycloakRuntimeProfile.Managed);
IKeycloakAdminClient sdk = await KeycloakFeatureManagedClient.CreateAsync(
    http, server, tokens, support,
    provider.GetRequiredService<IVariantFeatureManager>(),
    cancellationToken: cancellationToken);
var users = await sdk.Users.GetUsersAsync(
    "target-realm", max: 20, cancellationToken: cancellationToken);
```

用户查询使用总开关；组织等独立能力还须配置对应 `FeatureId` 开关。总开关与功能开关必须同时允许，缺失或关闭时请求会在业务 HTTP 发送前被拒绝。工厂初始化仍会先读取一次受认证的服务器元数据。

## 非 Stable 功能与运行环境

非 Stable 功能先完成独立业务验证和按操作、路线及运行环境晋升，再由支持配置逐功能许可，最后通过 FeatureManagement 决定灰度范围和关闭时机。开关不能替代验证或改变上游阶段；Managed 验证不会自动赋予 Native AOT 支持。

本扩展用于托管应用。Native AOT 使用主包的能力策略及 `KeycloakFeatureSnapshotGate`。Application Insights 遥测默认关闭，启用步骤见接入文档。

## 文档

- [功能开关及遥测接入](https://github.com/sugarst/Keycloak.Admin.Sdk/blob/main/docs/feature-management.md)
- [完整开关配置示例](https://github.com/sugarst/Keycloak.Admin.Sdk/blob/main/contracts/feature-management.example.json)
- [非 Stable 功能验证与晋升](https://github.com/sugarst/Keycloak.Admin.Sdk/blob/main/docs/non-stable-feature-lifecycle.md)
- [认证与依赖注入](https://github.com/sugarst/Keycloak.Admin.Sdk/blob/main/docs/authentication-and-errors.md)
- [版本变更](https://github.com/sugarst/Keycloak.Admin.Sdk/blob/main/CHANGELOG.md)
