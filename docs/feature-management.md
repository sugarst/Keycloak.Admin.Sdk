# FeatureManagement 与 Application Insights

`Keycloak.Admin.Sdk.FeatureManagement` 使用 Microsoft.FeatureManagement 4.8.0；独立的 `Keycloak.Admin.Sdk.FeatureManagement.ApplicationInsights` 使用同版本官方遥测适配器。两者仅面向托管宿主，不声明 AOT 兼容。原生应用使用 [能力策略](capability-policy.md) 的配置及禁用集合。

## 开放规则

`KeycloakFeatureManagementPolicy` 先执行能力策略，再检查 `KeycloakSdk.AdminApi` 总开关和目录项的 `FeatureId` 开关；目标就是总开关时只检查一次。目录拒绝不调用 FeatureManager；缺失/false 开关返回 DisabledByHost，过滤器或配置异常直接传播，均不发送业务请求。

开关不能绕过阶段、支持、验证或 FGAP 路线。所有请求入口每个逻辑调用只评估一次，401 重放复用结果，下一次调用重新评估；配置变化不撤销已发送请求。不同开关之间不保证跨提供方原子性。

策略接收 `IVariantFeatureManager`，复用宿主的注册、过滤器和刷新，仅消费布尔结果。若使用 scoped `IVariantFeatureManagerSnapshot` 固定宿主请求内的结果，SDK 客户端须同属该 scope；默认 singleton FeatureManager 可与单例客户端一起使用。

## 接入

完整能力 ID 和默认关闭的遥测配置见 [feature-management.example.json](../contracts/feature-management.example.json)。支持声明另用 [support-policy.example.json](../contracts/support-policy.example.json) 的严格解析器；不要反射绑定为 Options。

```csharp
using Keycloak.Admin.Sdk.Capabilities;
using Keycloak.Admin.Sdk.FeatureManagement;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.FeatureManagement;

var configuration = new ConfigurationBuilder()
    .AddJsonFile("feature-management.json", optional: false, reloadOnChange: true)
    .Build();
var services = new ServiceCollection();
services.AddSingleton<IConfiguration>(configuration);
services.AddFeatureManagement();
using var provider = services.BuildServiceProvider();

var support = KeycloakSupportConfiguration.Parse(
    await File.ReadAllTextAsync("support-policy.json"),
    Environment.GetEnvironmentVariable);
var sdk = await KeycloakFeatureManagedClient.CreateAsync(
    http, server, tokens, support,
    provider.GetRequiredService<IVariantFeatureManager>());
await sdk.Users.GetUsersAsync("target-realm");
```

`http`、`server`、`tokens` 由宿主管理，示例见 [README](../README.md)。工厂先读取一次受认证的 serverinfo，再检查版本和总开关；初始化拒绝前可能已发送该元数据请求。已有可信快照时可自行构造能力/功能策略，安装到 `KeycloakAdminClientOptions.RequestPolicy`。

支持策略的环境覆盖见 [能力策略](capability-policy.md)。FeatureManagement 由宿主配置提供方处理；启用 `AddEnvironmentVariables()` 后，示例总开关的键为 `feature_management__feature_flags__0__enabled`，Organizations 为 `feature_management__feature_flags__2__enabled`。数字取决于数组位置，重排须同步；优先沿用宿主配置发布/刷新机制。

## 可选遥测

必须同时满足：

1. 显式调用 `AddKeycloakApplicationInsightsTelemetry(enabled: true)`；默认 false 不注册 publisher。
2. 对目标 feature 设置 `"telemetry": { "enabled": true }`，采用 Microsoft `feature_management` schema。
3. 宿主注册 `TelemetryClient`，管理配置、hosted service 及发送生命周期。

在构建 Host/ServiceProvider 前注册；若宿主已有 Application Insights，复用其 `TelemetryClient`：

```csharp
using Keycloak.Admin.Sdk.FeatureManagement.ApplicationInsights;
using Microsoft.ApplicationInsights;
using Microsoft.ApplicationInsights.Extensibility;
using Microsoft.FeatureManagement;

bool enabled = bool.TryParse(configuration["KeycloakTelemetry:ApplicationInsightsEnabled"], out var value) && value;
services.AddFeatureManagement().AddKeycloakApplicationInsightsTelemetry(enabled);

using var telemetry = enabled ? new TelemetryConfiguration
{
    ConnectionString = Environment.GetEnvironmentVariable("APPLICATIONINSIGHTS_CONNECTION_STRING")
        ?? throw new InvalidOperationException("Missing Application Insights connection string")
} : null;
if (telemetry is not null) services.AddSingleton(new TelemetryClient(telemetry));
```

Generic Host / ASP.NET Core 自动启动注册的 hosted services。仅用 ServiceProvider 时，宿主须对 `GetServices<IHostedService>()` 调用 `StartAsync` / `StopAsync`，退出前 `FlushAsync`，最后释放配置；publisher 只注册一次。

官方 publisher 监听整个宿主的 `Microsoft.FeatureManagement` ActivitySource，因此其他开启遥测的 feature 也可能产生事件。适配器不添加 Keycloak URL、realm、用户、凭据或正文，也不注册请求/依赖自动采集；宿主自行管理 targeting、metadata、initializer 和采样。目录拒绝不产生开关评估，遥测不代表请求、授权或业务验收成功。

## 验证边界

严格原生发布曾触发标准引擎配置绑定、过滤器反射及间接遥测依赖的 IL2026 / IL3050 等诊断，因此两个包不进入原生程序，也不抑制相关警告。托管单测使用官方 FeatureManager 与 publisher，本地内存通道验证默认关闭及开启条件，未向 Azure 投递。

托管真实验收另验证动态开关控制创建/删除和持久化状态；原生程序排除这两个包，manifest 分别记录 `microsoft-4.8.0` 与 `not-loaded-native-aot`。结果见 [覆盖率](contracts/test-coverage.md) 和 [真实验收](contracts/full-live-acceptance.md)，命令见 [测试说明](testing.md)。

参考：[微软配置、生命周期与遥测文档](https://learn.microsoft.com/en-us/azure/azure-app-configuration/feature-management-dotnet-reference)。
