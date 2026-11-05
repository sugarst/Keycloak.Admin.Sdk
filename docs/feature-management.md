# FeatureManagement 与可选 Application Insights

依赖边界如下。核心 SDK 保持零运行时 NuGet 包依赖；FeatureManagement 与遥测均是独立的托管扩展，不要求 Native AOT。

| 包 | 依赖与用途 | 验证范围 |
| --- | --- | --- |
| `Keycloak.Admin.Sdk` | 无运行时 NuGet 依赖；520 项 wire API | 托管及严格 Native AOT |
| `Keycloak.Admin.Sdk.Capabilities` | 仅引用核心；版本目录及支持策略 | 托管及严格 Native AOT |
| `Keycloak.Admin.Sdk.FeatureManagement` | Capabilities + `Microsoft.FeatureManagement` **4.8.0** | 托管宿主 |
| `Keycloak.Admin.Sdk.FeatureManagement.ApplicationInsights` | FeatureManagement 扩展 + `Microsoft.FeatureManagement.Telemetry.ApplicationInsights` **4.8.0** | 托管宿主，本地遥测通道 |

本次实际尝试过 SDK 10.0.403 的严格原生发布：4.8.0 标准引擎的配置绑定、上下文过滤器反射及间接依赖 Application Insights 2.22.0 的动态配置触发 IL2026、IL3050 等诊断。因此两个托管扩展不声明 `IsAotCompatible`，不进入原生验收程序。没有关闭 AOT/裁剪警告，也没有复制或替换官方 FeatureManager。原生应用继续使用 [能力策略](capability-policy.md) 的声明式配置和禁用集合。

## 开放规则

`KeycloakFeatureManagementPolicy` 实现核心的 `IKeycloakAdminRequestPolicy`，依次执行：

1. 版本、真实服务端 feature、接口、FGAP 路线、阶段、支持状态及验证状态全部通过。
2. `KeycloakSdk.AdminApi` 总开关为 true。
3. 目录项的 `FeatureId` 开关为 true；如果就是总开关，只评估一次。

任何目录拒绝都不调用 FeatureManager。缺失和 false 开关返回 `DisabledByHost`；过滤器和配置异常直接向上传播，业务请求不发送。开关不能把 NotSupported 或缺少验收的接口变成可用，也不能把 FGAP v2 切换为 v1。`KeycloakCapabilityDecision.DisableByHost()` 只允许收紧结果，保留更早的拒绝原因。

生成方法、原始请求、显式 JSON 元数据请求和流共用这个入口，在 token 获取和 HTTP 发送前判断。每个逻辑请求评估一次；401 恢复重放复用本次判断，下一次调用重新评估。配置变更不撤销已发送的请求。两个不同开关之间没有跨提供方的原子事务保证。

策略接收 `IVariantFeatureManager`，可使用宿主标准注册、过滤器、配置刷新；适配器只消费开关的布尔结果，不给接口定义 variant 业务含义。宿主负责自定义过滤器的服务、参数和上下文。需要同一宿主请求内固定开关值时可传入 `IVariantFeatureManagerSnapshot`，此时 SDK 客户端必须同属该 scope；不得把 scoped snapshot 存入单例 SDK。默认的 singleton FeatureManager 可随单例客户端使用。

## 声明与接入

接入 `Keycloak.Admin.Sdk.FeatureManagement` 扩展。开发阶段可添加对应项目引用，或从 `artifacts/packages` 本地源消费 `Verify.cs` 生成的预览包；本次没有执行 NuGet 发布。完整 11 个能力 ID 的配置在 [feature-management.example.json](../contracts/feature-management.example.json)，所有遥测默认关闭；预览/实验能力关闭。`FgapV1` 开关为 true 仍受路线约束，只有明确声明 `fgap-v1-compat` 时才可能开放兼容接口。

配置加载由宿主管理。以下示例使用宿主的 `Microsoft.Extensions.Configuration.Json`；ASP.NET Core 通常已有配置入口。不要直接绑定反射式 Options 来解析支持策略，使用已有的严格解析器。

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

`http`、`server`、`tokens` 由宿主管理，初始化示例见 [README](../README.md)。工厂只豁免一次受认证的 `GET admin/serverinfo` 元数据读取，然后检查版本和总开关；初始化遇到版本未知或总开关关闭，可能已经发送这一次元数据读取，但不会发送业务请求。也可以使用已有的真实 serverinfo 快照自行构造 `KeycloakCapabilityPolicy` 和 `KeycloakFeatureManagementPolicy`，放入 `KeycloakAdminClientOptions.RequestPolicy`，避免重复读取。

路线仍由 `support-policy.json` 的 `route` 或 `KEYCLOAK_ADMIN_API_ROUTE` 明确声明；精确版本、preview/experimental 和静态禁用集合的环境变量见 [能力策略](capability-policy.md)。FeatureManagement 使用宿主配置提供方处理环境变量；如启用 `AddEnvironmentVariables()`，示例配置中总开关的覆盖键为 `feature_management__feature_flags__0__enabled`，Organizations 为 `...__2__enabled`。这些数字对应示例数组位置，重新排序后必须同步更新；不要把数组环境覆盖与支持策略的稳定能力 ID 禁用集合混淆。优先使用宿主已有的配置发布和刷新机制。

## 按需接入 Application Insights

仅需要开关评估遥测的托管宿主安装 `Keycloak.Admin.Sdk.FeatureManagement.ApplicationInsights`。必须同时满足三个条件：

1. 宿主显式调用 `AddKeycloakApplicationInsightsTelemetry(enabled: true)`；省略参数默认 false，不注册 publisher。
2. 对要记录的 feature 配置 `"telemetry": { "enabled": true }`，使用 Microsoft 的 `feature_management` schema。
3. 宿主注册 `TelemetryClient`，启动并停止注册的 `IHostedService`，管理遥测配置及发送生命周期。

注册示例（在构建 ServiceProvider/Host 之前）：

```csharp
using Keycloak.Admin.Sdk.FeatureManagement.ApplicationInsights;
using Microsoft.ApplicationInsights;
using Microsoft.ApplicationInsights.Extensibility;
using Microsoft.FeatureManagement;

bool enabled = bool.TryParse(configuration["KeycloakTelemetry:ApplicationInsightsEnabled"], out var value) && value;
var features = services.AddFeatureManagement();
features.AddKeycloakApplicationInsightsTelemetry(enabled);

// 若宿主已有 Application Insights 集成，复用它提供的 TelemetryClient。
// 否则在 enabled 时显式创建并注册；连接字符串从宿主密钥配置读取。
using var telemetry = enabled ? new TelemetryConfiguration
{
    ConnectionString = Environment.GetEnvironmentVariable("APPLICATIONINSIGHTS_CONNECTION_STRING")
        ?? throw new InvalidOperationException("Missing Application Insights connection string")
} : null;
if (telemetry is not null) services.AddSingleton(new TelemetryClient(telemetry));
```

Generic Host / ASP.NET Core 会启动已注册的 hosted services。直接使用 ServiceProvider 的控制台宿主，需要自行对 `GetServices<IHostedService>()` 调用 `StartAsync` / `StopAsync`，关闭前调用 `TelemetryClient.FlushAsync`，最后释放配置。应只注册一次 publisher。

扩展使用微软官方的 `FeatureEvaluation` publisher，监听宿主的 `Microsoft.FeatureManagement` ActivitySource，因此宿主其他启用遥测的 feature 也可能产生事件。适配器不附加 Keycloak URL、realm、用户、token、secret 或请求正文，不注册请求/依赖自动采集。宿主自己的 targeting、telemetry metadata、initializer 与采样仍由宿主负责。目录拒绝发生在 FeatureManager 之前，不生成 feature evaluation；该遥测不能代表业务请求成功、授权成功或接口验收证据。

当前已验证默认关闭、仅启用 publisher、仅启用 flag telemetry 均不产生事件；两者同时开启时，实际官方 publisher 向测试内存通道发出总开关及目标 feature 的评估事件。本次没有配置 Azure 账号或向 Application Insights 云端投递，不宣称远端 ingestion 已验收。

微软参考：[配置、生命周期与遥测](https://learn.microsoft.com/en-us/azure/azure-app-configuration/feature-management-dotnet-reference)，[4.8.0 标准引擎](https://www.nuget.org/packages/Microsoft.FeatureManagement/4.8.0)，[4.8.0 AI 适配器](https://www.nuget.org/packages/Microsoft.FeatureManagement.Telemetry.ApplicationInsights/4.8.0)。

## 验证入口

`dotnet run --file tools/Verify.cs -- --native-container` 执行托管单测、独立覆盖率门槛、全部扩展打包、核心包零依赖检查及核心/能力策略的严格 Native AOT 运行。新增两个扩展的方法、行、分支门槛各为 100%。

`dotnet run --file tools/Test-AllAdminRoutes.cs -- --update-docs` 在本机真实 Keycloak 26.8.1 + PostgreSQL 18.0 上重跑两路线、两模式。托管入口使用真实 FeatureManager 执行 478/492 项业务验收，并验证动态开关控制创建、读取与删除的实际持久化结果；原生入口编译时排除两个托管扩展。manifest 分别记录 `microsoft-4.8.0` 与 `not-loaded-native-aot`，门禁核验两种边界，防止混报。
