# Keycloak.Admin.Sdk.Platform

Managed 宿主的统一开关面：Admin API 与应用协议共享同一次 `serverinfo` 引导、同一能力目录和 gate。直接依赖 Protocols、Microsoft.FeatureManagement 4.8.0 和 Microsoft.FeatureManagement.Telemetry.ApplicationInsights 4.8.0。主包通过 Protocols 传递引用。

本包不声明 Native AOT 支持，即使关闭遥测也不作 AOT 兼容承诺。主包与 Protocols 仍保留各自的 Native AOT 支持。

## 快照开关

```csharp
using Keycloak.Admin.Sdk.Capabilities;
using Keycloak.Admin.Sdk.Platform;
using Keycloak.Admin.Sdk.Protocols;

var flags = new KeycloakFeatureFlagCatalog().All.ToDictionary(id => id, _ => true);
flags["KeycloakSdk.Organizations"] = false;
var host = await KeycloakPlatformHost.CreateAsync(http, server, tokens, new()
{
    Support = new KeycloakSupportConfiguration(KeycloakTarget.Version, KeycloakRuntimeProfile.Managed),
    ProtocolSupport = new ApplicationSupportConfiguration(KeycloakRuntimeProfile.Managed),
    Flags = flags
}, ct);
var users = await host.Admin.Users.GetUsersAsync("master", cancellationToken: ct);
var transport = host.CreateProtocolTransport(http, "master");
```

`KeycloakPlatformGate.Replace((KeycloakFeatureSnapshotGate)host.Gate, flags, host.Catalog)` 校验并原子替换完整快照；同一逻辑请求读取同代快照。目录中共 66 项开关，缺失或未知项在创建或替换时被拒绝。两个总闸为 `KeycloakSdk.AdminApi` 和 `KeycloakSdk.Protocols`。

## Microsoft 开关与可选 Application Insights

```csharp
using Microsoft.ApplicationInsights;
using Microsoft.ApplicationInsights.Extensibility;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.FeatureManagement;
using Keycloak.Admin.Sdk.Capabilities;
using Keycloak.Admin.Sdk.Platform;
using Keycloak.Admin.Sdk.Protocols;

var builder = Host.CreateApplicationBuilder(args);
// 将完整示例的 feature_management 配置放进宿主 appsettings.json。
bool telemetryEnabled = builder.Configuration.GetValue<bool>("ApplicationInsights:Enabled");
if (telemetryEnabled)
{
    builder.Services.AddSingleton(sp =>
    {
        var configuration = Microsoft.ApplicationInsights.Extensibility.TelemetryConfiguration.CreateDefault();
        configuration.ConnectionString = builder.Configuration["ApplicationInsights:ConnectionString"]
            ?? throw new InvalidOperationException("Application Insights connection string is required.");
        foreach (var initializer in sp.GetServices<Microsoft.ApplicationInsights.Extensibility.ITelemetryInitializer>())
            configuration.TelemetryInitializers.Add(initializer);
        return configuration;
    });
    builder.Services.AddSingleton(sp => new TelemetryClient(
        sp.GetRequiredService<Microsoft.ApplicationInsights.Extensibility.TelemetryConfiguration>()));
}
builder.Services.AddFeatureManagement()
    .AddKeycloakApplicationInsightsTelemetry(enabled: telemetryEnabled);
using var app = builder.Build();
await app.StartAsync(ct); // 启动官方遥测 publisher 的 IHostedService。

var host = await KeycloakPlatformHost.CreateAsync(http, server, tokens, new()
{
    Support = new KeycloakSupportConfiguration(KeycloakTarget.Version, KeycloakRuntimeProfile.Managed),
    ProtocolSupport = new ApplicationSupportConfiguration(KeycloakRuntimeProfile.Managed),
    FeatureManager = app.Services.GetRequiredService<IVariantFeatureManager>()
}, ct);
// 使用 host.Admin 和 host.CreateProtocolTransport(...)。
if (telemetryEnabled) await app.Services.GetRequiredService<TelemetryClient>().FlushAsync(ct);
await app.StopAsync(ct);
```

每个 SDK 开关还须配置 `telemetry.enabled=true` 才会发送标准 `FeatureEvaluation` 事件。默认注册参数为 false，示例配置的总开关及各项遥测也全部为 false。不启用时不要求注册 TelemetryClient 或连接字符串。Flags 快照模式不会经过 Microsoft 引擎，因此不发布微软评估事件；选择 `FeatureManager` 模式才能使用该遥测。`Flags` 与 `FeatureManager` 不能同时提供。

Microsoft 模式启动前检查所有 66 项 SDK 开关均已定义，允许配置中存在其他应用开关；后续缺失开关默认关闭，过滤器错误会向调用方传播并阻止业务 HTTP。普通 manager 随配置动态评估；需要作用域内一致性时，由宿主使用 `IVariantFeatureManagerSnapshot` 并匹配作用域生命周期，不能将 scoped snapshot 保存进单例 host。

本包不自动注册请求/依赖追踪，不配置 Azure App Configuration 云连接，不采集 realm、URL 或凭据。SDK channel 的缓冲、发送、刷新及宿主选配的采样、认证和存储设置由微软 SDK 与宿主管理。无需安装 Microsoft.FeatureManagement.AspNetCore，除非宿主需要其路由、MVC 等扩展。

配置示例：[platform-application-insights.example.json](../../contracts/platform-application-insights.example.json)。接入、对比与边界：[遥测说明](../../docs/platform-application-insights.md)。
