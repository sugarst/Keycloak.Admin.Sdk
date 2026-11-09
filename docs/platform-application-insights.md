# Microsoft FeatureManagement 与可选 Application Insights

Platform 使用 Microsoft.FeatureManagement 4.8.0 和 Microsoft.FeatureManagement.Telemetry.ApplicationInsights 4.8.0，后者通过 NuGet 引入 Application Insights SDK。自写 `/v2/track` HTTP、JSON envelope、聚合计数与 FlushAsync 实现已移除；不再维护第二套发送协议。不新增独立 SDK 包，所有适配都位于 Platform。

## 与原轻量实现的区别

| 项目 | 原轻量实现 | 当前微软包方案 |
| --- | --- | --- |
| 开关引擎 | 仅布尔快照 | 保留快照模式；另提供微软引擎模式及其过滤器、动态配置、作用域快照 |
| 事件 | 自定义 KeycloakSdk.FeatureEvaluation 聚合次数 | 官方 FeatureEvaluation 逐次评估事件，可携带配置元数据及宿主 targeting 上下文 |
| 投递 | 自写 HTTP，失败不重试 | 官方 TelemetryClient/channel 管理；可靠性取决于宿主选择的 channel 与配置 |
| 配置与扩展 | 自行解析连接字符串，只支持 ikey | 微软 SDK 解析及宿主既有 Application Insights 配置；认证、采样、持久化等按对应 SDK/channel 接入 |
| 开关 | 单个 Enabled | 发布器显式启用 + 每个 feature 的 telemetry.enabled |
| AOT | 曾在 Linux 原生实测 | Platform 为 Managed，IsAotCompatible=false；主包/Protocols AOT 独立保留 |

Microsoft.FeatureManagement.AspNetCore 提供路由/MVC 等集成，普通开关和评估遥测不需要它，因此 Platform 不引入 ASP.NET Core 包。官方遥测适配器 4.8.0 的 NuGet 依赖使用 Application Insights 2.x 基线；本项目不额外强升至 3.x，避免混用不兼容的 SDK 主版本。宿主升级整套 SDK 时需要独立验证。

## 可选接入

完整代码见 [Platform README](../src/Keycloak.Admin.Sdk.Platform/README.md#microsoft-开关与可选-application-insights)。[完整配置示例](../contracts/platform-application-insights.example.json) 包含全部 66 项 SDK 开关和默认关闭的遥测配置。把配置接入宿主的 IConfiguration；不需要订阅 Azure App Configuration 云服务。

1. `services.AddFeatureManagement()` 注册微软引擎。
2. 只有明确启用时，注册宿主管理的 `TelemetryClient` / `TelemetryConfiguration`，调用 `.AddKeycloakApplicationInsightsTelemetry(enabled: true)`。
3. 对需要采集的开关设置 `telemetry.enabled=true`。未启用 publisher 或未开启该项时不投递评估事件。
4. 使用 `KeycloakPlatformOptions.FeatureManager`，不同时传 `Flags`。启动时要求全部 SDK 开关已定义，允许其他应用开关。版本、阶段、运行环境及晋升策略依然先于宿主开关执行。
5. 启动 Generic Host 的 hosted services，让官方 publisher 开始监听；停机时按宿主 SDK/channel 约定刷新和释放。Platform 不创建私有服务容器或后台发送器。

快照模式 `Flags` / `KeycloakPlatformGate.Replace` 仍可用，但不经过微软引擎，不产生微软 FeatureEvaluation 遥测。微软 manager 模式由配置提供方负责刷新；普通 manager 不保证多个读取来自同一配置代。需要请求一致性时使用作用域内的 `IVariantFeatureManagerSnapshot`，Platform host 与它使用相同的作用域生命周期。

本包不会自动注册请求/依赖/异常采集，不主动添加用户、realm、业务 URL 或 token。微软 publisher 会使用宿主提供的 feature metadata、当前 Activity 和 targeting 信息；这些信息的隐私控制由宿主负责。本扩展的关闭只影响其注册，不会关闭宿主已经独立注册的 Application Insights 或其他 publisher。

## 事件查询

```kusto
customEvents
| where name == "FeatureEvaluation"
| project timestamp, customDimensions
```

事件维度遵循微软 FeatureEvaluation schema，查询可以按实际输出的 FeatureName、Enabled 等字段展开。过滤器失败按微软引擎语义向上传播，业务调用不会绕过能力门禁；不承诺把任意宿主遥测 channel 或 initializer 的异常静默吞掉。

## 验证边界

单元测试通过微软真实引擎与官方 publisher，将事件送入内存 ITelemetryChannel，检查 publisher/per-flag 双重 opt-in、Admin 与协议链、配置刷新、关闭后零业务 HTTP、缺失目录、过滤器失败和取消。本地测试不代表 Azure 云端投递已实测。

原生 smoke 不再引用 Platform。原生集成夹具只引用主包/Protocols，并使用核心 KeycloakFeatureSnapshotGate，证据标识 core-snapshot-v1 / core-snapshot；不能据此宣称 Platform 支持 AOT。源码和证据语义改变后的真实业务证据已重新生成，历史结果不代替当前输入。

本次验证：解决方案 Release 构建零警告、零错误；核心 587/587、协议 105/105、Hosting 14/14，共 706 项通过。15 项核心覆盖率门禁全通过，Platform 源码方法/行/分支及协议源码行/分支均为 100%；四包 nuspec 依赖和默认关闭的完整 66 项配置示例校验通过。排除 Platform 后的主包/Protocols `linux-musl-x64` Native AOT 本地包消费、发布与执行通过；原生集成夹具和真实 Keycloak 业务验收均已通过：v2 两种运行时各 478/478，v1 各 492/492；Managed 流程另外实际执行微软开关创建/删除、配置刷新、协议关闭及官方本地遥测事件检查。每条路线 14 项负向控制通过，完整 Release.cs --bootstrap 发布候选门禁通过。Azure 云端投递仍未纳入本地验收。

官方依据：[.NET Feature Management 遥测](https://learn.microsoft.com/en-us/azure/azure-app-configuration/feature-management-dotnet-reference#telemetry)、[官方适配器 4.8.0 依赖](https://www.nuget.org/packages/Microsoft.FeatureManagement.Telemetry.ApplicationInsights/4.8.0)、[Application Insights 3.x 迁移限制](https://github.com/microsoft/ApplicationInsights-dotnet/blob/main/BreakingChanges.md)。
