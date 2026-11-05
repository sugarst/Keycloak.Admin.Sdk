# 版本能力目录、支持状态与统一开放判断

`Keycloak.Admin.Sdk.Capabilities` 是独立的能力策略扩展。核心 SDK 保持零运行时 NuGet 依赖；能力扩展只依赖核心 SDK 和 .NET BCL，不引入 FeatureManagement、Application Insights、ASP.NET Core 或配置绑定包。FeatureManagement 与 Application Insights 已通过单独的托管扩展提供，详见 [接入指南](feature-management.md)。

## 接入方式

已有 `new KeycloakAdminClient(...)` 保留原有 wire 传输行为：它不是“已受支持策略保护”的客户端。需要支持范围约束时，显式使用 `KeycloakSupportedClient.CreateAsync`。该入口先用同一服务器/认证源读取受保护的 `GET /admin/serverinfo`，冻结实际能力，再为后续所有请求安装统一策略。初始化失败不返回一个无策略客户端。

```csharp
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Capabilities;

// http 和 tokens 的创建/释放由宿主负责；HttpClient 应关闭自动重定向。
var configuration = KeycloakSupportConfiguration.Parse(
    await File.ReadAllTextAsync("contracts/support-policy.example.json"),
    Environment.GetEnvironmentVariable);

var sdk = await KeycloakSupportedClient.CreateAsync(
    http, new Uri("https://keycloak.example.com/auth/"), tokens, configuration);
var users = await sdk.Users.GetUsersAsync("example", first: 0, max: 20);
```

也可以自行获取可信的真实 serverinfo，用 `KeycloakServerCapabilities.FromServerInfo` 解析，再构造 `KeycloakCapabilityPolicy`，通过 `KeycloakAdminClientOptions.RequestPolicy` 安装。现有 DI 扩展的 `options.Client` 可传入同一客户端选项；不要在同步 DI 工厂中阻塞等待网络初始化。

## 声明与环境覆盖

[示例配置](../contracts/support-policy.example.json) 使用独立的 schemaVersion，不把 SDK 支持声明等同于服务端启动参数。`Parse` 默认只读提供的 JSON；显式传入 `Environment.GetEnvironmentVariable` 才读取下列覆盖值：

| 环境变量 | 含义 |
| --- | --- |
| `KEYCLOAK_ADMIN_SERVER_VERSION` | 精确的目标版本；当前只有 26.8.1 快照 |
| `KEYCLOAK_ADMIN_API_ROUTE` | `fgap-v2-stable` 或 `fgap-v1-compat` |
| `KEYCLOAK_ADMIN_ALLOW_PREVIEW` | 是否允许进入预览阶段检查，默认 false |
| `KEYCLOAK_ADMIN_ALLOW_EXPERIMENTAL` | 是否允许进入实验阶段检查，默认 false |
| `KEYCLOAK_ADMIN_DISABLED_CAPABILITIES` | 逗号分隔的能力 ID；未知 ID 拒绝配置 |

未知/重复 JSON 字段、未知路线、未知 schema、非法布尔覆盖值均拒绝。JSON 字段需完整提供。现有部署/验收的 [admin-api-routes.json](../contracts/admin-api-routes.json) 继续决定 Keycloak 启动配置；SDK 使用真实 serverinfo 再核验，不通过声明猜测服务端能力。

配置、服务端快照和目录均不可变。改变服务器版本、功能开关或 FGAP 路线后，重新初始化客户端；不会在一个执行流程中随机切换 FGAP 版本。实例可并发使用；一次逻辑请求的策略只评估一次，401 安全重放不会重新选择开放状态。

## 四个独立维度

[26.8.1 目录](../contracts/capabilities.json) 为全部 520 个方法/路径保存以下属性：

| 属性 | 含义 |
| --- | --- |
| `stage` | 所属上游功能的 Stable、Preview、Experimental、Deprecated、Removed；不等同于单个 Java 方法的 @Deprecated 注解 |
| `implementation` | SDK wire 实现是否存在；Implemented 不等于正式支持 |
| `support` | Supported、Compatibility、NotSupported |
| `verification` | Contract、Managed、NativeAot 证据位；保留历史验收状态，不能由宿主开关修改 |
| `requiredServerFeatures` | 服务端真实 feature 名称；未知与关闭有不同拒绝原因 |
| `routes` | 适用路线，独立于 Compatibility 支持状态；26.8.1 的旧管理权限仅适用于 v1 |
| `evidence` | 对应方法/路径的证据位置 |

目录还保存精确的 Keycloak 版本和发布源码 commit。业务证明见 [全功能验收](contracts/full-live-acceptance.md)。默认 v2 正式范围为 478 项；v1 兼容范围为 492 项。28 项预览/实验接口只有契约测试，均为 NotSupported；即使把两个 allow 开关改为 true，也不能绕过未支持/未验证状态。

稳定的能力 ID 包括 `KeycloakSdk.AdminApi`、`KeycloakSdk.Authorization`、`KeycloakSdk.Organizations`、`KeycloakSdk.Workflows`、`KeycloakSdk.AdminUi`、`KeycloakSdk.ClientPolicies`、`KeycloakSdk.Impersonation`、`KeycloakSdk.FgapV1`、`KeycloakSdk.Oid4vcVci`、`KeycloakSdk.Ssf`、`KeycloakSdk.ClientTypes`。其中 FgapV1 为 Deprecated/Compatibility；Workflows 在 26.8.1 为 Stable。宿主关闭 AdminApi 时阻断整个 Admin API，其余 ID 关闭对应功能。

## 统一开放判断

所有条件同时成立才允许请求：

1. 精确版本存在目录，且与真实服务器版本一致；26.8.2 不自动继承 26.8.1 的验证。
2. 目标 URI 属于绑定的服务器及上下文路径，方法/路径对应目录中的已知接口。
3. 实际启用的 FGAP 版本与声明一致，另一版本明确处于关闭状态。
4. 阶段允许、SDK 支持、wire 已实现，且契约/托管/AOT 三种验证状态完整。
5. 宿主没有关闭该能力，且接口必需的服务端功能已知且实际启用。

可用 `KeycloakCapabilityPolicy.Evaluate` 做只读预判。结果包含 `Reason`、路线、目标版本和目录项；拒绝请求抛出 `KeycloakCapabilityDeniedException`，包含同一结构化结果，不写入实际用户路径、token 或请求正文。

核心的 `IKeycloakAdminRequestPolicy` 在最终 URI 构造后、token 获取及 HTTP 发送前执行。生成方法、原始缓冲请求、显式 JsonTypeInfo 请求与流请求共用同一入口；本地拒绝也按原契约释放请求内容。未知原始/vendor 接口在受策略客户端中拒绝，不作为默认逃逸路径。业务资源是否存在及当前账户是否获授权，仍由 Keycloak 判断；能力策略不替代鉴权。

## 升级与晋升流程

每个 SDK 构建只支持基线声明的一个目标版本，活跃目录是 `contracts/capabilities.json`，通过 `KeycloakCapabilityCatalog.Current` 访问。升级时完整替换该目录，旧版本通过历史 Git tag 和包追溯。升级需比较发布源码路由、请求/响应、功能阶段、服务端 feature 及 FGAP 路线；上游转正式仍需完成独立单测、真实托管/AOT 验收才能晋升 SDK 支持。

生成入口的 `--check` 核验当前规则一致性，`--seed` 只登记契约验证，`--promote` 依据当前源码的真实验收晋升；规则位于 `contracts/capability-rules.json`，并核验上游源码阶段。完整替换与首次验收流程见 [单基线流程](single-target-workflow.md)。

可选的 `Keycloak.Admin.Sdk.FeatureManagement` 现已实现 `IKeycloakAdminRequestPolicy`：先调用目录策略，再通过 `IVariantFeatureManager` 检查总开关及能力开关，以 AND 组合收紧结果。Application Insights 使用独立可选包，默认关闭；遥测不作为开放判断或业务验收证据。两者仅面向托管宿主，不要求 AOT，不进入核心或本能力包的依赖。配置及范围见 [接入指南](feature-management.md)。

## 验证

独立测试覆盖全 520 项目录与两条路线的允许数量、JSON/环境覆盖、未知版本/接口/能力、版本和路线不匹配、未支持阶段、缺失验证、真实 feature 未知/关闭、跨服务器/上下文请求、原始路径、流、请求内容释放及重放决策一致性。测试也编译进无测试框架依赖的 Native AOT 程序。

新能力扩展的方法、行和分支覆盖率门槛均为 100%，独立于核心已有门槛。真实容器全量入口现在通过受策略客户端执行 478/492 项业务验证，并另外确认宿主关闭、未知版本/接口、预览/实验开关不能产生 HTTP 请求。实际结果见 [覆盖率](contracts/test-coverage.md) 和 [真实证据](contracts/full-live-acceptance.md)。
