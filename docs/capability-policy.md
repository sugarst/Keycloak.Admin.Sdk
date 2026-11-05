# 版本能力与支持策略

`Keycloak.Admin.Sdk.Capabilities` 命名空间随主包提供。它检查精确版本、真实服务器功能与发布支持范围；业务资源和账户权限仍由 Keycloak 判断。

## 接入

`new KeycloakAdminClient(...)` 只提供底层传输。使用以下工厂安装支持策略；工厂先以同一认证源读取一次 `GET /admin/serverinfo`，冻结实际能力，初始化失败不返回客户端：

```csharp
using Keycloak.Admin.Sdk;
using Keycloak.Admin.Sdk.Capabilities;

var configuration = KeycloakSupportConfiguration.Parse(
    await File.ReadAllTextAsync("contracts/support-policy.example.json"),
    Environment.GetEnvironmentVariable);
var sdk = await KeycloakSupportedClient.CreateAsync(
    http, new Uri("https://keycloak.example.com/auth/"), tokens, configuration);
var users = await sdk.Users.GetUsersAsync("example", first: 0, max: 20);
```

HTTP 客户端和 token 的初始化/释放见 [认证说明](authentication-and-errors.md)。也可用可信 serverinfo 经 `KeycloakServerCapabilities.FromServerInfo` 构造 `KeycloakCapabilityPolicy`，放入 `KeycloakAdminClientOptions.RequestPolicy`；DI 的 `options.Client` 接受同一选项，避免在同步工厂阻塞网络初始化。

## 配置

[示例](../contracts/support-policy.example.json) 的所有字段必填；未知/重复字段、schema、路线或非法布尔值均拒绝。`Parse` 默认只读 JSON，显式传入环境变量读取器后才应用覆盖：

| 环境变量 | 含义 |
| --- | --- |
| `KEYCLOAK_ADMIN_SERVER_VERSION` | 精确目标版本 |
| `KEYCLOAK_ADMIN_API_ROUTE` | `fgap-v2-stable` / `fgap-v1-compat` |
| `KEYCLOAK_ADMIN_ALLOW_PREVIEW` | 允许进入预览阶段检查，默认 false |
| `KEYCLOAK_ADMIN_ALLOW_EXPERIMENTAL` | 允许进入实验阶段检查，默认 false |
| `KEYCLOAK_ADMIN_DISABLED_CAPABILITIES` | 逗号分隔的能力 ID，未知 ID 拒绝 |

配置与服务器快照不可变，可并发使用；服务器版本、feature 或路线变化后须重新初始化。部署启动配置由 [路线声明](../contracts/admin-api-routes.json) 管理，SDK 以真实 serverinfo 核验。能力 ID 见 [功能开关示例](../contracts/feature-management.example.json)；禁用 `KeycloakSdk.AdminApi` 阻断全部接口，其余 ID 阻断对应功能。

## 目录与开放条件

当前唯一目录 [capabilities.json](../contracts/capabilities.json) 通过 `KeycloakCapabilityCatalog.Current` 访问，记录版本、commit 及每个方法/路径的：

| 字段 | 含义 |
| --- | --- |
| `stage` | Stable / Preview / Experimental / Deprecated / Removed；指上游功能阶段 |
| `implementation` | wire 是否实现 |
| `support` | Supported / Compatibility / NotSupported |
| `verification` | Contract、Managed、NativeAot 证据位 |
| `requiredServerFeatures`、`routes` | 必需的真实功能与适用路线 |
| `evidence` | 证据位置 |

仅当以下条件全部满足才允许请求：

1. 目录、声明与真实服务器精确版本一致，URI 属于绑定服务器和上下文，且方法/路径已知。
2. 实际 FGAP 版本与路线一致，另一版本明确关闭。
3. 阶段允许、实现存在、SDK 支持，且契约/托管/AOT 验证完整。
4. 宿主未禁用能力，必需的服务端功能已知且启用。

预览/实验 allow 开关不能覆盖 NotSupported 或缺失证据；`FgapV1` 为 Deprecated/Compatibility，仅适用于 v1。当前支持数量及排除原因见 [支持路线](contracts/admin-api-routing.md) 和 [支持矩阵](contracts/admin-api-support-matrix.tsv)。

`KeycloakCapabilityPolicy.Evaluate` 可只读预判，返回原因、路线、版本及目录项；发送时拒绝抛出 `KeycloakCapabilityDeniedException`，不附加实际用户路径或请求内容。生成、原始、显式 JSON 元数据及流入口共用策略，在 token 获取和 HTTP 发送前执行；本地拒绝仍释放内容。目录外接口拒绝。每个逻辑请求只评估一次，401 重放复用结果。

## 维护与验证

`Generate-CapabilityCatalog.cs -- --check` 检查快照，`--seed` 仅登记契约证据，`--promote` 核验当前源码的真实验收后晋升。规则在 [capability-rules.json](../contracts/capability-rules.json)，与上游 `Profile.java` 核验。更换目标完整替换目录，流程见 [单基线升级](single-target-workflow.md)。

独立测试覆盖目录、配置、各拒绝原因、原始/流入口、内容释放和重放，并链接进 Native AOT 程序；真实验收确认本地拒绝未发送 HTTP。[覆盖率](contracts/test-coverage.md) 与 [业务证据](contracts/full-live-acceptance.md) 分别维护结果。托管宿主可叠加 [FeatureManagement](feature-management.md)，开关只收紧目录结果。
