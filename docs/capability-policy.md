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

配置与服务器快照不可变，可并发使用；服务器版本、feature 或路线变化后须重新初始化。部署启动配置由 [路线声明](../contracts/admin-api-routes.json) 管理，SDK 以真实 serverinfo 核验。能力 ID 见 [平台开关示例](../contracts/platform-feature-flags.example.json)；禁用 `KeycloakSdk.AdminApi` 阻断全部接口，其余 ID 阻断对应功能。

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

## 按运行环境开放（schema 2）

旧构造函数和 schema 1 保持原来的严格行为：同一路线必须同时具备托管和 Native AOT 证据。新目录使用 schema 2，旧调用无需迁移。

新宿主可选择 [托管配置](../contracts/support-policy.managed.example.json) 或 [原生配置](../contracts/support-policy.native-aot.example.json)，也可使用新的构造重载：

```csharp
var support = new KeycloakSupportConfiguration(
    KeycloakTarget.Version, KeycloakRuntimeProfile.Managed);
```

| runtimeProfile | 要求 |
| --- | --- |
| Managed | 当前 FGAP 路线的 Contract + Managed 业务证据 |
| NativeAot | 当前路线、当前 RID 的 Contract + NativeAot 发布与业务证据 |
| Portable | 当前路线的 Managed 和指定 Native AOT RID 证据均完整 |

Managed 的 `runtimeIdentifier` 必须为 null；其他模式可指定 RID，null 时取当前进程 RID。schema 2 在请求前检查运行模式和原生 RID，不能在原生程序中选择 Managed 来跳过原生验证。只有 linux-musl-x64 证据不能声明 win-x64 原生支持。

schema 2 的 `previewCapabilities`、`experimentalCapabilities` 是逐功能许可集合，默认均为空；不会使用 schema 1 的全局 allow 环境变量。与目录中的上游阶段不匹配、未知或重复 ID 均拒绝。新增显式环境覆盖：`KEYCLOAK_ADMIN_RUNTIME_PROFILE`、`KEYCLOAK_ADMIN_RUNTIME_IDENTIFIER`、`KEYCLOAK_ADMIN_PREVIEW_CAPABILITIES`、`KEYCLOAK_ADMIN_EXPERIMENTAL_CAPABILITIES`，后两个使用逗号分隔。

```csharp
var validationSupport = new KeycloakSupportConfiguration(
    KeycloakTarget.Version, KeycloakRuntimeProfile.Managed,
    experimentalCapabilities: ["KeycloakSdk.ClientTypes"]);
```

许可只允许考虑该能力，仍要求该操作和环境已晋升、真实服务端功能启用以及宿主开关打开。Deprecated 仍走明确的兼容路线，Removed 永远拒绝。

目录根部的 `verificationProfiles` 保存每次验收的路线、运行模式、RID、源码指纹和不可变证据文件及其 SHA256；每个端点的 `supportProfiles` 只引用真正通过验证的组合。`support` 和 `verification` 是汇总信息，不代表所有环境均已支持。首次迁移保留既有历史验收的原始指纹，不将其冒充当前源码的新验收。

上游 Stage 来源于固定版本源码，与 SDK 验证独立。后续 Keycloak 版本转为 Stable 时，必须升级精确目标、审阅契约并重新验收，不能靠开关修改阶段或继承旧目标的成功证据。

## 非 Stable 功能的验证与晋升

完整的职责分工、当前缺口、逐步操作和失败处理见 [非 Stable 功能流程](non-stable-feature-lifecycle.md)。验证和晋升由独立工具完成；平台开关面负责完成这些步骤之后的灰度开放和关闭。

[验证计划](../contracts/feature-validation-plans.json) 独立于 FGAP 路线和运行模式，声明功能、阶段、必需服务端功能和操作白名单。当前提供 Client Types 的真实查询、写入、持久化读取和替换删除工作流。新增其他功能须先添加经过审阅的业务工作流；仅增加计划不会执行未经实现的测试。

```shell
# 隔离容器上的候选验证，不绕过生产客户端的支持策略。
dotnet run --file tools/Test-Feature.cs -- --feature=client-types
# 只晋升该证据覆盖的操作、运行环境和路线。
dotnet run --file tools/Check-FeatureAcceptance.cs -- --evidence=artifacts/feature-validation/client-types/fgap-v2-stable-managed-candidate.json --promote
# 使用晋升后的目录复验，并验证关闭开关时没有业务 HTTP 请求。
dotnet run --file tools/Test-Feature.cs -- --feature=client-types --guarded
dotnet run --file tools/Check-FeatureAcceptance.cs -- --supported
```

原生验证加 `--native-aot`，v1 路线加 `--v1`；Native AOT 会实际 publish 并执行 linux-musl-x64 程序。候选证明不等同于最终受策略保护的验收；`--promote` 和 `--guarded` 不能合并。工具拒绝缺失、重复、非成功、无业务证明、错误阶段/版本/路线/运行模式、未知服务端功能和过期指纹。

候选采用 `ValidationFingerprint`，覆盖实现、测试工作流、工具、配置和契约输入，单独排除生成的 `contracts/capabilities.json`，避免晋升目录使自己的输入证据立即失效。集成程序在构建时嵌入输入指纹与目录 SHA256，运行时拒绝使用旧程序验证新源码；最终受保护验收还必须匹配当前目录 SHA256。发布的完整源码指纹仍包含目录。失败运行会清除其旧结果，不能复用先前同名文件。

晋升后，原始证据按内容 SHA256 保存到 `docs/contracts/capability-evidence/`。正式路线继续排除非 Stable 功能；`Release.cs` 另外通过 `Test-SupportedFeatures.cs` 对所有已支持的非 Stable 组合执行隔离复验，任一组合缺失或失败即拒绝候选。它不会把某个环境的成功扩散到另一个环境，也不会自动发布包。

`KeycloakCapabilityPolicy.Evaluate` 可只读预判，返回原因、路线、版本及目录项；发送时拒绝抛出 `KeycloakCapabilityDeniedException`，不附加实际用户路径或请求内容。生成、原始、显式 JSON 元数据及流入口共用策略，在 token 获取和 HTTP 发送前执行；本地拒绝仍释放内容。目录外接口拒绝。每个逻辑请求只评估一次，401 重放复用结果。

## 维护与验证

`Generate-CapabilityCatalog.cs -- --check` 检查快照，`--seed` 仅登记契约证据，`--promote` 核验当前源码的真实验收后晋升。规则在 [capability-rules.json](../contracts/capability-rules.json)，与上游 `Profile.java` 核验。更换目标完整替换目录，流程见 [单基线升级](single-target-workflow.md)。

独立测试覆盖目录、配置、各拒绝原因、原始/流入口、内容释放和重放，并链接进 Native AOT 程序；真实验收确认本地拒绝未发送 HTTP。[覆盖率](contracts/test-coverage.md) 与 [业务证据](contracts/full-live-acceptance.md) 分别维护结果。托管与 Native AOT 宿主可叠加 [平台开关面](platform-feature-gate.md)，共享同一份快照门禁，开关只收紧目录结果。
