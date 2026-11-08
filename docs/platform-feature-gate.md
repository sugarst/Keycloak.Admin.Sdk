# 平台开关面

`Keycloak.Admin.Sdk.Platform` 提供一个宿主统一开关面，用同一个 `IKeycloakFeatureGate` 实例同时控制 Admin API 与应用协议链。它只通过两条 `ProjectReference` 引用主包与 Protocols，零 NuGet 依赖，并声明 `IsAotCompatible=true`；Admin 链与协议链共享一次受认证的 `serverinfo` 引导、同一份开关目录和同一个 gate 实例，托管与 Native AOT 走同一代码路径。包结构与依赖边界见 [架构与契约来源](architecture.md)。

## 定位

| 公开类型 | 职责 |
| --- | --- |
| `KeycloakPlatformOptions` | 统一配置：支持配置、协议支持配置、开关快照、可选自定义目录及 401 恢复开关 |
| `KeycloakPlatformHost` | 一次 `serverinfo` 引导得到 `KeycloakServerCapabilities`；产出 Admin client 与协议 transport，二者共享同一 gate 实例 |
| `KeycloakFeatureFlagCatalog` | 完整开关目录，启动时校验配置完整性（fail-closed） |
| `KeycloakPlatformGate` | `KeycloakFeatureSnapshotGate` 的创建与原子替换包装，沿用快照语义 |

`KeycloakPlatformHost.CreateAsync` 返回的实例包含 `Admin`、`ServerCapabilities`、`Gate`、`Catalog` 四个属性，并提供 `CreateProtocolTransport(...)` 方法。本包只负责最终开放与关闭：不执行业务验证、不生成晋升证据、不修改支持目录或上游阶段，也不替宿主打开开关。能力策略、阶段许可与逐环境晋升仍由 [能力策略](capability-policy.md) 和 [非 Stable 功能流程](non-stable-feature-lifecycle.md) 负责。

## 安装

```shell
dotnet add package Keycloak.Admin.Sdk.Platform
```

引用本包会自动引入 `Keycloak.Admin.Sdk` 与 `Keycloak.Admin.Sdk.Protocols`。ASP.NET Core 宿主集成仍按需单独引用 `Keycloak.Admin.Sdk.Hosting`（该包不声明 Native AOT 支持）。

## 接入

完整开关示例见 [platform-feature-flags.example.json](../contracts/platform-feature-flags.example.json)；支持声明仍用 [support-policy.example.json](../contracts/support-policy.example.json) 的严格解析器，不要反射绑定为 Options。

```csharp
using Keycloak.Admin.Sdk.Capabilities;
using Keycloak.Admin.Sdk.Platform;
using Keycloak.Admin.Sdk.Protocols;

var flags = new KeycloakFeatureFlagCatalog().All.ToDictionary(id => id, _ => true);
flags["KeycloakSdk.Organizations"] = false;

var options = new KeycloakPlatformOptions
{
    Support = new KeycloakSupportConfiguration(
        KeycloakTarget.Version, KeycloakRuntimeProfile.Managed),
    ProtocolSupport = new ApplicationSupportConfiguration(KeycloakRuntimeProfile.Managed),
    Flags = flags
};

var host = await KeycloakPlatformHost.CreateAsync(http, server, tokens, options, ct);
var users = await host.Admin.Users.GetUsersAsync("master", cancellationToken: ct);
var transport = host.CreateProtocolTransport(http, "master");
```

`http`、`server`、`tokens` 由宿主管理，见 [认证说明](authentication-and-errors.md)。`CreateAsync` 仅执行一次受认证的 `admin/serverinfo` 读取，并在返回前对该元数据请求本身执行能力与开关检查，保证关闭总闸时引导请求同样被拒绝；后续业务请求都经过 `KeycloakFeatureGatePolicy`。`CreateProtocolTransport` 复用同一份 `KeycloakServerCapabilities` 与同一个 gate，不会重复引导。宿主拥有 HttpClient、token provider 以及全部用户与会话隔离。

## 开关目录与总闸

| 分类 | 数量 | 说明 |
| --- | --- | --- |
| 总闸 | 2 | `KeycloakSdk.AdminApi`、`KeycloakSdk.Protocols` |
| Admin 侧 `FeatureId` | 11 | 含 `KeycloakSdk.AdminApi`，逐端点收紧目录结果 |
| 协议侧开关 | 54 | `KeycloakSdk.Protocols.*`，对应 52 个应用能力族 |
| 合计 | 66 | 完整开关面，单一真源 |

两个总闸分别控制 Admin 链（`KeycloakSdk.AdminApi`）与协议链（`KeycloakSdk.Protocols`）；Admin 链还检查目标端点的 `FeatureId`，协议链检查对应的 `KeycloakSdk.Protocols.*`。协议侧开关与能力族的映射由 [application-capability-flags.json](../contracts/application-capability-flags.json) 单一真源维护，完整目录见 [feature-flag-catalog.json](../contracts/feature-flag-catalog.json)，由 [Generate-FeatureCatalog.cs](../tools/Generate-FeatureCatalog.cs) `--check` 与能力矩阵校验一致。

开关不能绕过阶段、支持、验证或 FGAP 路线：Flag 为 true 仍须满足能力策略的全部条件。所有请求入口在 token 获取和 HTTP 发送前检查，每个逻辑请求只评估一次，401 重放复用结果，下一次调用重新评估；配置变化不撤销已发送请求。

## fail-closed 校验

`KeycloakFeatureFlagCatalog.EnsureComplete` 在启动时校验宿主提供的开关集合：未知开关、缺失开关、重复或空 ID 都被拒绝，避免能力被静默关闭。`KeycloakPlatformGate.Create` 与 `KeycloakPlatformGate.Replace` 都先经过这一校验，校验失败不会生成或替换快照。宿主必须提供完整的 66 项开关集合，不能只提交关心的子集。

## 快照替换

开关保存在不可变的 `KeycloakFeatureSnapshotGate` 快照中。`KeycloakPlatformGate.Replace` 先校验再原子替换整份快照；失败替换不影响旧快照，一次逻辑请求中总开关与功能开关读取同一代快照。配置变化只影响后续请求，不改变上游阶段、支持目录或服务端 feature。配置文件、远端更新、取消令牌和提供方生命周期由宿主管理；若宿主仍要接入自定义特性管理引擎，自行实现主包的 `IKeycloakFeatureGate` 即可，SDK 不再打包适配器。

## AOT 兼容

包内不引入任何外部特性管理引擎、过滤器或反射配置绑定，`IsAotCompatible=true`，因此托管与 Native AOT 走同一份代码，不再有 managed / native-aot 分叉。真实验收的 `evidence.platformGate` 在两种模式统一为 `snapshot-v1`、`platformGateBusinessGuards` 为 true，首次 bootstrap 证据为 `not-loaded-bootstrap` 且业务守卫为 false。结果见 [真实验收](contracts/full-live-acceptance.md) 和 [覆盖率](contracts/test-coverage.md)，命令见 [测试与验证](testing.md)。

## 边界

- 不控制上游 `KC_FEATURES`：`serverinfo.features[]` 只读入并用于能力校验，启用或关闭服务端功能由部署层负责，见 [全能力扩展](full-platform-coverage.md)。
- 不提供遥测：不打包遥测适配器，不采集开关评估事件，也不注册请求或依赖自动采集；宿主如需观测自行订阅。
- 不合并两套总闸命名：统一的是同一 gate 实例与同一份开关目录，Admin 与协议各自的总闸保持独立。
- 不提供灰度人群、比例筛选或目标过滤器，SDK 只消费宿主给出的最终布尔结果。

本包不改变支持目录与上游阶段；非 Stable 功能仍须先完成逐环境验证与晋升，再由宿主决定灰度范围。
