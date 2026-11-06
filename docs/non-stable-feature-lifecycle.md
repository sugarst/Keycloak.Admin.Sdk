# 非 Stable 功能的验证、晋升与灰度

非 Stable 功能通过独立的业务验证获得 SDK 支持资格，再由 `Keycloak.Admin.Sdk.FeatureManagement` 决定最后的灰度开放和关闭。验证通过、晋升支持和打开开关是三个独立动作。

## 职责与晋升含义

| 责任方 | 输入与产出 |
| --- | --- |
| 上游阶段分类 | 从固定 Keycloak 版本源码确定 Stable / Preview / Experimental 等阶段 |
| 验证工具与业务工作流 | 按审阅后的计划执行隔离测试，产出带版本、输入指纹及操作证明的候选报告 |
| 晋升工具与支持目录 | 校验证据、归档原件，只给已验证操作的路线、运行模式和 RID 增加支持记录 |
| 能力策略 | 请求前检查精确版本、阶段许可、支持证据、运行环境、路线和真实服务器功能 |
| FeatureManagement | 在能力策略允许后，通过宿主配置、过滤器和刷新机制决定本次调用是否开放 |

这里的“晋升”指 **SDK 对指定环境和操作提供支持**。Experimental 功能通过验证后仍是 Experimental，Preview 功能仍是 Preview。上游转为 Stable 需要升级精确目标、审阅新版本并重新验收；不能通过晋升命令或 FeatureManagement 修改阶段。

FeatureManagement 不生成验证证据、不修改支持目录，也不自动开关 Keycloak 服务端功能。功能开关为 true 时，仍须满足能力策略的全部条件。Native AOT 宿主使用主包的快照门禁，职责同样限于最后的开放和关闭，见 [门禁接入](feature-management.md)。

## 当前落地范围

以 [支持目录](../contracts/capabilities.json) 为准，当前固定目标为 Keycloak 26.8.1：

| 功能 | 上游阶段 | 操作数 | SDK 验证与晋升状态 |
| --- | --- | --- | --- |
| Client Types | Experimental | 2 | 已有独立业务工作流；仅 Managed / FGAP v2 已晋升，默认开关关闭 |
| Shared Signals Framework（SSF） | Experimental | 19 | 已有 wire 实现和契约测试，尚缺专用业务验证计划与工作流，未晋升 |
| OID4VC VCI | Preview | 7 | 已有 wire 实现和契约测试，尚缺专用业务验证计划与工作流，未晋升 |

Client Types 的 Native AOT 候选验证不会自动赋予原生支持，v1 路线也不继承 v2 的结果。Deprecated 的 FGAP v1 接口继续走既有兼容路线，不作为 Preview / Experimental 功能晋升。

## 操作流程

### 1. 定义验证范围

在 [feature-validation-plans.json](../contracts/feature-validation-plans.json) 登记功能 ID、上游阶段、必需服务端功能和精确操作白名单，并在集成测试中实现对应的业务工作流。计划、实现和测试应一起审阅。

业务工作流须证明接口效果，包括适用的写入、读取、持久化检查、替换或删除，并在独立清理阶段移除测试资源。仅有 HTTP 2xx 或契约序列化测试不能作为晋升证明。未实现的计划由工具拒绝执行。

### 2. 执行候选验证

从仓库根目录运行：

```shell
dotnet run --file tools/Test-Feature.cs -- --feature=client-types
dotnet run --file tools/Check-FeatureAcceptance.cs -- --evidence=artifacts/feature-validation/client-types/fgap-v2-stable-managed-candidate.json
```

工具启动固定 digest 的临时 Keycloak 容器，只启用计划和路线声明所需功能。候选工作流直接验证尚未受 SDK 支持的操作，入口仅用于隔离测试；生产受支持客户端继续拒绝未晋升操作。该步骤只产出报告，**不改变支持目录和宿主开关**。

报告包含固定版本与上游 commit、验证输入指纹、实际服务端功能、运行模式、原生 RID、程序哈希和逐操作业务证明。源码、契约、配置或工作流改变后须重新验证；旧构建程序不能验证新输入。失败运行清除同名旧结果。

### 3. 审阅并晋升指定组合

审阅验证计划、业务证明和运行范围后，显式执行：

```shell
dotnet run --file tools/Check-FeatureAcceptance.cs -- --evidence=artifacts/feature-validation/client-types/fgap-v2-stable-managed-candidate.json --promote
```

此命令将原始证据按内容 SHA256 归档到 `docs/contracts/capability-evidence/`，更新 `contracts/capabilities.json` 中对应操作的 `supportProfiles`。晋升只覆盖报告中的目标版本、操作、FGAP 路线、运行模式及原生 RID；其他组合仍需各自验证。应审阅并一同提交计划、工作流、证据原件和目录变化。

晋升不修改 FeatureManagement 配置，也不修改 Preview / Experimental 阶段许可。候选报告不能充当最终受策略保护的验收结果。

### 4. 使用受支持客户端复验

```shell
dotnet run --file tools/Test-Feature.cs -- --feature=client-types --guarded
dotnet run --file tools/Check-FeatureAcceptance.cs -- --evidence=artifacts/feature-validation/client-types/fgap-v2-stable-managed-guarded.json --guarded
dotnet run --file tools/Check-FeatureAcceptance.cs -- --supported
```

复验使用晋升后的目录和真实宿主门禁。既检查开关打开时的业务效果，也检查关闭时业务请求在 token 获取和 HTTP 发送前被拒绝。最终报告必须匹配当前目录 SHA256，不能复用晋升前的报告。

原生验证加 `--native-aot`，v1 路线加 `--v1`；当前原生执行器实际发布并运行 linux-musl-x64 程序。例如原生 v2 的候选文件为 `fgap-v2-stable-native-aot-linux-musl-x64-candidate.json`，后续命令须选择对应报告。

`Test-SupportedFeatures.cs` 会重新验证所有已晋升的非 Stable 组合；`Release.cs` 在既有正式路线验收之外运行此门禁。复验失败即阻止发布候选，目录改动仍留在工作区供修正。修复后重新走候选验证、晋升和受保护复验。

### 5. 由宿主灰度开放和关闭

部署通过验证的 SDK 后，宿主先选择实际运行环境，并逐功能声明阶段许可，例如：

```csharp
var support = new KeycloakSupportConfiguration(
    KeycloakTarget.Version, KeycloakRuntimeProfile.Managed,
    experimentalCapabilities: ["KeycloakSdk.ClientTypes"]);
```

再通过 [FeatureManagement 接入](feature-management.md#接入) 安装支持策略和宿主门禁。`KeycloakSdk.AdminApi` 总开关及 `KeycloakSdk.ClientTypes` 功能开关必须同时允许；非 Stable 功能的示例默认关闭。灰度人群、比例及配置刷新由宿主管理，SDK 消费最终布尔结果。

宿主可以按“关闭 → 小范围开放 → 扩大范围 → 全量开放”推进，并随时关闭功能开关。关闭只影响后续逻辑请求，不撤销已发送请求，也不删除已有验证证据；重新开放仍须通过能力策略。紧急关闭优先使用功能开关，整体停用使用总开关，无需重新晋升目录。

## 失败处理与后续升级

| 情况 | 后续动作 |
| --- | --- |
| 候选业务验证失败、证据缺失或过期 | 修复后重新验证，保持未晋升状态 |
| 某个路线、运行模式或 RID 未验证 | 继续拒绝该组合，单独补充验证与晋升 |
| 晋升后受保护复验失败 | 阻止发布，修复并重新生成候选和最终报告 |
| 灰度运行异常 | 关闭宿主功能开关，定位问题；实现改变后重新验证与晋升 |
| 上游功能转为 Stable | 升级精确目标、重新分类与验收，再由宿主决定开放时间 |

新增 SSF、OID4VC VCI 等功能沿用同一流程。正式路线的默认验收范围与非 Stable 功能独立，新增候选计划不会自动扩大任何支持声明。
