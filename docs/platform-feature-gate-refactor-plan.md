# 全平台特性开关包改造方案

> 当前验收：采用下述微软包方案后已完成全量重跑，`Release.cs --bootstrap` 全部门禁通过。Admin v2 两种模式各 478/478、v1 各 492/492，标准协议 434/391、兼容协议各 20；Managed 真实验收包含微软引擎和官方本地遥测通道。记录见[当前候选](releases/26.8.1-preview.3/a1993485c6eeb5901f3c10ff76b1e165f329994bf4b7e0a2feb31c93808c3545.json)。以下原始执行结果保留为方案历史，不代表尚未重跑。

> 状态：**方案 / 代码闭环已完成，真实容器全量验收待重跑（2026-11-09）**。第 ①～⑤ 批已落地；第 ⑦ 批把 `FeatureValidationRunner` / `ProtocolValidationRunner` 收敛到 66 项平台开关目录与原子快照替换，并补齐上游 pinned-source 缓存。Release 构建 0 警 0 错；主测试 586/586、协议 105/105、宿主 14/14；覆盖率 15 项全 PASS；4 个 nupkg 依赖校验通过。第 ⑥ 批仍待执行：源码指纹变更使旧证据按设计自动失效，本机拉取固定 Keycloak 26.8.1 镜像受网络限制。适用 `26.8.1-preview.3` 开发线。

> 当前方案调整：按用户要求放弃 Platform 的 Native AOT 承诺，同包接入 Microsoft.FeatureManagement 4.8.0 及其官方 Application Insights 适配器，遥测默认关闭，删除自写 HTTP 发送器。主包/Protocols 继续独立原生测试，原生验收使用核心快照。下文「零外部引擎」「两项依赖」「Platform AOT」等描述原始重构及历史结果，不代表当前依赖与支持范围；当前用法见[遥测说明](platform-application-insights.md)。
> 前提：四个包**没有历史包袱**，不需要考虑 `26.8.1-preview.2` 消费者的升级路径。
> 文中行号均以 2026-11-09 当前工作树为基准，实施时以实际代码为准。

目标是用**一个宿主开关面控制 SDK 暴露的全部能力**，同时把包结构收敛为干净的 4 包：新增独立的 `Keycloak.Admin.Sdk.Platform`，不依赖 `Keycloak.Admin.Sdk.FeatureManagement`（下称 FM），改造完成后彻底移除 FM。方案落地后的最终依赖形态见 [4.2 节](#42-包依赖图)。

## 1. 结论

**可行，且是当前所有候选方案里架构最干净的一个。** 此前列为硬 blocker 的三件事，在「无历史包袱」前提下全部解除：验收证据 schema 可以整体换字段、覆盖率分类可以重命名、已发布包 ID 不再构成约束。唯一的硬成本是 `LiveEvidence.Fingerprint` 会让全部已归档证据失效，必须重跑全套真实验收，属于工程量而非架构阻塞。

两个决定性事实：

1. `../tools/Check-FullAcceptance.cs:19-20` 只读 `artifacts/full-live`（或 `--evidence=` 指定目录）与当前指纹，**不遍历** `docs/releases/` 和 `docs/contracts/*-evidence/` 历史归档，所以证据字段可整体替换。
2. 新包只使用主包的 `KeycloakFeatureSnapshotGate`，`ProjectReference` 指向主包与 Protocols（两者均为 `IsAotCompatible=true`），**0 个 `PackageReference`**，因此可声明 `IsAotCompatible=true`——这是首次让全平台开关面可用于 Native AOT，验收证据也不再需要 managed / native-aot 分叉。

## 2. 目标与非目标

| 目标 | 非目标 |
| --- | --- |
| 一个宿主开关面覆盖 Admin API、应用协议与宿主集成能力 | 控制 Keycloak 上游 80 个服务端 feature（`KC_FEATURES`）；SDK 只能读 `serverinfo.features[]` 并校验 |
| 最终仍为 4 个包，FM 项目彻底移除 | 新增第 5 个汇聚包 |
| 零微软 FeatureManagement 引擎依赖，AOT 可用 | 保留 Application Insights 遥测适配（随 FM 一起删除，宿主需要则自行订阅） |
| 开关目录有单一真源、可机械校验 | 合并 Admin 与 Protocols 两套总闸命名 |
| 改造后证据链、覆盖率、发布清单自洽 | 抹掉 `docs/releases/` 历史发布记录 |

被否决的备选：在 FM 内加统一门面（阶段 1，仍带微软引擎、AOT 不可用）、新增第 5 个 Managed-only 汇聚包（阶段 2，5 包 6 边）、就地把 FM 改成平台包（4 包 4 边但仍带引擎）。对比见 [第 11 节](#11-方案对比)。

## 3. 现状

当前 4 包依赖为 3 条边：FM → 主包、Protocols → 主包、Hosting → Protocols。主包是依赖树根，`IsAotCompatible=true`；Hosting 因 `FrameworkReference Microsoft.AspNetCore.App` 与 SAML 依赖显式为 false。

| 层次 | 数量 | 说明 |
| --- | --- | --- |
| 上游服务端 feature | 80 | `../contracts/platform-capabilities.json`，由部署层 `KC_FEATURES` 控制 |
| 应用能力族 | 52 | 同一契约，32 个归 `SdkProtocol`、20 个归 `HostIntegration` |
| Admin API 操作 | 520 | `../contracts/capabilities.json`，每个操作带 `FeatureId` |
| 协议侧开关 ID | 54 | 硬编码在 `../src/Keycloak.Admin.Sdk.Protocols/ApplicationSupportPolicy.cs:68-97` 的 switch |

问题集中在装配层：主包的 `IKeycloakFeatureGate` 本身是统一抽象，但 FM 的公开工厂 `KeycloakFeatureManagedClient.CreateAsync` 只装配 Admin 客户端；FM 与 Protocols/Hosting 是兄弟包，跨包胶水只能由宿主手写；`../contracts/feature-management.example.json` 只有 11 个 Admin 开关，`contracts/` 全目录 `KeycloakSdk.Protocols` 零匹配；两条链各自引导（Admin 工厂自读 serverinfo，协议链要求外部传 `KeycloakServerCapabilities`）；协议工作流测试全部使用 `KeycloakFeatureSnapshotGate`，全仓没有测试证明 FM 驱动过协议或宿主能力。

## 4. 目标架构

### 4.1 包职责

| 包 | ProjectReference | IsAotCompatible | 职责 |
| --- | --- | --- | --- |
| `Keycloak.Admin.Sdk` | — | ✅ | 520 操作；`IKeycloakFeatureGate`、`KeycloakFeatureSnapshotGate`、`KeycloakFeatureGatePolicy`、`KeycloakServerCapabilities`、`KeycloakCapabilityPolicy` |
| `Keycloak.Admin.Sdk.Protocols` | → 主包 | ✅ | 52 能力族 / 54 协议开关；`ProtocolTransport.CreateSupported`；`ApplicationSupportPolicy` |
| **`Keycloak.Admin.Sdk.Platform`（新）** | **→ 主包 + Protocols** | **✅** | **统一宿主开关面，0 个 NuGet 依赖** |
| `Keycloak.Admin.Sdk.Hosting` | → Protocols | ❌ | Web / OIDC / JWT / SAML / Backchannel，宿主按需引用 |

**Platform 不引用 Hosting**，否则会传递引入 `Microsoft.AspNetCore.App` 与 `ITfoxtec.Identity.Saml2`，AOT 声明立即作废。

### 4.2 包依赖图

```text
                        ┌──────────────────────────────┐
                        │  Keycloak.Admin.Sdk          │  AOT ✅  依赖树根
                        │  520 ops / gate / capability │
                        └───────────┬──────────┬───────┘
                                    │          │
              ┌─────────────────────┘          └──────────────────┐
              ▼                                                    ▼
┌──────────────────────────────┐                  ┌──────────────────────────────┐
│  Keycloak.Admin.Sdk.Protocols│  AOT ✅          │  Keycloak.Admin.Sdk.Platform │  AOT ✅
│  52 能力族 / 54 开关         │◄─────────────────│  统一开关面 · 零 NuGet 依赖   │
└───────────────┬──────────────┘  ProjectRef     └──────────────────────────────┘
                │
                ▼
┌──────────────────────────────┐
│  Keycloak.Admin.Sdk.Hosting  │  AOT ❌  Web 宿主按需引用
└──────────────────────────────┘

已移除：FeatureManagement 项目、Microsoft.FeatureManagement 引擎与遥测、
        KEYCLOAK_FEATURE_MANAGEMENT 条件编译、evidence.featureManagement 维度。
最终 4 包、4 条 ProjectReference；箭头 = 依赖方 → 被依赖方。
```

### 4.3 新包公开面

建议只暴露 4 个类型，避免把 FM 的复杂度原样搬过来：

| 类型 | 职责 |
| --- | --- |
| `KeycloakPlatformOptions` | 统一配置：server、令牌提供方、支持配置、开关快照、可选的自定义 gate |
| `KeycloakPlatformHost` | **一次** `serverinfo` 引导得到 `KeycloakServerCapabilities`；产出 Admin client 与 Protocol transport，二者共享同一个 `IKeycloakFeatureGate` 实例 |
| `KeycloakFeatureFlagCatalog` | 完整开关目录，从契约生成、启动时校验配置完整性（fail-closed） |
| `KeycloakPlatformGate` | `KeycloakFeatureSnapshotGate` 的可热替换包装；沿用「配置变化影响后续请求、不撤销已发送请求」语义 |

宿主若仍要接微软引擎，自行实现主包的 `IKeycloakFeatureGate` 即可，SDK 不再打包适配器。

### 4.4 边界约束

- 不重复实现能力策略：复用主包 `KeycloakCapabilityPolicy` 与 Protocols 的 `ApplicationSupportPolicy`。
- Admin 侧检查 `KeycloakSdk.AdminApi` + 端点 `FeatureId`；协议侧检查 `KeycloakSdk.Protocols` + 各 `KeycloakSdk.Protocols.*`。Platform 统一的是**同一 gate 实例 + 同一份开关目录**，不强行合并两套命名。
- 开关目录构成：2 个总闸 + Admin 侧 `FeatureId` + 54 个协议开关，去重后实测 **66 项**，由 `Generate-FeatureCatalog.cs` 输出并校验。
- `ProtocolTransport.HostAllowsAsync` 对 `KeycloakFeatureSnapshotGate` 有单次快照优化；Platform 默认使用快照 gate，天然走该路径。

## 5. 文件级改造清单

### 5.1 新增

| 路径 | 内容 |
| --- | --- |
| `../src/Keycloak.Admin.Sdk.Platform/Keycloak.Admin.Sdk.Platform.csproj` | 2 条 `ProjectReference`、0 条 `PackageReference`、`IsAotCompatible=true`、包内 README |
| `../src/Keycloak.Admin.Sdk.Platform/*.cs` | 4.3 节的 4 个公开类型 |
| `../contracts/feature-flag-catalog.json` | 完整开关目录，由生成器产出 |
| `../contracts/application-capability-flags.json` | 52 个 kebab 能力族 ↔ 54 个协议开关 ID 的单一真源 |
| `../tools/Generate-FeatureCatalog.cs` | 生成目录、示例配置、协议侧映射；支持 `--check` |
| `../docs/platform-feature-gate.md` | 新包的接入与边界文档（替换现有 [feature-management.md](feature-management.md)） |
| `../src/Keycloak.Admin.Sdk.Protocols/obj/ApplicationFeatureMap.g.cs` | 编译期生成到 `obj/`，不进源码目录 |

### 5.2 删除（FM 项目共 6 个文件，整目录移除）

| 文件 | 说明 |
| --- | --- |
| `../src/Keycloak.Admin.Sdk.FeatureManagement/Keycloak.Admin.Sdk.FeatureManagement.csproj` | 含 96 行嵌入式 release notes、`Microsoft.FeatureManagement 4.8.0` 与遥测两个包引用 |
| `../src/Keycloak.Admin.Sdk.FeatureManagement/KeycloakFeatureManagedClient.cs` | 工厂，能力迁入 `KeycloakPlatformHost` |
| `../src/Keycloak.Admin.Sdk.FeatureManagement/KeycloakFeatureManagementPolicy.cs` | 主包 `KeycloakFeatureGatePolicy` 已等价 |
| `../src/Keycloak.Admin.Sdk.FeatureManagement/KeycloakMicrosoftFeatureGate.cs` | **不迁移**，这是「不依赖 FM」的核心 |
| `../src/Keycloak.Admin.Sdk.FeatureManagement/ApplicationInsights/KeycloakTelemetryExtensions.cs` | 遥测能力整体移除 |
| `../src/Keycloak.Admin.Sdk.FeatureManagement/README.md` | 由 Platform README 替代 |

⚠️ 引导守卫：`KeycloakFeatureManagedClient.cs:22` 与 `KeycloakSupportedClient.cs:30` **都**在 bootstrap 之后对 `admin/serverinfo` 执行 `EnsureAllowedAsync`（实施时复核确认，初稿误判为主包没有）。Platform 的 `KeycloakPlatformHost.CreateAsync` 保留了等价守卫，否则旧 `featureManagementBusinessGuards` 对应的业务断言在新模型里失去对应物。

### 5.3 改写

| 位置 | 改动 |
| --- | --- |
| `../Keycloak.Admin.Sdk.slnx:5` | 替换 `/src/` 下的项目路径 |
| `../tools/Verify.cs:50` | 依赖字典改为 `["Keycloak.Admin.Sdk.Platform"] = ["Keycloak.Admin.Sdk", "Keycloak.Admin.Sdk.Protocols"]`；`:68` 数量断言仍为 4；`:23` 若新增生成器需加入编译清单；`:30-31` 加入 `--check` |
| `../tools/Release.cs:53` | 4 个包 ID 列表替换 FM → Platform |
| `../src/Keycloak.Admin.Sdk/Keycloak.Admin.Sdk.csproj:13` | 内嵌 release notes 中「可安装 …FeatureManagement」改为 Platform |
| `../src/Keycloak.Admin.Sdk/Capabilities/KeycloakSupportedClient.cs:11` | 注释 `without Microsoft.FeatureManagement dependencies` 改为中性表述 |
| `../contracts/feature-management.example.json` | 重建为完整开关目录示例 |
| `../tests/Keycloak.Admin.Sdk.Tests/Keycloak.Admin.Sdk.Tests.csproj:5,13` | 去掉 `DefineConstants`；`ProjectReference` 切到 Platform |
| `../tests/Keycloak.Admin.Sdk.Tests/FeatureManagementContracts.cs` | 迁移为 Platform 契约测试（当前 29 处命中） |
| `../tests/Keycloak.Admin.Sdk.Tests/ContractSuite.cs:23`、`ContractTests.cs` | 去掉条件编译包围 |
| `../tests/Keycloak.Admin.Sdk.IntegrationTests/FullAdminSuite.cs:15-34` | 合并 managed / AOT 分叉，走同一 Platform 路径 |
| `../tests/Keycloak.Admin.Sdk.IntegrationTests/FeatureValidationRunner.cs:8-59` | 合并为 `KeycloakFeatureSnapshotGate` 路径，`gateName` 统一 |
| `../tests/Keycloak.Admin.Sdk.IntegrationTests/FullFeatureManagement.cs` | 重写为 Platform 业务守卫，或删除后并入 Platform 测试 |
| `../tests/Keycloak.Admin.Sdk.IntegrationTests/Keycloak.Admin.Sdk.IntegrationTests.csproj:11,16,18-20` | 只保留 `KEYCLOAK_HOSTING`；引用切到 Platform；删除 `<Compile Remove="FullFeatureManagement.cs" />` |
| `../README.md`、`../README.en.md`、`../CHANGELOG.md` | 四包表、接入示例、preview.3 breaking change（历史条目保留） |
| `../docs/architecture.md`、`capability-policy.md`、`full-platform-coverage.md:20`、`non-stable-feature-lifecycle.md`、`testing.md`、`authentication-integration.md`、`wallet-integration.md`、`single-target-workflow.md`、`../src/Keycloak.Admin.Sdk.Hosting/README.md` | 术语与结构同步；顺手修 `architecture.md:43` 关于「仅两个包 / 尚未发布」的滞后描述 |

### 5.4 保留不动

- `../docs/releases/26.8.1-preview.1/*`、`../docs/releases/26.8.1-preview.2/*`：不可变历史发布记录，不参与构建与门禁。「无历史包袱」指不必考虑升级兼容，**不等于抹掉历史**。
- `../.github/workflows/*.yaml`：实测 `FeatureManagement` 相关字样 **0 命中**，CI 通过 `Service.cs` / `Verify.cs` 间接调用，无需改动。
- `../docs/contracts/*-evidence/*.json`、`../docs/contracts/test-coverage.md`、`../docs/contracts/full-live-acceptance.*`、`../docs/contracts/protocol-coverage.md`：脚本导出产物，由重跑覆盖，**不要手改**。

触面量化：大小写不敏感检索 `FeatureManagement|featureManagement|feature_management` 共 **52 个文件 / 约 190 处**，其中活跃需改约 30 个，其余为历史归档与生成产物。

## 6. 门禁迁移

### 6.1 验收证据 schema（四处联动）

| 环节 | 位置 | 现状 → 目标 |
| --- | --- | --- |
| 写入 | `../tests/Keycloak.Admin.Sdk.IntegrationTests/FullAdminSuite.cs:27-34` | `featureManagement` / `featureManagementBusinessGuards` → `platformGate` / `platformGateBusinessGuards` |
| 校验 | `../tools/Check-FullAcceptance.cs:44-46` | managed 与 native-aot **同为** `"snapshot-v1"` / `true`；bootstrap 仍为 `not-loaded-bootstrap` / `false` |
| 负向控制 | `../tools/Test-AcceptanceGate.cs:29` | 改翻转新字段，错误信息同步改为平台 gate 语义 |
| 文档文案 | `../tools/Check-FullAcceptance.cs:93` | 现写「托管入口使用 Microsoft FeatureManagement 4.8.0…Native AOT 编译时排除」，必须重写 |

这是**语义升级**而非改名：旧模型 native-aot 必然是 `not-loaded-native-aot` / `false`，新模型两种模式都是正向断言，负向控制更简单，也真正证明了 AOT 侧开关面可用。

### 6.2 覆盖率分类

`../tools/Check-Coverage.cs` 的 `:66-69`（package 名换 Platform、删除 `IsTelemetry` 分类）、`:81-86`（6 个 metrics → 3 个 `platformGate{Method,Line,Branch}Percent`）、`:98`（报告文案「能力、开关和遥测模块分别统计」）、`:108`（`FileName()` 的两条 FM 路径前缀换成 Platform）。`../tests/coverage-policy.json:14-19` 删除 3 个 `featureTelemetry*`、重命名 3 个 `featureManagement*`，门槛保持 100%。前提是 Tests 项目引用 Platform 且新包达到 100% 覆盖；**不要降低门槛**。

注意 `:112` 的 `Percent` 对空集会抛错：删除遥测分类时必须同时删除对应 metrics，不能留空统计项。

### 6.3 Protocols 100% 覆盖率

`../tools/Check-ProtocolCoverage.cs:24` 只排除 filename 含 `/obj/` 的 class。把 `ApplicationSupportPolicy.cs:68-97` 的手写 switch 抽成生成映射时，必须沿用 Protocols.csproj 现有 `StampApplicationInputs` target 的范式**生成到 `obj/`**，否则新增 class 的行/分支会击穿 100% 门禁。这也是 5.1 节把 `ApplicationFeatureMap.g.cs` 放在 `obj/` 的原因。

### 6.4 条件编译

`KEYCLOAK_FEATURE_MANAGEMENT` 全仓 7 处：`ContractSuite.cs:23`、`FullAdminSuite.cs:15,28`、`FeatureValidationRunner.cs:8,41`、两个 csproj（`:5` / `:11`）。Platform AOT 兼容后 managed 与 native-aot 可走同一份代码，常量**整体删除**，`#if/#else/#endif` 分叉合并。`KEYCLOAK_HOSTING` 保留——Hosting 仍不 AOT 兼容，这条分叉是真实的。

## 7. 指纹与全量重跑

`../tests/Keycloak.Admin.Sdk.IntegrationTests/LiveEvidence.cs:11-18` 的指纹输入包含 `src/` 全目录、`tools/` 全目录、`tests/IntegrationTests`、`local/keycloak` 与全部 `contracts/*.json`。新增 Platform 目录、删除 FM 目录、改写工具与契约必然改变指纹，`../tools/Check-FullAcceptance.cs:41` 的 `sourceFingerprint` 断言会让旧证据立即全部失效。

```shell
dotnet run --file tools/Verify.cs -- --skip-native-publish
dotnet run --file tools/Verify.cs -- --native-container

# 真实验收：路线由 KEYCLOAK_ADMIN_API_ROUTE 环境变量或 local/keycloak/.env 指定。
# 逐条切换到 fgap-v2-stable 与 fgap-v1-compat，每条路线各跑 managed 与 native-aot 两次。
dotnet run --file local/keycloak/Service.cs -- test-full
dotnet run --file local/keycloak/Service.cs -- test-full-native

dotnet run --file tools/Test-AcceptanceGate.cs -- --v1
dotnet run --file tools/Test-AcceptanceGate.cs -- --v2
dotnet run --file tools/Check-FullAcceptance.cs -- --update-docs
dotnet run --file tools/Release.cs
```

真实 Keycloak 26.8.1 + PostgreSQL 18 容器下的两条路线（`fgap-v2-stable` / `fgap-v1-compat`）× 两种执行模式（managed / native-aot）共 4 份 manifest 必须全部重新产生。这是整个改造中唯一耗时且不可跳过的环节。

## 8. 风险与缓解

| 风险 | 影响 | 缓解 |
| --- | --- | --- |
| 引导守卫语义漂移 | 关闭总开关后 `serverinfo` 仍可访问，业务断言失去对应物 | Platform 保留 `EnsureAllowedAsync` 等价调用；补单测断言总闸关闭时 serverinfo 也被拒绝 |
| AOT 声明被污染 | Platform 传递引入 ASP.NET Core / SAML | `Verify.cs:50` 断言 nuspec 依赖恰好 2 项；AotSmoke 真正引用 Platform 并调用开关面 |
| 开关目录不完整 / 双真源 | 宿主配置漏 flag 导致能力静默不可用 | 生成 `feature-flag-catalog.json`，`Generate-PlatformMatrix.cs --check` 加一致性断言；启动时 fail-closed 校验 |
| 覆盖率击穿 | Verify 直接失败 | 生成文件落 `obj/`；新包 100% 覆盖；metrics 与 policy 同步改名 |
| 文档与证据矛盾 | 发布候选不可信 | `Check-FullAcceptance.cs:93` 文案与证据字段同批修改 |
| 误删历史归档 | 丢失已发布版本追溯 | 5.4 节白名单，删除阶段只针对活跃文件 |

## 9. 验收标准

- [ ] `dotnet build Keycloak.Admin.Sdk.slnx -c Release` 0 错 0 警（`TreatWarningsAsErrors=true`）。
- [ ] `Verify.cs` 通过；feed 中恰好 4 个 `.nupkg`，Platform 的 nuspec 依赖恰好 2 项且无 `Microsoft.FeatureManagement` / `Microsoft.AspNetCore.App`。
- [ ] `Check-Coverage.cs` 新 3 项 `platformGate*` 均 100%，其余指标不退化；`Check-ProtocolCoverage.cs` 仍为行/分支 100%。
- [ ] `Check-FullAcceptance.cs` 4 份 manifest 全部 PASS；`platformGate = "snapshot-v1"`、`platformGateBusinessGuards = true` 且 managed 与 native-aot 一致。
- [ ] `Test-AcceptanceGate.cs --v1 / --v2` 全部负向控制 PASS。
- [ ] Native AOT smoke 可执行文件运行成功，且 Platform 开关面在其中被实际调用。
- [ ] 活跃文件中 `KEYCLOAK_FEATURE_MANAGEMENT`、`Microsoft.FeatureManagement`、`Keycloak.Admin.Sdk.FeatureManagement` **0 命中**；`grep` 残留仅限 `docs/releases/` 历史归档。
- [ ] 新增契约与生成器的 `--check` 全部通过；`Release.cs` 产出的候选包列表为新的 4 包。

### 9.1 当前执行结果（2026-11-09）

| 门禁 | 结果 |
| --- | --- |
| `dotnet build Keycloak.Admin.Sdk.slnx -c Release` | PASS，0 警告 0 错误 |
| `Check-Baseline`、`Generate-TestMatrix --check`、`Generate-LiveRoutes --check`、`Check-AdminRoutes`、`Generate-CapabilityCatalog --check`、`Generate-FeatureCatalog --check`、`Check-Coverage --self-test` | 全部 PASS |
| 主测试 + `Check-Coverage` | 586/586；15 项指标全 PASS，`platformGate{Method,Line,Branch}Percent` 均 100% |
| 协议测试 + `Check-ProtocolCoverage` | 105/105；源码行/分支 100%（补齐上游缓存后此前 9 个环境失败消失） |
| 宿主测试 | 14/14 |
| 四包 `dotnet pack` + nuspec 依赖 | PASS；Platform 恰好 2 项依赖，无 `Microsoft.FeatureManagement` / `Microsoft.AspNetCore.App` |
| `Generate-PlatformMatrix --check` | **未通过（设计预期）**。`ApplicationAcceptance.CurrentProfiles` 只接受 `inputFingerprint == LiveEvidence.ValidationFingerprint` 的证据，源码变更使旧证据自动退出；直接重生成会清空全部已晋升业务证据，已还原，不得绕过 |
| `Verify.cs` 全链路 | 在矩阵检查处按预期停止；其余步骤已单独执行并通过 |
| `Check-FullAcceptance`、`Test-AcceptanceGate --v1/--v2`、Native AOT smoke、`Release.cs` | 待第 ⑥ 批真实容器全量验收重新生成证据 |

> 结论：代码、契约、测试、覆盖率与打包链路已闭环；唯一缺口是**证据重生成**，必须由真实 Keycloak 26.8.1 容器 + Managed/Native AOT 双路线重新产出，不能手工改写指纹或证据字段。

## 10. 实施顺序

| 批次 | 内容 | 指纹重跑 |
| --- | --- | --- |
| ① 契约与生成器 | 新增 flag catalog 与 `Generate-FeatureCatalog.cs`；Protocols 映射改为生成到 `obj/`；先跑 `--check` | 否 |
| ② 新包落地 | `src/Keycloak.Admin.Sdk.Platform/`（4 类型 + README + csproj）、slnx 替换、单测补到 100% | 否（尚未删除旧包） |
| ③ 门禁与测试迁移 | 6.1 四处、6.2 五处、6.4 七处、Tests.csproj 引用 | 否 |
| ④ 删除 FM | 整目录 6 文件 + 2 处 csproj 引用 + 常量；确认编译 0 错、活跃文件 0 命中 | 是（触发） |
| ⑤ 工具链 / 发布 / 文档 | Verify / Release / README / docs / CHANGELOG；生成类文档由脚本产出 | 否 |
| ⑥ 全量验收 | 第 7 节命令集，导出证据，生成新发布候选 | 是 |
| ⑦ 功能闭环收口 | 两个真实验收 runner 改用 66 项平台目录与 `KeycloakPlatformGate`；补齐上游 pinned-source 缓存；同步 CHANGELOG 与方案状态 | 是（已触发） |

建议第 ② 与 ④ 批之间保留一个 checkpoint（本地提交或 stash）：④ 之后旧证据与新门禁同时失效，若一次性做完，很难定位是哪一处改动击穿了哪条门禁。

## 11. 方案对比

| 方案 | 包数 | 引用边 | 全平台开关面可用于 AOT | 微软引擎依赖 | 证据 managed/AOT 分叉 | 需兼容旧包 ID |
| --- | --- | --- | --- | --- | --- | --- |
| 原状 | 4 | 3 | ❌ | 有 | 有 | 是 |
| 阶段 1：FM 内加统一门面 | 4 | 3 | ❌ | 有 | 有 | 是 |
| 阶段 2：新增第 5 汇聚包 | 5 | 6 | ❌ | 有 | 有 | 是 |
| FM 就地改为平台包 | 4 | 4 | ❌ | 有 | 有 | 是 |
| **本方案：Platform 替换 FM** | **4** | **4** | **✅** | **无** | **无** | **否** |

本方案在不增加包数与发布复杂度的前提下，同时解决了「统一开关面」「零引擎依赖」「AOT 可用」「证据模型统一」四个问题，因此是支配性方案。

## 附录：核实依据

| 事实 | 依据 |
| --- | --- |
| 门禁只读当前指纹证据，不遍历历史归档 | `../tools/Check-FullAcceptance.cs:19-20,41` |
| 证据字段的写入点 | `../tests/Keycloak.Admin.Sdk.IntegrationTests/FullAdminSuite.cs:27-34` |
| 覆盖率分类按 package 名与路径前缀硬编码 | `../tools/Check-Coverage.cs:66-69,81-86,108`；`../tests/coverage-policy.json:14-19` |
| Protocols 仅排除 `/obj/` | `../tools/Check-ProtocolCoverage.cs:23-28` |
| 指纹输入范围 | `../tests/Keycloak.Admin.Sdk.IntegrationTests/LiveEvidence.cs:11-18` |
| 所有 Native AOT 发布路径都不引用 FM | `../tests/Keycloak.Admin.Sdk.IntegrationTests/Keycloak.Admin.Sdk.IntegrationTests.csproj:10-20`、AotSmoke.csproj、PackageSmoke.csproj |
| 主包 / Protocols AOT 兼容，Hosting 不兼容 | 三个 `src/*/*.csproj` 的 `IsAotCompatible` |
| 包清单与依赖断言 | `../tools/Verify.cs:47-69`、`../tools/Release.cs:53` |
| 80 feature / 52 能力族 / 520 操作 | `../contracts/platform-capabilities.json`、`../contracts/capabilities.json`、`../contracts/baseline.json` |
