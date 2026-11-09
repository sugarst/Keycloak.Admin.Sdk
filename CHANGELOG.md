# 版本变更

记录可分发版本的变化；本地候选通过验收后生成的机器记录见 [docs/releases](docs/releases/README.md)。实际发布以对应发布记录中的 NuGet 链接和发布时间为准。

## 26.8.1-preview.3（开发中，未发布 / In development, unpublished）

- 当前源码全量复验通过：标准协议 Managed 434/434、Native AOT 391/391，兼容协议各 20/20；Admin v2 各 478/478、v1 各 492/492；706 项单测、两路线各 14 项门禁负向控制、六套非 Stable 受保护复验及严格原生包消费全部通过。完整 `Release.cs --bootstrap` 生成新本地候选，未发布 NuGet。
- Revalidate current inputs: standard protocols 434/434 Managed and 391/391 Native AOT, legacy 20/20 per runtime; Admin v2 478/478 and v1 492/492 per runtime. Pass 706 unit tests, 14 negative controls per route, six guarded non-Stable runs and strict native package consumption. Full `Release.cs --bootstrap` produces a fresh local candidate without NuGet publication.

- 真实验收补强：托管全量流程新增微软引擎创建/删除、配置刷新、协议关闭及官方本地遥测通道检查；发布门禁强制核对对应证据，并增加错误运行模式证据的负向控制。修复 AOT Docker 构建上下文遗漏解决方案根标记，导致协议开关生成器无法定位仓库的问题。
- Strengthen live acceptance with Microsoft-engine create/delete, configuration reload, protocol shutdown and official local-channel telemetry checks. Require matching business evidence and reject wrong-runtime claims. Fix the missing solution root marker in the AOT Docker context, which prevented the protocol flag generator from locating the repository.

- Platform 同包改用 Microsoft.FeatureManagement 4.8.0 及官方 Application Insights 评估遥测适配器，移除自写 HTTP/JSON 发送器；遥测需 publisher 和逐开关显式启用。Platform 不再声明 Native AOT 支持；主包/Protocols 原生验证使用核心快照门禁，不引用 Platform。补充官方 publisher 内存通道测试、完整配置和文档。本次源码与证据语义变更后须重跑真实业务验收。
- Use Microsoft.FeatureManagement 4.8.0 and its official Application Insights publisher inside Platform, removing the custom HTTP/JSON sender. Require publisher and per-flag telemetry opt-ins. Platform is Managed-only; core/Protocols native tests use the core snapshot gate without Platform. Add official-publisher tests, full configuration and docs. Live business evidence must be regenerated for changed inputs and evidence semantics.

- **架构变更（preview.3，破坏性）**：移除独立的 `Keycloak.Admin.Sdk.FeatureManagement` 包，在 Managed `Keycloak.Admin.Sdk.Platform` 内统一快照及微软引擎入口，控制 Admin 与协议能力；开关目录共 66 项。验收证据使用 `platformGate` / `platformGateBusinessGuards`，覆盖率分类为 `platformGate*`。已发布 preview.2 的范围不变。
- 建立独立于 Admin API 的全能力矩阵：固定源码的 80 个功能开关及 52 个独立应用协议／宿主集成能力族，明确服务端责任边界；52/52 完成实现与晋升，完整覆盖门禁通过。
- 新增 Protocols 模块：OIDC、标准/委托/旧版/JWT 授权、Device/CIBA、PAR、JAR/JARM、兼容响应、认证强度、资源指示器、参数化 scope、客户端断言、SCIM、账户、注册、UMA、AuthZen、Client Admin v2、OpenAPI、Docker、DPoP、身份代理与 SSF。
- 补齐钱包 JWT VC、SD-JWT、mdoc、加密签发、Offer/二维码、预授权、刷新/撤销、OID4VP 和客户端 attestation；增加 WebAuthn、Passkey、Kerberos、恢复码、邮箱确认、临时用户和独立控制的弃用兼容入口。
- 新增 Managed Hosting 模块：ASP.NET Core OIDC/资源令牌、服务端票据、前/后通道注销、MCP 资源元数据和 SAML SP 签名/加密/单点注销。Managed 专属证据不能晋升 Native AOT。
- 协议源码行和分支覆盖率要求 100%，真实流程验证用户同意、独立验签、持久化结果、拒绝、撤销、过期和重放。能力按固定版本、输入指纹、运行模式/RID 独立晋升，由 `Keycloak.Admin.Sdk.Platform` 的统一开关面最后开放或关闭。
- 标准应用验收 Managed 434/434、Native AOT 391/391；旧版兼容计划各 20/20。Client Types、SSF、OID4VC 的 28 个 Admin 操作完成 v2 托管及原生独立晋升与受保护复验；14 个 FGAP v1 专用操作继续保留兼容阶段，默认稳定路线不扩大。
- 单元测试共 706 项：核心 587、协议 105、宿主 14；协议源码行／分支覆盖均为 100%。补充未晋升目录的关闭状态测试，并按服务端异步提交语义等待工作流持久化，避免重复发送写操作。
- 所有 Preview、Experimental 和 Deprecated 能力仍须明确选择，并通过对应服务器功能及最终宿主开关；晋升不修改上游阶段。preview.3 尚未发布，已发布 preview.2 的功能范围不变。
- **Architecture (preview.3, breaking)**: Replace the separate `Keycloak.Admin.Sdk.FeatureManagement` package with Managed `Keycloak.Admin.Sdk.Platform`, offering snapshot and Microsoft-engine entry points across the same 66-flag Admin/protocol switch surface. Acceptance evidence and coverage metrics use `platformGate*`. Published preview.2 scope is unchanged.
- Add separate matrices for 80 pinned upstream features and 52 application capability families. All 52 reviewed families are implemented and independently promoted; the complete-coverage gate passes within the documented server/host responsibilities and verified runtimes.
- Add Protocols and Managed Hosting, including secure OIDC/OAuth, delegation, SAML, authorization, account, provisioning, wallets, WebAuthn/Passkeys, Kerberos, transient users and explicitly controlled legacy compatibility. Standard workflows pass 434 Managed / 391 Native AOT checks, with 20 legacy checks per runtime. Independently promote and guard all 28 optional Admin operations for v2 Managed / Native AOT; retain 14 FGAP v1 compatibility operations.
- Preserve explicit per-capability non-Stable opt-ins and current-input/runtime evidence. The `Keycloak.Admin.Sdk.Platform` switch surface controls final exposure. preview.3 remains unpublished; published preview.2 capabilities are unchanged.
- Pass 706 unit tests: 587 core, 105 protocol and 14 hosting tests, with 100% protocol source line/branch coverage. Verify unpromoted catalog entries remain closed, and await asynchronous workflow persistence without replaying writes.

## 26.8.1-preview.2（已发布至 NuGet）

**中文：相较 26.8.1-preview.1**

目标仍为精确的 Keycloak 26.8.1，生成接口仍为 520 个；默认正式路线和兼容路线的验收范围保持不变。

- 补全集成验收、协议夹具、并发等待和工具进程中的 CancellationToken 传递，增加取消及独立清理验证。
- 能力目录与支持配置增加 schema 2，按接口、FGAP 路线、运行模式及 Native AOT RID 记录验证；旧配置继续要求托管与原生证据。
- 主包提供统一宿主开关及可原子刷新的 AOT 配置快照，FeatureManagement 托管适配器复用同一门禁。
- 增加隔离功能验证、逐项晋升和最终受策略保护复验；构建指纹防止用旧程序验证新源码，发布流程检查所有已支持非 Stable 组合。FeatureManagement 负责最后的灰度开放和关闭，验证及晋升工具不修改宿主开关。
- Client Types 两个操作完成托管 v2 的独立验证与晋升，仍保留 Experimental 阶段并默认关闭；AOT 和 v1 组合不继承该支持状态。
- 两个包的发布说明采用 Markdown 并提供可编译的使用示例；FeatureManagement 包补充包内 README。
- 测试从 preview.1 对应源码的 567 项增加至 586 项。本版本已通过全部测试、覆盖率门禁、严格 Native AOT、两条 FGAP 路线各自的托管/原生业务验收及 Client Types 受保护复验；v2 各 478/478，v1 各 492/492。
- SSF 和 OID4VC VCI 尚未晋升支持；非 Stable 功能不会自动开启。两个包已发布至 NuGet：[主包](https://www.nuget.org/packages/Keycloak.Admin.Sdk/26.8.1-preview.2)、[FeatureManagement 扩展](https://www.nuget.org/packages/Keycloak.Admin.Sdk.FeatureManagement/26.8.1-preview.2)。

**English: changes since 26.8.1-preview.1**

The exact Keycloak target remains 26.8.1, with 520 generated operations. The default stable and compatibility acceptance scopes are unchanged.

- Propagate CancellationToken through integration acceptance, protocol fixtures, concurrent waits and tool processes; add cancellation and independent cleanup checks.
- Add schema 2 capability catalogs and support configuration, recording verification by operation, FGAP route, runtime and Native AOT RID. Existing configurations retain their requirement for both managed and native evidence.
- Add a shared host feature gate and an atomically replaceable Native AOT flag snapshot. The managed FeatureManagement adapter uses the same gate.
- Introduce isolated candidate validation, scoped support promotion and final guarded acceptance. Build fingerprints prevent stale executables from validating changed inputs, and release gates check every supported non-stable combination. FeatureManagement controls the final rollout and shutdown; validation and promotion tools leave host flags unchanged.
- Verify and promote both Client Types operations for Managed / FGAP v2 only. They remain Experimental and disabled by default; Native AOT and FGAP v1 do not inherit this support.
- Provide Markdown package release notes with compilable examples for both packages, and include a README in the FeatureManagement package.
- Increase tests from 567 on the preview.1 source to 586. All tests, coverage gates, strict Native AOT, both routes in managed/native modes and guarded Client Types acceptance pass: 478/478 per v2 run and 492/492 per v1 run.
- SSF and OID4VC VCI remain unpromoted. Non-stable features are not enabled automatically. Both preview.2 packages have been published to NuGet: [core](https://www.nuget.org/packages/Keycloak.Admin.Sdk/26.8.1-preview.2) and [FeatureManagement](https://www.nuget.org/packages/Keycloak.Admin.Sdk.FeatureManagement/26.8.1-preview.2).

本地验收候选、源码指纹及候选包 SHA256 / Local acceptance candidate, source fingerprint and candidate package SHA256: [候选记录 / candidate record](docs/releases/26.8.1-preview.2/83bb57fe71297c43802b47e945f9efb8acc594d50c226f6ef4c531ecc7d0d402.json)。实际发布状态与公开包信息 / Publication status and public package information: [发布记录 / publication record](docs/releases/26.8.1-preview.2/publication.json)。

## 26.8.1-preview.1（已在 NuGet 提供）

- SDK 包版本改为对齐 Keycloak 26.8.1；预览阶段使用 `preview.N` 递增。当前产出主包和 FeatureManagement 两个 NuGet 包。
- 修复升级隔离构建时缺少嵌入能力目录的问题，新目标仍从未验收状态开始。
- 工具编译检查使用隔离输出目录，避免 Windows 发布流程覆盖正在运行的程序。
- 发布流程将来源、包 SHA-256 和验收摘要同步保存到 Git 跟踪的目录，区分 SDK 提交与 Keycloak 上游提交。

NuGet 已提供 [主包](https://www.nuget.org/packages/Keycloak.Admin.Sdk/26.8.1-preview.1) 和 [FeatureManagement 包](https://www.nuget.org/packages/Keycloak.Admin.Sdk.FeatureManagement/26.8.1-preview.1)。已下载包的来源 commit 均为 `0d1213b`；历史本地候选与公开包的 SHA256 不同，不能将其视作同一制品。能力范围、兼容路线和排除项见 [README](README.md#keycloak-2681-能力边界)；历史验收仅代表其对应源码。
