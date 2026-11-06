# 版本变更

记录可分发版本的变化；本地候选通过验收后生成的机器记录见 [docs/releases](docs/releases/README.md)。实际发布以对应发布记录中的 NuGet 链接和发布时间为准。

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
