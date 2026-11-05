# 发布记录与保存规则

## 提交到 Git

| 内容 | 位置 | 维护方式 |
| --- | --- | --- |
| 版本、目标 Keycloak、固定来源和工具链 | `contracts/baseline.json` 及派生文件 | 修改基线后同步、校验 |
| 每版变化、兼容性和已知问题 | [CHANGELOG.md](../../CHANGELOG.md) | 准备候选时更新，实际发布后补充状态 |
| 每次成功候选的来源、包哈希和验收摘要 | `<packageVersion>/<sourceFingerprint>.json` | `Release.cs` 全部门禁通过后自动生成，与候选目录的 manifest 一致 |
| 当前契约、支持范围和验收证据 | `contracts/`、`docs/contracts/` | 随代码一起提交；历史候选记录在升级时保留 |

记录中的 `keycloakSourceCommit` 是上游 Keycloak 提交；`sdkCommit` 是命令启动时的 SDK HEAD。`sdkWorkingTreeDirty=true` 表示启动时有未提交文件，或重建改变了验收输入，此时不能仅凭该提交还原候选，应结合 `sourceFingerprint` 和提交后的源码检查。命令生成的报告和记录可在后续提交保存，不要求记录包含自身提交的哈希。

迁入的旧记录保留原始 schema 1：其中 `sourceCommit` 指 Keycloak 上游提交，未记录 SDK HEAD。新流程使用 schema 2，明确区分两者，不为历史记录补造来源信息。

候选状态固定为 `local-candidate`、`published=false`。相同版本、不同源码指纹各保留一份；相同指纹重跑更新该记录，Git 保留修改历史。失败不会写入本次成功记录，已有记录只代表其对应的历史成功执行。

## 单独保存的制品

`.nupkg`、`.snupkg`、完整日志、TRX、Cobertura、缓存和 AOT 二进制继续由 `.gitignore` 排除。本地候选位于 `artifacts/releases/<packageVersion>/<sourceFingerprint>/`，清理前如需保存，应复制到长期制品存储。CI 会上传候选及测试附件，但 CI 附件会按保留策略过期，不能作为唯一的长期存档。

## 实际发布时

1. 提交并推送版本说明和验收通过的代码，核对候选的源码指纹与两个包的 SHA-256。
2. 发布明确选定的包后，在该版本目录补充 `publication.json`，记录发布时间、NuGet 源及两个包的链接、SHA-256、对应候选文件、SDK 提交和版本标签；同时更新 CHANGELOG 状态。上传失败或未上传时保留候选状态。
3. 为实际发布的 SDK 源码创建 `v<packageVersion>` 标签，将原始包、manifest 和完整验收材料保存为对应 Release 附件或长期制品；实际发布记录保持历史事实，后续修复使用新版本。

构建、提交、推送和创建候选记录均不会自动上传 NuGet。命令和门禁见 [单基线升级与发布](../single-target-workflow.md#发布候选验收)。
