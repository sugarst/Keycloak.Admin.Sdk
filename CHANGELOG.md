# 版本变更

记录可分发版本的变化；本地候选通过验收后生成的机器记录见 [docs/releases](docs/releases/README.md)。实际发布以对应发布记录中的 NuGet 链接和发布时间为准。

## 26.8.1-preview.1（本地候选）

- SDK 包版本改为对齐 Keycloak 26.8.1；预览阶段使用 `preview.N` 递增。当前产出主包和 FeatureManagement 两个 NuGet 包。
- 修复升级隔离构建时缺少嵌入能力目录的问题，新目标仍从未验收状态开始。
- 发布流程将来源、包 SHA-256 和验收摘要同步保存到 Git 跟踪的目录，区分 SDK 提交与 Keycloak 上游提交。

当前尚未上传 NuGet。能力范围、兼容路线和排除项见 [README](README.md#keycloak-2681-能力边界)；验收结果以该版本的候选记录为准。
