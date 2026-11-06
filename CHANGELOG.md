# 版本变更

记录可分发版本的变化；本地候选通过验收后生成的机器记录见 [docs/releases](docs/releases/README.md)。实际发布以对应发布记录中的 NuGet 链接和发布时间为准。

## 未发布

- 能力目录与支持配置增加 schema 2，按接口、FGAP 路线、运行模式及 Native AOT RID 记录验证；旧配置继续要求托管与原生证据。
- 主包提供统一宿主开关及可原子刷新的 AOT 配置快照，FeatureManagement 托管适配器复用同一门禁。
- 增加隔离功能验证、逐项晋升和最终受策略保护复验；构建指纹防止用旧程序验证新源码，发布流程检查所有已支持非 Stable 组合。FeatureManagement 负责最后的灰度开放和关闭，验证及晋升工具不修改宿主开关。
- Client Types 两个操作完成托管 v2 的独立验证与晋升，仍保留 Experimental 阶段并默认关闭；AOT 和 v1 组合不继承该支持状态。

## 26.8.1-preview.1（本地候选）

- SDK 包版本改为对齐 Keycloak 26.8.1；预览阶段使用 `preview.N` 递增。当前产出主包和 FeatureManagement 两个 NuGet 包。
- 修复升级隔离构建时缺少嵌入能力目录的问题，新目标仍从未验收状态开始。
- 工具编译检查使用隔离输出目录，避免 Windows 发布流程覆盖正在运行的程序。
- 发布流程将来源、包 SHA-256 和验收摘要同步保存到 Git 跟踪的目录，区分 SDK 提交与 Keycloak 上游提交。

当前尚未上传 NuGet。能力范围、兼容路线和排除项见 [README](README.md#keycloak-2681-能力边界)；验收结果以该版本的候选记录为准。
