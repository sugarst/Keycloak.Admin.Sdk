# 单基线升级与发布

每个 SDK 构建及包只声明一个精确 Keycloak 版本，升级完整替换活跃实现；历史契约和结果通过 Git tag、包及发布附件追溯。

## 基线

[baseline.json](../contracts/baseline.json) 是版本、commit、归档/OpenAPI 哈希、镜像、接口数、包版本和 .NET SDK 的唯一来源。`Target.props`、`KeycloakTarget.g.cs`、`global.json` 为派生值，`Check-Baseline.cs` 核验，`--sync` 同步。新目标须使用新的包版本。

活跃契约固定使用 `contracts/` 下的当前文件，能力目录通过 `KeycloakCapabilityCatalog.Current` 访问。规则记录上游阶段、服务端 feature 及适用路线，并与发布源码 `Profile.java` 核验。

## 准备升级

候选目录须包含已审阅文件：

```text
baseline.json
admin-api-routes.json
capability-rules.json
overrides.json
support-policy.example.json
feature-management.example.json
openapi.json                       # 可选，省略时下载该版本官方定义
```

先审阅发布源码、迁移说明、接口变化和功能阶段，再填写 commit、哈希、digest、接口数及包版本；不能只替换版本字符串。来源变化可能需要调整 Java 索引器、显式修正和手写业务场景。

```shell
dotnet run --file tools/Upgrade.cs -- --candidate=artifacts/candidate
dotnet run --file tools/Upgrade.cs -- --candidate=artifacts/candidate --apply
```

第一条在 `artifacts/upgrade/<id>` 隔离生成，输出 `upgrade-diff.json`（路由、签名、OpenAPI 结构及哈希），不改活跃代码。第二条重新准备、校验并安装；准备失败不安装，安装异常恢复已保存文件。

源码归档先验 SHA256 再解包到新目录，避免已删除 Java 文件残留。安装删除退役 `.g.cs` 与旧真实验收证据，不复制本机 `.env`；新能力从 Contract / NotSupported 开始。`Test-Workflow.cs` 在隔离副本验证这些行为。

## 发布候选验收

```shell
dotnet run --file tools/Release.cs
```

入口顺序：

1. 核验基线、完整重建、自检升级流程，在线核验官方 tag/OpenAPI 并审计源码。
2. 新目录尚未验收时，执行两路线、托管/AOT 的首次业务验收，再晋升能力支持。
3. 执行构建、单测、覆盖率、打包、核心零依赖检查及严格 Native AOT。
4. 用最终能力策略客户端重跑四套真实验收，包含本地拦截及托管功能开关的数据断言。
5. 验证两路线各十三项门禁负向控制，更新逐项清单并核对源码指纹。
6. 收集五个包及证据，写入含版本、指纹和包 SHA256 的 `release-manifest.json`。

首次验收只在测试程序显式使用 `bootstrap-wire`，业务断言不减少，但没有最终策略拦截证明，不能导出为发布证据。`--promote` 核验四份首次证据，晋升后必须重跑最终客户端。`Release.cs -- --bootstrap` 可强制演练。

失败即停止，不输出成功 manifest；旧 artifacts 可能保留，以本次成功清单为准。输出位于 `artifacts/releases/<packageVersion>/<sourceFingerprint>/`。命令只生成候选，不提交、推送或发布 NuGet。[release.yaml](../.github/workflows/release.yaml) 手动工作流执行同一入口。

## 数据与路线边界

本地服务记录数据卷所属目标版本，基线改变时停止启动，要求选择备份/迁移或显式 `reset --delete-data`，不自动删卷。操作见 [本地环境](../local/keycloak/README.md)。

当前 v1 兼容和 v2 正式路线在 [路线配置](../contracts/admin-api-routes.json) 定义。上游删除路线或改变业务契约时，必须同步规则、编排和手写场景；工具不承诺任意未来版本无需改代码。
