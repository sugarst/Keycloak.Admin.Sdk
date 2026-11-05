# 单基线升级与发布流程

每个 SDK 构建和 NuGet 包只声明一个精确的 Keycloak 版本。主分支完整替换为新的目标版本；历史实现、契约和验收结果通过 Git tag、历史包及发布附件追溯。核心保持零运行时 NuGet 依赖与严格 Native AOT，FeatureManagement/遥测为独立托管扩展。

## 唯一基线

`contracts/baseline.json` 声明 Keycloak 版本、源码 commit/归档哈希、OpenAPI 哈希、固定镜像 digest、接口数量、SDK 包版本、.NET SDK 和容器环境。`Target.props`、`KeycloakTarget.g.cs` 和 `global.json` 为派生文件；`Check-Baseline.cs` 核验一致性，`--sync` 同步派生值。包版本独立于 Keycloak 版本，新的目标必须使用新的包版本，已发布包不能覆盖。

活跃契约固定使用 `contracts/openapi.json`、`capabilities.json`、`capability-rules.json`、`overrides.json` 和测试矩阵，不建立多版本注册表。`KeycloakCapabilityCatalog.Current` 是当前唯一目录；未知版本仍明确拒绝。能力规则记录上游阶段、服务端 feature 和适用路线，并与当前源码 `Profile.java` 核验，阶段与路线分别声明。

## 准备上游升级

为实际发布的上游版本准备一个经过审阅的候选目录，包含：

```text
baseline.json
admin-api-routes.json
capability-rules.json
overrides.json
support-policy.example.json
feature-management.example.json
openapi.json                       # 可选；省略时从该版本官方地址下载
```

先检查发布源码、迁移说明、接口范围、功能阶段及 FGAP 路线，再填写 commit、哈希、digest、接口数和新包版本。不能仅修改版本字符串。来源变更时还需审查 Java 索引器、显式修正以及手写业务场景。

```shell
dotnet run --file tools/Upgrade.cs -- --candidate=artifacts/candidate
dotnet run --file tools/Upgrade.cs -- --candidate=artifacts/candidate --apply
```

第一条在 `artifacts/upgrade/<id>` 的隔离副本生成候选，输出 `upgrade-diff.json`，不会改动活跃代码。报告包含新增/删除/签名变化、OpenAPI 结构差异及来源哈希。第二条重新准备、校验并安装整套替换结果；期间失败不安装，安装异常恢复已保存文件。

源码归档先校验 SHA256，再解包到全新目录，完成后替换当前提取目录，避免上游删除的 Java 文件残留。生成器完整重建 API、DTO、JSON 元数据、独立测试矩阵及真实调用分派；安装时删除退出生成集合的 `.g.cs`。候选不会复制本机 `.env`。新目标的能力目录从 `Contract` / `NotSupported` 开始，旧真实验收文档与证据移除，禁止继承旧版本的通过状态。

`Test-Workflow.cs` 在隔离副本实测错误哈希不改主目录、只读准备、实际安装清理退役 API/旧证据，以及所有能力重置为未获真实验收。

## 发布前全量验收

```shell
dotnet run --file tools/Release.cs
```

统一入口依次执行：

1. 基线核验、完整重新生成、升级流程自检、官方 tag/OpenAPI 与源码审计。
2. 如果目录尚未验收，先在真实服务上执行两条路线、托管与 Native AOT 的完整业务场景，形成首次业务证据，再晋升支持状态。
3. 编译和生成一致性检查、全部单测、覆盖率门禁、核心包零依赖检查及严格 Native AOT 发布运行。
4. 使用最终能力策略客户端重新执行两条路线、两种运行模式的全量真实验收，包含本地支持策略拦截，以及托管 FeatureManagement 的真实数据变化。
5. 两条路线各执行十三项验收门禁负向控制，更新逐接口清单，最后再次核验当前源码指纹。
6. 收集五个当前包及证据，生成包含目标版本、包版本、源码指纹和包 SHA256 的 `release-manifest.json`。

首次业务验收仅在测试程序中显式选择 `bootstrap-wire`，没有跳过业务断言、权限或协议验证。该模式没有最终支持策略/FeatureManagement 拦截证明，默认发布门禁会拒绝，不能导出为正式证据。晋升后必须重跑最终受策略客户端；生成器的 `--promote` 也先核验当前源码的四份首次验收证据。`Release.cs -- --bootstrap` 可强制完整演练这个过程。

任何阶段失败，流程停止且不会输出成功发布清单。执行前已有的产物仍可能留在 artifacts，发布应以本次成功日志及其 manifest 为准。该命令生成候选产物，不自动提交、推送或上传 NuGet。

输出目录为 `artifacts/releases/<packageVersion>/<sourceFingerprint>/`。常规开发可运行 `Verify.cs -- --native-container`；省略真实验收的检查不能作为发布验收。CI 的 `release.yaml` 手动工作流运行同一条 `Release.cs` 命令并上传产物，不实施发布。

## 本地数据库和升级边界

`Service.cs` 从基线读取固定 Keycloak/PostgreSQL 镜像及实际版本要求，并核对运行服务。数据卷所属目标版本写入忽略提交的 `.env`；目标改变时停止启动，要求使用者选择数据库备份/迁移或显式 `reset --delete-data`。工具不会自动删除数据卷。普通验收结束恢复目标版本的 v2 服务。

当前实现保留 26.8.1 已审定的 FGAP v1 兼容与 v2 正式路线。新上游若删除路线或改变业务契约，必须同步调整规则、验收编排及手写场景；升级工具会生成差异并阻断未通过的生成/验收，不承诺任意未来版本无需改代码。
