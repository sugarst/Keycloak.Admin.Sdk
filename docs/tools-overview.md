# tools 工具总览

本文介绍 `tools/` 下的入口、参数及主要文件影响。测试和验收细节见 [测试与验证](testing.md)，目标升级的完整顺序见 [单基线流程](single-target-workflow.md)。

## 运行方式与前置条件

以下命令均从仓库根目录运行，使用 [global.json](../global.json) 固定的 .NET SDK。`tools/*.cs` 中的独立入口使用 .NET 文件式 C#：

```powershell
dotnet run --file tools/Verify.cs -- --help
```

`--` 后的参数传给工具；`--help` 或 `-h` 显示该工具的用法。多数工具会构建项目或在 `artifacts/` 写入产物；即使是 `--check`，也不应把它理解为整个执行过程完全不写磁盘。`--check` 的作用是比较生成结果，不覆盖它检查的目标文件。

真实 Keycloak 验收和容器原生构建需要可用的 Docker。当前平台 Native AOT 还需要对应的本机编译工具；Windows 需要 C++ 桌面工具链和 Windows SDK。在线审计、下载缺失的固定来源或还原缺失的依赖需要网络。首次生成/审计通常需要由契约更新流程准备的固定源码归档及提取目录，来源、哈希和版本以 [baseline.json](../contracts/baseline.json) 为准。

部分命令会覆盖生成文件、更新文档或切换本地容器。执行前先检查工作区改动；生成和验收结果需要按实际差异审阅，不能把旧产物视为本次通过的证据。

## 日常验证

| 工具 | 常用命令 | 用途及影响 |
| --- | --- | --- |
| [Verify.cs](../tools/Verify.cs) | `dotnet run --file tools/Verify.cs -- --skip-native-publish` | 执行基线检查、构建、生成一致性检查、单测、覆盖率门禁和本地打包。写入 `artifacts/`，成功时更新覆盖率报告。省略参数会发布并运行当前平台的 Native AOT 测试程序；`--native-container` 改用 Docker 验证 Linux Native AOT。两个参数不能同时使用。 |
| [Test-Integration.cs](../tools/Test-Integration.cs) | `dotnet run --file tools/Test-Integration.cs` | 使用固定镜像启动隔离 Keycloak，运行真实服务集成测试并在结束时清理本次容器；写入本地验证产物。`--native-aot` 先构建并运行原生集成程序；`--native-aot --no-build-native` 复用已构建程序。 |
| [Check-Coverage.cs](../tools/Check-Coverage.cs) | `dotnet run --file tools/Check-Coverage.cs -- --results=artifacts/test-results/<run>` | 读取该目录的 `contracts.trx` 和其 Cobertura 附件，检查矩阵与覆盖率门槛；通过后写入摘要及 `docs/contracts/test-coverage.md`。`--self-test` 验证门禁的负向控制。 |
| [Check-Baseline.cs](../tools/Check-Baseline.cs) | `dotnet run --file tools/Check-Baseline.cs` | 校验基线、派生配置、契约和 OpenAPI 哈希。`--sync` 根据基线写入派生配置；`--self-test` 执行负向控制。 |
| [Check-AdminRoutes.cs](../tools/Check-AdminRoutes.cs) | `dotnet run --file tools/Check-AdminRoutes.cs` | 检查两条路线的声明及负向控制；`--source` 额外读取固定 Keycloak Java 源码核验 feature 阶段。 |

不带结果目录运行 `Check-Coverage.cs` 时默认使用 `artifacts/test-results`；应确保该目录包含对应的一次测试结果，而不是旧报告。测试结果和覆盖率的完整命令见 [测试说明](testing.md)。

## 真实服务验收与证据

| 工具 | 常用命令 | 用途及影响 |
| --- | --- | --- |
| [Test-AllAdminRoutes.cs](../tools/Test-AllAdminRoutes.cs) | `dotnet run --file tools/Test-AllAdminRoutes.cs -- --update-docs` | 依次执行 v1、v2 路线的托管和 Linux Native AOT 全量业务验收，再核验结果并更新证据文档。会操作本地 Keycloak 服务和容器，结束时尝试恢复普通 v2 服务；需要 Docker、本地服务环境和较长时间。`--bootstrap` 生成首次验收证据，不能与 `--update-docs` 同用。 |
| [Check-FullAcceptance.cs](../tools/Check-FullAcceptance.cs) | `dotnet run --file tools/Check-FullAcceptance.cs` | 核验已有的两条路线、两种运行模式证据和当前源码指纹；默认读取 `artifacts/full-live/`。`--v1` 或 `--v2` 只检查一条路线；`--evidence=<artifacts子目录>` 指定另一份证据；`--update-docs` 要求原始证据目录及两条完整路线，并更新受版本控制的验收报告和证据文件。 |
| [Test-AcceptanceGate.cs](../tools/Test-AcceptanceGate.cs) | `dotnet run --file tools/Test-AcceptanceGate.cs -- --v2` | 在 `artifacts/` 中复制已有证据并注入缺失、重复、旧指纹等缺陷，验证门禁拒绝。支持 `--v1` 或 `--v2`；不指定时使用 v2。先准备对应路线完整且可通过的证据。 |
| [Test-Fingerprint.cs](../tools/Test-Fingerprint.cs) | `dotnet run --file tools/Test-Fingerprint.cs` | 构建 Linux 原生集成程序，对比编排器、托管程序和原生程序的源码指纹；需要 Docker，会写入原生产物。 |
| [Test-ApplicationProtocols.cs](../tools/Test-ApplicationProtocols.cs) | `dotnet run --file tools/Test-ApplicationProtocols.cs` | 隔离运行应用协议标准计划；`--native-aot` 验证 Linux 原生运行时，`--legacy` 选择旧版兼容计划。标准计划使用固定镜像的 MIT Kerberos 对端。`--wallet-only`、`--authentication-only` 等诊断不生成可晋升报告；`--support-only` 复验最终支持策略。 |
| [Check-ApplicationProtocols.cs](../tools/Check-ApplicationProtocols.cs) | `dotnet run --file tools/Check-ApplicationProtocols.cs -- --archive` | 校验当前输入、实际程序哈希、全部业务断言和固定对端镜像，归档托管／原生报告并晋升能力；旧版计划另加 `--legacy`。诊断结果不能代替完整计划。 |
| [Update-Verification.cs](../tools/Update-Verification.cs) | `dotnet run --file tools/Update-Verification.cs` | 读取 `artifacts/routing-verified.tsv` 和 `artifacts/live-endpoints.tsv`，更新 `docs/contracts/endpoint-inventory.md` 并复制实时观测文件。运行前确认输入来自需要记录的测试。 |

完整验收使用的本地持久化数据库、路线切换和服务命令见 [local/keycloak/README.md](../local/keycloak/README.md)。验收工具产生的观测不等同于所有服务器配置、权限和第三方扩展均已验证。

## 契约、生成与审计

| 工具 | 常用命令 | 用途及影响 |
| --- | --- | --- |
| [Audit-Contracts.cs](../tools/Audit-Contracts.cs) | `dotnet run --file tools/Audit-Contracts.cs` | 独立扫描固定 Java 源码，对比 SDK 与 OpenAPI；写入 `artifacts/alignment/` 及 `docs/contracts/` 下的审计报告和清单。`--online` 额外核验官方 tag 和 OpenAPI，需要网络。发现差异时可能返回非零。 |
| [Update-Contracts.cs](../tools/Update-Contracts.cs) | `dotnet run --file tools/Update-Contracts.cs` | 校验固定来源并调用生成器，重建 SDK 生成代码、契约、清单和生成测试。缺失源码归档时会下载；会覆盖生成文件及报告，应先检查工作区。 |
| [Generate-TestMatrix.cs](../tools/Generate-TestMatrix.cs) | `dotnet run --file tools/Generate-TestMatrix.cs -- --check` | 从冻结的测试矩阵生成强类型测试入口并核对。`--check` 不覆盖生成目标；不带参数会写入生成文件和测试文档；`--refresh-contracts` 还会根据已校验的独立源码及 OpenAPI 刷新冻结矩阵。 |
| [Generate-LiveRoutes.cs](../tools/Generate-LiveRoutes.cs) | `dotnet run --file tools/Generate-LiveRoutes.cs -- --check` | 根据 SDK 目录和矩阵生成真实验收的调用分派。`--check` 只比较目标；不带参数会重写 `LiveRoutes.g.cs`。 |
| [Generate-CapabilityCatalog.cs](../tools/Generate-CapabilityCatalog.cs) | `dotnet run --file tools/Generate-CapabilityCatalog.cs -- --check` | 结合当前目标规则和固定 Java 源码生成或核对能力目录。`--check` 比较现有目录；不带参数会写入目录；`--seed` 重建仅含契约验证的初始支持状态；`--promote` 先核验首次真实验收证据，再写入晋升结果。三种参数互斥。 |
| [Generate-PlatformMatrix.cs](../tools/Generate-PlatformMatrix.cs) | `dotnet run --file tools/Generate-PlatformMatrix.cs -- --require-complete` | 从固定上游功能、审阅责任边界和当前独立晋升证据生成全能力矩阵。`--check` 校验生成一致性；`--require-complete` 拒绝缺少应用能力或 Admin 操作支持配置的目标。 |
| [Check-ProtocolCoverage.cs](../tools/Check-ProtocolCoverage.cs) | `dotnet run --file tools/Check-ProtocolCoverage.cs -- --results=artifacts/protocol-test-results/<run>` | 检查独立协议测试及源码行／分支覆盖率，要求 100%；完整调用由 `Verify.cs` 编排。 |
| [Generate-ValidationList.cs](../tools/Generate-ValidationList.cs) | `dotnet run --file tools/Generate-ValidationList.cs` | 根据支持矩阵和真实验收表重写 `docs/contracts/admin-api-validation-list.md`。 |

直接调用 [Keycloak.Admin.Sdk.Generator](../tools/Keycloak.Admin.Sdk.Generator/Program.cs) 的项目入口需要两个参数：仓库根目录和已准备的 Keycloak 源码根目录。该生成器会删除并重建生成 API 集合、写入契约和文档；通常使用 `Update-Contracts.cs` 统一处理固定来源校验，不建议在未审阅输入时直接调用。

## 目标升级与候选验收

非 Stable 能力的逐环境工作流：`Test-Feature.cs -- --feature=client-types [--native-aot] [--v1]` 执行隔离候选验证；`Check-FeatureAcceptance.cs -- --evidence=<path> --promote` 只晋升已证明的组合；随后 `Test-Feature.cs -- --feature=client-types --guarded` 验证最终目录和宿主开关。`Test-SupportedFeatures.cs` 自动复验所有已支持组合，`Release.cs` 调用它作为附加发布门禁。具体证据规则见[能力策略](capability-policy.md#非-stable-功能的验证与晋升)。

| 工具 | 常用命令 | 用途及影响 |
| --- | --- | --- |
| [Upgrade.cs](../tools/Upgrade.cs) | `dotnet run --file tools/Upgrade.cs -- --candidate=artifacts/candidate` | 在 `artifacts/upgrade/<id>/` 隔离准备新目标并生成差异，不替换活跃源码。添加 `--apply` 会重新准备并安装替换结果，删除不再生成的 API 和旧验收证据；使用前审阅候选和工作区。候选输入要求见 [单基线流程](single-target-workflow.md)。 |
| [Test-Workflow.cs](../tools/Test-Workflow.cs) | `dotnet run --file tools/Test-Workflow.cs` | 在 `artifacts/workflow-test/` 的隔离副本中测试升级准备、失败和安装行为；需要已准备的固定源码归档，会在副本中构建和改写文件。 |
| [Release.cs](../tools/Release.cs) | `dotnet run --file tools/Release.cs` | 执行基线检查、重建、审计、托管/Native AOT 和两路线真实验收，最终收集本地候选及 manifest，并同步记录到 `docs/releases/<版本>/<源码指纹>.json`；需要 Docker、网络和较长时间，会更新生成文件、证据及报告。`--bootstrap` 强制执行首次验收阶段，然后仍须完成最终策略客户端验收。此入口不提交、推送或发布 NuGet。 |

这些工具可以覆盖或清理生成内容；特别是 `Upgrade.cs --apply` 和完整候选验收，应先阅读对应详细流程并确认所用基线、工作区及本地服务环境。

## 辅助代码

- [ScriptSupport.cs](../tools/ScriptSupport.cs)：供文件式工具共用的参数、取消、路径和子进程支持；不是独立命令。
- [TargetBaseline.cs](../tools/TargetBaseline.cs)：解析和校验单目标基线，供多个工具及生成器引用；不是独立命令。
- [ApplicationAcceptance.cs](../tools/ApplicationAcceptance.cs) 与 [PlatformCoverage.cs](../tools/PlatformCoverage.cs)：应用计划、证据晋升与矩阵计算的共用实现。
- [Stamp-ApplicationInputs.cs](../tools/Stamp-ApplicationInputs.cs)：构建时绑定当前验证输入，避免旧程序为新源码出具验收证据。
- [ProtocolTlsFixture.cs](../tools/ProtocolTlsFixture.cs) 与 [ProtocolKerberosFixture.cs](../tools/ProtocolKerberosFixture.cs)：隔离验收的临时 TLS 材料及 MIT Kerberos 对端编排；私钥和 keytab 不进入归档报告。
- [JavaAuditIndex.cs](../tools/JavaAuditIndex.cs)：独立 Java token 扫描器，供契约审计和测试矩阵使用；不是独立命令。
- [Keycloak.Admin.Sdk.Generator/Program.cs](../tools/Keycloak.Admin.Sdk.Generator/Program.cs) 与 [JavaRoutes.cs](../tools/Keycloak.Admin.Sdk.Generator/JavaRoutes.cs)：生成器入口及 Java 路由发现实现，属于独立 .NET 项目，不使用上述文件式工具的 `--help` 约定。
