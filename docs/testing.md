# 测试与验证

从仓库根目录运行；.NET SDK 版本以 [global.json](../global.json) 为准。文件式工具支持 `--help`；全部工具入口、参数和文件影响见 [tools 工具总览](tools-overview.md)。YAML 使用 `.yaml`；升级与发布验收见 [单基线流程](single-target-workflow.md)。

## 常用入口

| 目的 | 命令 |
| --- | --- |
| 构建、单测、覆盖率、打包 | `dotnet run --file tools/Verify.cs -- --skip-native-publish` |
| 同时验证当前平台 Native AOT | `dotnet run --file tools/Verify.cs` |
| 同时验证 Linux 容器 Native AOT | `dotnet run --file tools/Verify.cs -- --native-container` |
| 仅运行 MSTest | `dotnet test tests/Keycloak.Admin.Sdk.Tests -c Release` |
| 隔离 Keycloak 场景 | `dotnet run --file tools/Test-Integration.cs`；原生加 `-- --native-aot` |
| 两条路线、托管/AOT 全量验收及证据更新 | `dotnet run --file tools/Test-AllAdminRoutes.cs -- --update-docs` |
| 独立源码审计 | `dotnet run --file tools/Audit-Contracts.cs`；在线来源核验加 `-- --online` |
| 隔离非 Stable 功能验证 | `dotnet run --file tools/Test-Feature.cs -- --feature=client-types`；原生加 `--native-aot`，晋升后加 `--guarded` |
| 按操作、路线和环境晋升 | `dotnet run --file tools/Check-FeatureAcceptance.cs -- --evidence=<candidate.json> --promote` |
| 所有已支持非 Stable 组合复验 | `dotnet run --file tools/Test-SupportedFeatures.cs`；发布流程会自动执行 |

Windows 原生发布需要 Visual Studio C++ 桌面工具链和 Windows SDK；Linux 需要 clang、zlib 开发库，或使用上述 Docker 入口。跳过原生发布仅适用于常规开发检查。

非 Stable 功能按“候选验证 → 审阅晋升 → 受策略保护复验 → 宿主灰度”推进，职责、命令与失败处理见 [完整流程](non-stable-feature-lifecycle.md)。

## 测试工程分组

解决方案按 `tests/Unit`、`tests/Integration`、`tests/PackageConsumption` 分组。四个单元测试工程各自对应一个发布包；Platform 的微软开关与可选遥测断言独立执行。`Engineering.Tests` 验证验收证据、取消和子进程，不再让核心单测依赖 IntegrationTests。

核心托管测试和 AotSmoke 通过 `tests/Shared/CoreContracts.props` 显式共享 AOT 安全断言；不使用通配符引入 Managed 测试。两个包消费工程均纳入解决方案：AotSmoke 验证主包/Protocols 的原生包，Managed PackageSmoke 验证 Hosting/Platform 的实际 NuGet 图和默认关闭遥测。没有增加发布包。

## 契约测试与覆盖率

每个生成操作有一个独立 MSTest 入口，映射见 [测试矩阵](contracts/admin-api-test-matrix.md)。期望值冻结在 [admin-api-test-matrix.json](../contracts/admin-api-test-matrix.json)，来自独立 Java token 扫描和发布定义。查询参数逐一隔离测试，以检出同类型参数互换；模型同时检查嵌套往返与单字段 wire 映射，避免对称读写错误相互抵消。媒体类型、动态分派等另有 [手写专项断言](../tests/Shared/Contracts/AlignmentContracts.cs)。

操作矩阵通过 `IKeycloakAdminClient` 及生成资源接口调用。托管测试核对接口与实现的签名、参数名及默认值，并用 Moq 验证资源替换；DI 别名和六个原始入口的接口调用同时进入 Native AOT 验证。支持策略及平台开关面工厂另验证返回值可通过接口使用。

`Verify.cs` 检查生成一致性和门禁负向控制，再运行 MSTest，将本次目录写入 `artifacts/test-results/latest.txt`。覆盖率门禁只读取该次 TRX 引用的 Cobertura；操作缺失、重复、跳过、失败或低于 [coverage-policy.json](../tests/coverage-policy.json) 均返回非零。当前测试总数、实测指标及统计口径仅在 [覆盖率报告](contracts/test-coverage.md) 维护。

Platform 与 Hosting 分别由 `Check-ModuleCoverage.cs` 读取独立 TRX/Cobertura，报告见 [Platform](contracts/platform-coverage.md)、[Hosting](contracts/hosting-coverage.md)。Platform 保持方法/行/分支 100%；Hosting 根据现有实测设防退化门槛（方法 90%、行 79%、分支 75%），不宣称 100%。策略见 [module-coverage-policy.json](../tests/module-coverage-policy.json)。

需要单独收集覆盖率时：

```shell
dotnet test tests/Keycloak.Admin.Sdk.Tests -c Release --logger 'trx;LogFileName=contracts.trx' --results-directory artifacts/test-results/manual-run --collect 'XPlat Code Coverage'
dotnet run --file tools/Check-Coverage.cs -- --results=artifacts/test-results/manual-run
```

每次使用新的结果目录。`Generate-TestMatrix.cs -- --check` 核对冻结矩阵与强类型入口；审阅来源后可用 `-- --refresh-contracts` 更新。`Check-Coverage.cs -- --self-test` 验证门禁拒绝条件。

## 依赖边界

常规测试的直接包引用均设为 `PrivateAssets="all"`，项目不可打包；MSTest 和 Coverlet 版本统一定义在 [测试构建配置](../tests/Directory.Build.props)。

| 包 | 用途 |
| --- | --- |
| Microsoft.NET.Test.Sdk、MSTest.TestAdapter、MSTest.TestFramework | 测试发现、运行及断言 |
| coverlet.collector | Cobertura 覆盖率 |
| AutoFixture、Bogus | 请求样本、局部固定种子的用户数据 |
| Moq、PasswordGenerator | token/策略交互次数、密码透传与错误脱敏 |

`ManagedTestDataTests.cs` 中的测试数据工具只进入 MSTest 项目，不进入 AOT。关键字段、密码策略边界仍用明确样本；随机测试不依赖特定输出。核心包不引用测试依赖，`Verify.cs` 检查四个 nuspec 的直接依赖清单及包数量。

`Verify.cs` 在本开发分支将主包、Platform、Protocols 和 Hosting 四个包写入 `artifacts/packages/<packageVersion>/`。主包直接依赖 Microsoft.Extensions.Http 10.0.14 和 Microsoft.Extensions.Http.Resilience 10.11.0；Platform 直接依赖 Protocols、Microsoft.FeatureManagement 4.8.0 和官方 Application Insights 遥测适配器，主包为传递依赖，Platform 仅声明 Managed 支持；Protocols 依赖主包、IdentityModel、COSE 和 CBOR；Hosting 依赖 Protocols、ASP.NET Core OIDC/JWT、ITfoxtec SAML、Pkcs 和 Xml，要求 ASP.NET Core 10.0.14 或更高的 10.0 补丁版本，仅声明 Managed 支持。Hosting 保留 Pkcs/Xml 10.0.14 的显式 NuGet 依赖，并用未声明直接 ASP.NET Core FrameworkReference 的独立消费项目验证实际恢复版本。独立的版本目录避免混入其他版本产物。

`ResilienceContracts.cs` 的七组测试验证默认关闭、408/429/5xx/连接故障重试及响应释放、写入/内容/Token POST 排除、401 组合次数与策略单次判断、单次/总超时、Retry-After、取消、命名读熔断及流交付边界；校验所有配置限制。该文件同时链接到 AotSmoke，原生程序从本次 NuGet 包还原并实际启用管道，覆盖序列化关闭反射及裁剪边界。

## 原生与真实业务验收

`Verify.cs` 的原生步骤通过 `SdkPackageFeed` 让 `AotSmoke` 引用本次本地 NuGet 主包与 Protocols 包（不引用 Managed Platform），源码链接执行完整管理操作矩阵、模型、适用的运行时、DI、能力策略及协议传输断言。直接构建 `AotSmoke` 项目时默认使用项目引用。托管通过后仍需实际发布并运行原生程序。Managed 快照验收记录 `snapshot-v1`，Native AOT 使用核心快照夹具并记录 `core-snapshot-v1`；官方微软引擎与遥测只在 Managed 单测中验证，详见 [平台开关面](platform-feature-gate.md)。

应用协议使用独立的 `Keycloak.Admin.Sdk.Protocols.Tests` 测试集和 `Check-ProtocolCoverage.cs` 门禁，要求其源码行和分支覆盖率 100%。`Test-ApplicationProtocols.cs` 对固定版本的临时 Keycloak 实例运行选定真实工作流，原生加 `--native-aot`；这些结果不等于完整协议晋升。全能力覆盖情况见 [矩阵](contracts/platform-capability-matrix.md) 和 [实施说明](full-platform-coverage.md)。

`Test-Integration.cs` 使用固定 digest、临时本机端口和隔离 realm，退出时清理容器。原生模式自动构建 Linux 程序；已有二进制可加 `--no-build-native`。需要持久化 PostgreSQL 时使用 [本地服务](../local/keycloak/README.md) 的 `test` / `test-native`，全量业务验收使用 `test-full` / `test-full-native`。

全量场景位于手写的 `Full*.cs`；生成的 `LiveRoutes.g.cs` 仅分派调用。`LiveLedger` 要求成功 SDK 响应及已通过的业务断言，未完成项非空即失败。验收数量、协议效果、排除项及执行时间见 [真实验收](contracts/full-live-acceptance.md)，不重复维护在本页。

`Check-FullAcceptance.cs` 核对源码指纹、版本、路线和唯一完整的业务记录；`Test-AcceptanceGate.cs` 在副本中注入十四类缺陷，验证缺失、重复、失败、空证明、过期代码、错误模式/排除项及缺少权限撤销、支持策略或平台 gate 业务守卫证明均被拒绝。CI 的 [verify.yaml](../.github/workflows/verify.yaml) 运行 Windows/Linux 常规及原生检查，并按两条路线执行真实 PostgreSQL 托管/AOT 验收。
