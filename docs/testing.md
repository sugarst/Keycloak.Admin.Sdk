# 测试与验证

从仓库根目录运行；.NET SDK 版本以 [global.json](../global.json) 为准。辅助工具统一为 .NET 文件式 C#，支持 `--help`；YAML 使用 `.yaml`。升级与发布验收见 [单基线流程](single-target-workflow.md)。

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

Windows 原生发布需要 Visual Studio C++ 桌面工具链和 Windows SDK；Linux 需要 clang、zlib 开发库，或使用上述 Docker 入口。跳过原生发布仅适用于常规开发检查。

## 契约测试与覆盖率

每个生成操作有一个独立 MSTest 入口，映射见 [测试矩阵](contracts/admin-api-test-matrix.md)。期望值冻结在 [admin-api-test-matrix.json](../contracts/admin-api-test-matrix.json)，来自独立 Java token 扫描和发布定义。查询参数逐一隔离测试，以检出同类型参数互换；模型同时检查嵌套往返与单字段 wire 映射，避免对称读写错误相互抵消。媒体类型、动态分派等另有 [手写专项断言](../tests/Keycloak.Admin.Sdk.Tests/AlignmentContracts.cs)。

`Verify.cs` 检查生成一致性和门禁负向控制，再运行 MSTest，将本次目录写入 `artifacts/test-results/latest.txt`。覆盖率门禁只读取该次 TRX 引用的 Cobertura；操作缺失、重复、跳过、失败或低于 [coverage-policy.json](../tests/coverage-policy.json) 均返回非零。当前测试总数、实测指标及统计口径仅在 [覆盖率报告](contracts/test-coverage.md) 维护。

需要单独收集覆盖率时：

```shell
dotnet test tests/Keycloak.Admin.Sdk.Tests -c Release --logger 'trx;LogFileName=contracts.trx' --results-directory artifacts/test-results/manual-run --collect 'XPlat Code Coverage'
dotnet run --file tools/Check-Coverage.cs -- --results=artifacts/test-results/manual-run
```

每次使用新的结果目录。`Generate-TestMatrix.cs -- --check` 核对冻结矩阵与强类型入口；审阅来源后可用 `-- --refresh-contracts` 更新。`Check-Coverage.cs -- --self-test` 验证门禁拒绝条件。

## 依赖边界

常规测试的直接包引用均设为 `PrivateAssets="all"`，项目不可打包；准确版本见 [测试项目](../tests/Keycloak.Admin.Sdk.Tests/Keycloak.Admin.Sdk.Tests.csproj)。

| 包 | 用途 |
| --- | --- |
| Microsoft.NET.Test.Sdk、MSTest.TestAdapter、MSTest.TestFramework | 测试发现、运行及断言 |
| coverlet.collector | Cobertura 覆盖率 |
| Microsoft.Extensions.Configuration.Json | FeatureManagement 配置；托管集成程序也直接引用 |
| AutoFixture、Bogus | 请求样本、局部固定种子的用户数据 |
| Moq、PasswordGenerator | token/策略交互次数、密码透传与错误脱敏 |

`ManagedTestDataTests.cs` 中的测试数据工具只进入 MSTest 项目，不进入 AOT。关键字段、密码策略边界仍用明确样本；随机测试不依赖特定输出。核心包不引用测试依赖，`Verify.cs` 检查两个 nuspec 的直接依赖清单及包数量。

`Verify.cs` 将本次两个包写入 `artifacts/packages/<packageVersion>/`。主包直接依赖 Microsoft.Extensions.Http 10.0.14 和 Microsoft.Extensions.Http.Resilience 10.11.0；FeatureManagement 包依赖主包和两个微软功能开关/遥测包。独立的版本目录避免混入早期五包产物。

`ResilienceContracts.cs` 的七组测试验证默认关闭、408/429/5xx/连接故障重试及响应释放、写入/内容/Token POST 排除、401 组合次数与策略单次判断、单次/总超时、Retry-After、取消、命名读熔断及流交付边界；校验所有配置限制。该文件同时链接到 AotSmoke，原生程序从本次 NuGet 包还原并实际启用管道，覆盖序列化关闭反射及裁剪边界。

## 原生与真实业务验收

`Verify.cs` 的原生步骤通过 `SdkPackageFeed` 让 `AotSmoke` 引用本次本地 NuGet 主包，源码链接执行完整操作矩阵、模型和适用的运行时、DI、能力策略断言。直接构建 `AotSmoke` 项目时默认使用项目引用。托管通过后仍需实际发布并运行原生程序。FeatureManagement 及其遥测模块在托管模式验证，详见 [接入指南](feature-management.md)。

`Test-Integration.cs` 使用固定 digest、临时本机端口和隔离 realm，退出时清理容器。原生模式自动构建 Linux 程序；已有二进制可加 `--no-build-native`。需要持久化 PostgreSQL 时使用 [本地服务](../local/keycloak/README.md) 的 `test` / `test-native`，全量业务验收使用 `test-full` / `test-full-native`。

全量场景位于手写的 `Full*.cs`；生成的 `LiveRoutes.g.cs` 仅分派调用。`LiveLedger` 要求成功 SDK 响应及已通过的业务断言，未完成项非空即失败。验收数量、协议效果、排除项及执行时间见 [真实验收](contracts/full-live-acceptance.md)，不重复维护在本页。

`Check-FullAcceptance.cs` 核对源码指纹、版本、路线和唯一完整的业务记录；`Test-AcceptanceGate.cs` 在副本中注入十三类缺陷，验证缺失、重复、失败、空证明、过期代码、错误模式/排除项及缺少权限撤销、支持策略或功能开关证明均被拒绝。CI 的 [verify.yaml](../.github/workflows/verify.yaml) 运行 Windows/Linux 常规及原生检查，并按两条路线执行真实 PostgreSQL 托管/AOT 验收。
