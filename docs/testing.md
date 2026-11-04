# 测试依赖与运行方式

测试项目允许使用以下包，使用时固定版本并设置 `PrivateAssets="all"`。核心 SDK 的零运行时包依赖要求继续有效。

| 包 | 允许版本 | 当前用途 |
| --- | --- | --- |
| Microsoft.NET.Test.Sdk | 18.11.0 | 已引入：测试发现和执行 |
| MSTest.TestAdapter | 4.5.2 | 已引入：MSTest 适配器 |
| MSTest.TestFramework | 4.5.2 | 已引入：测试属性和断言 |
| coverlet.collector | 10.1.0 | 已引入：Cobertura 覆盖率收集 |
| AutoFixture | 4.18.1 | 允许按需引入：自动构造测试对象 |
| Bogus | 35.6.5 | 允许按需引入：有固定种子的业务测试数据 |
| Moq | 4.21.0 | 允许按需引入：依赖行为模拟 |
| PasswordGenerator | 3.0.0 | 允许按需引入：集成测试密码数据 |

目前手工构造的数据和 `HttpMessageHandler` 足以支持现有测试，因此后四个包尚未添加引用。引入数据生成器时仍须保证测试可复现，且不依赖随机值恰好满足断言。

## 常规测试

`tests/Keycloak.Admin.Sdk.Tests` 为标准 MSTest 项目，可以通过 IDE 测试资源管理器或以下命令运行：

```shell
dotnet test tests/Keycloak.Admin.Sdk.Tests -c Release --logger 'trx;LogFileName=contracts.trx' --results-directory artifacts/test-results --collect 'XPlat Code Coverage'
```

当前共 **538 个测试方法**：520 个按操作独立发现的功能契约矩阵用例，原有 11 项基础/六路径回归检查，新增 2 项 SAML `@JsonValue` 字符串和隐式 multipart 请求体回归，1 项覆盖全部发布模型的 JSON 往返检查，以及 4 项 URI、token、构造参数/内容所有权、流异常检查。原有冒烟仍执行 520 次调用，另有独立矩阵逐项断言功能契约。路由检查通过后，在仓库根目录 `artifacts/routing-verified.tsv` 写入证据。

矩阵期望值冻结在 `contracts/admin-api-test-matrix.json`，来源是独立 Java token 扫描器与发布 OpenAPI/已审定差异，不从 SDK 的 URI、请求序列化实现或原有生成冒烟样本计算期望值。每个操作测试声明的全部查询绑定（缺省、false/true、0/非零、Unicode、空串、重复/空列表）、不同路径参数的独立编码、完整/缺省请求体、成功状态/Location/header、完整/空集合/标量/空响应，以及 400/401/403/404/409/415/500、取消、网络失败和不重放。JSON 响应检查完整字段与非法 JSON；原始内容检查声明媒体类型及字节透传。服务端要求的具体文件/表单业务格式另由真实测试验证。

每个查询参数还会逐一隔离发送，其他参数保持缺省，以检出同类型参数被互换的错误。全量模型样本包含嵌套对象、集合、false/数字及未知扩展字段，反序列化再序列化后结构必须一致；每个 DTO 属性另以单字段对象序列化，核对其 C# 属性到 wire 字段的绑定，避免对称的读写错误相互抵消。六条易错分派路径继续保留手写专项测试。完整操作与用例映射见 [测试矩阵](contracts/admin-api-test-matrix.md)。

六组回归断言位于手写的 `AlignmentContracts.cs`，不从 OpenAPI 或生成器复用响应样本：工作流空/非空数组；policy 与 permission 的全部查询参数（含 `false`、`0`、编码及对象/数组分派）；身份提供方和本地化的 JSON/multipart；SMTP 的 JSON/form。测试会核对 MIME、multipart 字段与文件内容、表单编码及响应内容。

上述直接命令的 TRX 输出为 `artifacts/test-results/contracts.trx`；Cobertura 输出位于该目录的本次运行子目录。`Verify.cs` 每次使用新的 `artifacts/test-results/verify-<id>`，并把路径写入 `artifacts/test-results/latest.txt`。门禁只读取这次 TRX 引用的覆盖率附件，不能复用旧通过记录。

`dotnet run --file tools/Verify.cs` 先执行矩阵生成一致性检查及门禁负向自检，再执行 MSTest、覆盖率门禁和 SDK 零运行时包依赖检查。策略位于 [coverage-policy.json](../tests/coverage-policy.json)：操作及可执行方法 100%；生成 API 行/分支与 DTO 行 100%；SDK 自有源码分支 100%、行至少 99.9%；含 .NET 框架源生成实现的原始报告行至少 94%、分支至少 59%。自有源码保留全部 SDK 生成 API/DTO，只把 `obj/` 中框架生成代码另列；原始报告不删减。当前自有源码行 2398/2399（唯一未命中为 token 方法结束括号的 PDB 序列点）、分支 314/314，详细结果见 [覆盖率报告](contracts/test-coverage.md)。

每个操作必须有且仅有一个通过的矩阵测试；缺失、重复、跳过、失败、空覆盖率或指标不足都返回非零。`Check-Coverage.cs -- --self-test` 使用负向控制核验这些阻断条件；CI 同时上传 TRX、Cobertura 和门禁结果。`Generate-TestMatrix.cs -- --check` 检查冻结矩阵与强类型调用入口一致；审阅发布来源后可用 `-- --refresh-contracts` 更新期望，再提交契约及生成用例。该检查覆盖 SDK 功能契约，不等同于所有服务器业务/权限组合已实测。

## Native AOT 和真实容器测试

`tests/Keycloak.Admin.Sdk.AotSmoke` 为无测试框架包的独立原生程序，以源码链接执行全部 520 个功能契约矩阵、模型往返、公共异常分支及原有专项断言。它不引用 MSTest 项目程序集，发布时也不依赖测试适配器、覆盖率工具或反射发现测试。常规 MSTest 通过后，仍必须单独发布和运行此程序，才能形成 Native AOT 证据。

`tests/Keycloak.Admin.Sdk.IntegrationTests` 为可直接 Native AOT 发布的真实容器测试程序。通过 `dotnet run --file tools/Test-Integration.cs` 创建隔离环境并执行；加 `-- --native-aot` 会自动构建并运行 Linux 原生版本。工具使用 .NET 的 Process/HttpClient 管理 Docker、临时端口和就绪检查；凭据仅注入子进程环境，退出和取消时清理本次测试容器。具体操作见 [README](../README.md)。

`AlignmentLive.cs` 覆盖六条修复路径，`CallbackFixture.cs` 用 .NET TcpListener 提供 SAML 元数据 HTTP 服务和 SMTP 接收器，核验真实回调及两封邮件投递，不需要外部服务账号。托管测试通过 `host.docker.internal` 回调，原生测试共享 Keycloak 容器网络并使用 loopback。成功后分别写入 `artifacts/six-contracts-live-managed.txt` 和 `artifacts/six-contracts-live-native-aot.txt`；完整场景及本次验证结果见 [六路径修复记录](contracts/six-path-fixes.md)。

需要持久化 PostgreSQL 后端时，使用 [local/keycloak](../local/keycloak/README.md)：`dotnet run --file local/keycloak/Service.cs` 一键启动固定 Keycloak/PostgreSQL 镜像；`-- test` / `-- test-native` 在该服务上运行当前真实场景。工具生成并复用忽略提交的 `.env`，从运行中的服务核验版本和数据库 schema。测试支持 `KC_TEST_USERNAME`，并在 SMTP 夹具结束后恢复管理员邮箱，适合重复使用常驻环境。

全功能业务验收使用该入口的 `test-full` / `test-full-native`，共享同一套 `Full*.cs` 业务场景。强类型分派 `LiveRoutes.g.cs` 仅生成 SDK 调用，不生成业务前置条件或期望值；真实资源 ID、协议结果和持久化断言由手写场景提供。`LiveLedger` 只接受已观察到的成功 SDK 响应和通过的业务证明；缺失项非空即失败。两个路线的支持范围、预览排除原因和 FGAP 委派授权结果均显式记录。

本次在真实 Keycloak 26.8.1 + PostgreSQL 18.0 上通过 v2 正式路线 478/478、v1 兼容路线 492/492，托管及 Native AOT 均通过。LDAP 使用真实 OpenLDAP；SMTP、元数据/JWKS、X509/CRL、OIDC 登录/同意和 PostgreSQL/SCRAM 全部实际通信。缓存验证观察外部数据变更、密钥轮换和证书吊销后的结果，不以空 204 响应作为全部证明。结果见 [逐接口业务矩阵](contracts/full-live-acceptance.md)。

`Check-FullAcceptance.cs` 校验当前源码指纹、实际路线/版本、完整且唯一的成功记录和非空业务证明。`Test-AcceptanceGate.cs` 在独立 artifacts 副本上注入十类缺陷，确认门禁拒绝缺失、重复、失败响应、空证明、额外操作、过期代码、未完成、错误执行方式、错误排除清单和缺失 FGAP 撤销证据；原始实测证据保留。CI 对两条声明路线分别执行真实 PostgreSQL 托管/AOT 场景及这些负向控制。

## 工具技术栈

统一使用 .NET 10 / C#，SDK 版本固定 10.0.403。辅助入口为 .NET 文件式程序，通过 `#:include ScriptSupport.cs` 复用进程管理和仓库路径处理；不需要额外脚本运行器或脚本语言。契约解压使用 .NET TarReader/GZipStream，校验和报告处理使用 .NET 的 SHA256、JSON 和 XML API。YAML 配置文件统一使用 `.yaml`。

`dotnet run --file tools/Audit-Contracts.cs -- --online` 使用独立 Java token 扫描器对照发布源码、官方 OpenAPI、编译后的 SDK 目录和文档清单。它会写出 [审计报告](contracts/keycloak-26.8.1-alignment-audit.md) 与逐项 TSV；存在契约缺口时返回非零，不应将该结果描述为全部对齐。该静态检查与运行测试的职责不同。
