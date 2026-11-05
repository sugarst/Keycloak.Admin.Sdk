# Keycloak.Admin.Sdk

面向 **.NET 10 / Native AOT** 的 Keycloak 26.8.1 Admin REST API 客户端。固定 SDK **10.0.403**，核心库无运行时 NuGet 包依赖，JSON 使用源生成元数据，默认关闭反射序列化。

当前为 SDK 开发版本：从固定源码建立 520 个端点的 wire 清单并生成对应方法，包含官方 OpenAPI、用户存储/LDAP/缓存、授权、组织、工作流和控制台扩展。119 个 OpenAPI schema 按 wire 类型处理，动态契约提供 `HttpContent` / `JsonElement`。服务器支持范围通过 [JSON 路线声明](contracts/admin-api-routes.json) 明确选择：默认 `fgap-v2-stable` 只支持 26.8.1 正式功能；`fgap-v1-compat` 提供 v1 兼容支持，两条路线均不启用预览/实验功能。

独立源码审计确认官方 415 个操作及 105 个源码补充操作均有路由。此前发现的 6 个路径契约缺口已修复：保留 526 个源码分派变体，补齐动态查询参数与媒体类型分支，修正工作流列表响应；新增六组独立测试并通过托管与 Native AOT 真实容器验证。完整分组及逐项对照见 [对齐审计](docs/contracts/keycloak-26.8.1-alignment-audit.md)，变更及验证场景见 [六路径修复记录](docs/contracts/six-path-fixes.md)。

全部 **520/520 Admin API SDK 操作已有功能契约单元测试**，每个操作有独立的 MSTest 入口；当前 **553/553** 通过。SDK 自有源码（含生成 API/DTO）、能力扩展及两个开关/遥测扩展的方法、行和分支覆盖率均为 **100%**；[覆盖率门槛](tests/coverage-policy.json) 阻断缺失、跳过、失败与未达标。详见 [520 项测试矩阵](docs/contracts/admin-api-test-matrix.md) 和 [覆盖率报告](docs/contracts/test-coverage.md)。

**真实 Keycloak 26.8.1 + PostgreSQL 18.0 业务验收**：v2 正式路线 **478/478**、v1 兼容路线 **492/492**，托管和 .NET 10 Native AOT 均通过。每项有业务结果或数据状态断言，包含委派管理员 403 → 授权读写 → 撤销 403、LDAP 同步、SMTP 投递、OIDC 会话/同意、JWKS 轮换、X509 CRL 吊销与数据库缓存失效。28 项预览/实验 API 政策排除；v2 另排除 14 项 v1 专用接口，均不计为成功。逐接口证据见 [全功能验收](docs/contracts/full-live-acceptance.md)。

## 使用

需要按 Keycloak 版本、真实服务端能力和声明路线控制可用接口时，使用可选 `Keycloak.Admin.Sdk.Capabilities` 扩展及 `KeycloakSupportedClient.CreateAsync`。它在请求发送前统一检查支持状态；原有构造方式继续提供 wire 传输。配置、拒绝原因、升级流程和示例见 [版本能力与开放策略](docs/capability-policy.md)。

托管宿主可以使用独立的 `Keycloak.Admin.Sdk.FeatureManagement` 扩展（Microsoft.FeatureManagement 4.8.0），在能力判断通过后再检查总开关和目标功能开关。Microsoft.FeatureManagement.Telemetry.ApplicationInsights 4.8.0 另有可选遥测适配包，默认关闭。**核心零运行时 NuGet 依赖并坚持 Native AOT；这两个托管扩展不要求 AOT**。完整配置、生命周期及遥测范围见 [接入指南](docs/feature-management.md)。

```csharp
using Keycloak.Admin.Sdk;

// 由宿主管理 HttpClient、凭据和 token provider 的生命周期。
using var http = new HttpClient(new SocketsHttpHandler { AllowAutoRedirect = false });
using var tokens = new ClientCredentialsTokenProvider(
    http, new Uri("https://keycloak.example.com/auth/"),
    authenticationRealm: "master", clientId: "admin-service",
    secret: ct => ValueTask.FromResult(
        Environment.GetEnvironmentVariable("KEYCLOAK_CLIENT_SECRET")
        ?? throw new InvalidOperationException("Missing secret")));
var sdk = new KeycloakAdminClient(http, new Uri("https://keycloak.example.com/auth/"), tokens);

var page = await sdk.Users.GetUsersAsync("target-realm", first: 0, max: 20);
foreach (var user in page.Body ?? []) Console.WriteLine(user.Username);

var created = await sdk.Users.CreateUserAsync("target-realm",
    new UserRepresentation { Username = "new-user", Enabled = true });
Console.WriteLine(created.Location);
```

认证 realm 与目标 realm 独立。可用 `StaticAccessTokenProvider` 或实现 `IAccessTokenProvider` 接入现有 token 系统。SDK 不自动授予服务账号权限；401 恢复默认关闭，可显式开启。结构化错误、认证恢复及 DI 配置见 [认证与错误处理](docs/authentication-and-errors.md)。

每个生成方法有明确的 HTTP 方法、路径和源码位置，见 [端点清单](docs/contracts/endpoint-inventory.md)。资源入口沿 Java 资源类命名，如 `Users`、`User`、`Clients`、`Client`、`RealmAdmin`、`AuthenticationManagement`。同一 Java 方法挂载到多个不同路径时，后续方法带路径后缀，以避免公开名称冲突；预览期间命名仍可能调整。

`realm` 是名称；`clientUuid`、路径中的 `client-id` 等按服务端契约使用内部 ID，不等于 OIDC `clientId`。所有网络方法均支持取消。单页方法直接暴露服务端分页参数，不提供快照或总数保证。

## 请求、响应和所有权

- `HttpClient` 和 token provider 由调用方持有并释放。传入的 `HttpContent` 由一次请求消费并释放，不可复用。
- 常规方法返回缓冲响应，保留状态码、Location、header、原始内容和可选强类型 `Body`。以 `HasBody` 区分空响应与值类型的默认值。Location 不会被自动跟随。
- `OpenStreamAsync` 提供不缓冲的下载，调用方须释放返回的 `AdminStreamResponse`。
- `SendAsync` 可提交原始 JSON、表单、多部分或二进制内容；`SendJsonAsync` 接受显式 `JsonTypeInfo<T>`，允许调用方的源生成契约在 AOT 下使用。
- 身份提供方导入、本地化导入及 SMTP 测试的方法接收 `HttpContent`，由调用方选择 JSON、multipart 或表单；scheduled workflows 返回 `List<WorkflowRepresentation>`。这两项是预览 API 签名变更，示例见 [修复记录](docs/contracts/six-path-fixes.md)。
- DTO 中 null 属性默认省略；false、0、空集合会发送。需要显式 JSON null 或特殊更新结构时，使用原始请求。读取 DTO 可能含只读字段、掩码密钥或 brief 信息，更新时应构造明确的请求，避免直接回写。
- **26.8.1 的客户端 PUT 若省略 `authorizationServicesEnabled=true` 会关闭该客户端的授权服务。** 更新模型应明确保留所需配置。SDK 忠实传递服务器语义，不隐式先读后写。
- `KeycloakAdminException` 保留 HTTP 状态、方法、`Stage`、`ErrorKind` 及生成接口的固定 `Operation`；错误响应体不读取，`ErrorCode` 当前为 null。传输异常、取消和 JSON 格式异常分别保留。超时后的写入结果可能未知。

## 构建与验证

本地常驻的 Keycloak 26.8.1 + PostgreSQL 18.0 环境已配置在 [local/keycloak](local/keycloak/README.md)。一键启动并完成就绪、登录及版本检查：

```shell
dotnet run --file local/keycloak/Service.cs
```

管理控制台为 <http://127.0.0.1:18080/admin/>；默认用户 `admin`，随机密码保存在该目录生成的 `.env`。数据库使用命名卷持久化；全功能真实测试使用 `test-full` / `test-full-native`。路线可由 `KEYCLOAK_ADMIN_API_ROUTE` 环境变量或 `.env` 显式声明，启动时核验服务器实际功能开关，详见 [路线规则](docs/contracts/admin-api-routing.md)。

常规测试已接入 MSTest，使用你允许的固定版本测试 SDK、MSTest 和 coverlet。完整的测试包清单、依赖边界及报告位置见 [测试说明](docs/testing.md)。

本机辅助工具统一采用 .NET 10 文件式 C#（file-based app），共用 `tools/ScriptSupport.cs`，通过 `dotnet run --file` 执行；SDK 固定为 10.0.403。脚本中的进程调度、HTTP 就绪检查、JSON/XML、哈希和 tar/gzip 解压均由 .NET 标准库实现，外部工具仅用于 dotnet 构建和 Docker 容器管理。

```shell
dotnet run --file tools/Verify.cs                 # 构建、MSTest、打包、当前平台原生验证
dotnet test tests/Keycloak.Admin.Sdk.Tests -c Release # IDE/CLI 常规测试入口
dotnet run --file tools/Test-Integration.cs       # 固定 digest、临时本机端口，退出清理容器
dotnet run --file tools/Update-Contracts.cs       # 校验固定来源，使用 .NET TarReader 生成契约
dotnet run --file tools/Update-Verification.cs    # 将本地测试证据更新至端点清单
dotnet run --file tools/Audit-Contracts.cs -- --online # 独立比对发布源码；发现契约缺口返回非零
dotnet run --file tools/Generate-TestMatrix.cs -- --check # 核对冻结契约与全部强类型单测入口
dotnet run --file tools/Check-Coverage.cs -- --results=artifacts/test-results/<run> # 核验该次 TRX 与覆盖率
dotnet run --file local/keycloak/Service.cs -- test-full # 当前声明路线的全部真实业务验收
dotnet run --file local/keycloak/Service.cs -- test-full-native # 同一套业务场景的 Native AOT 实跑
dotnet run --file tools/Check-FullAcceptance.cs -- --update-docs # 两路线、两模式的全量门禁和逐项报告
dotnet run --file tools/Test-AllAdminRoutes.cs -- --update-docs # 一条命令重跑四套业务验收并恢复普通 v2 服务
```

Native AOT 需要目标平台编译工具。Windows 需 Visual Studio C++ 桌面工具链和 Windows SDK；Linux 可用仓库中的隔离编译方式：

```shell
dotnet run --file tools/Verify.cs -- --native-container
```

Docker 构建会使用 10.0.403 实际编译并运行全部端点的原生测试程序，输出目录包含原生 ELF。可仅跳过当前平台的原生发布运行 `dotnet run --file tools/Verify.cs -- --skip-native-publish`；这不替代 Native AOT 验收。CI 配置为 `.github/workflows/verify.yaml`，包含 Windows/Linux 原生验证和独立的真实 Keycloak 集成测试，调用同一组 C# 工具；远端执行状态以 CI 结果为准。仓库 YAML 文件统一使用 `.yaml` 扩展名，构建验证会检查此约定。

真实接口也可在原生模式验证：`dotnet run --file tools/Test-Integration.cs -- --native-aot` 会自动构建原生集成程序并启动隔离 Keycloak。已构建时可加 `--no-build-native` 复用本地二进制。原生程序与隔离 Keycloak 共享容器网络，测试产物只写入仓库的 artifacts 目录。各脚本均支持 `--help`；例如 `dotnet run --file tools/Test-Integration.cs -- --help`。

核心运行时无包依赖；.NET 的 ILLink/ILCompiler 等官方分析器和编译工具由 SDK 在构建阶段隐式还原，不进入 SDK 包的运行时依赖。

## 契约与发布范围

- [实施方案](docs/dotnet10-keycloak-admin-sdk-plan.md)
- [固定版本、commit、镜像 digest 与输入哈希](contracts/baseline.json)
- [源码文件校验清单](contracts/source-files.sha256)
- [端点与源码对照](docs/contracts/endpoint-inventory.md)
- [验证结果、未完成项和动态扩展边界](docs/contracts/verification.md)

当前不承诺旧 SDK API 兼容，不把 26.8.1 的结果扩展为全部 26.x 兼容。逐接口验收覆盖声明范围内的业务场景，未穷尽所有权限组合、策略提供方类型和第三方 SPI 扩展。

## 许可证

[Apache License 2.0](LICENSE)。契约来源及归属见 [第三方说明](THIRD_PARTY_NOTICES.md)。
