# Keycloak.Admin.Sdk

简体中文 | [English](README.en.md)

面向 **.NET 10 / Native AOT** 的 Keycloak Admin REST API 客户端，当前仅支持 **Keycloak 26.8.1**。主包集成 Microsoft.Extensions.Http，使用源生成 JSON 元数据，默认关闭反射序列化。仓库固定 .NET SDK **10.0.403**。

当前包版本为 **0.1.0-preview.2**，公开 API 仍可能调整。可引用 [核心项目](src/Keycloak.Admin.Sdk/Keycloak.Admin.Sdk.csproj)，或使用验证工具生成的 `artifacts/packages/0.1.0-preview.2` 本地 NuGet 源。

## 快速开始

先在 Keycloak 配置服务账号及目标 realm 的管理权限，再由宿主管理 HTTP 客户端和凭据：

```csharp
using Keycloak.Admin.Sdk;

var server = new Uri("https://keycloak.example.com/auth/");
using var http = new HttpClient(new SocketsHttpHandler { AllowAutoRedirect = false });
using var tokens = new ClientCredentialsTokenProvider(
    http, server, authenticationRealm: "master", clientId: "admin-service",
    secret: ct => ValueTask.FromResult(
        Environment.GetEnvironmentVariable("KEYCLOAK_CLIENT_SECRET")
        ?? throw new InvalidOperationException("Missing secret")));
var sdk = new KeycloakAdminClient(http, server, tokens);

var page = await sdk.Users.GetUsersAsync("target-realm", first: 0, max: 20);
foreach (var user in page.Body ?? []) Console.WriteLine(user.Username);

var created = await sdk.Users.CreateUserAsync("target-realm",
    new UserRepresentation { Username = "new-user", Enabled = true });
Console.WriteLine(created.Location);
```

认证 realm 与目标 realm 独立；`realm` 使用名称，客户端路径参数使用内部 UUID，而非 OIDC `clientId`。可用 `StaticAccessTokenProvider` 或实现 `IAccessTokenProvider` 接入已有认证。所有网络方法支持取消；分页直接采用服务端参数，不保证快照或总数。

## NuGet 包与迁移

| 包 | 用途 | Native AOT |
| --- | --- | --- |
| `Keycloak.Admin.Sdk` | 管理客户端、认证、能力策略、DI 和 HttpClientFactory | 支持 |
| `Keycloak.Admin.Sdk.FeatureManagement` | 宿主功能开关与可选 Application Insights 评估遥测 | 仅托管 |

从 preview.1 升级时，将 `.Capabilities`、`.DependencyInjection` 的包引用换成主包，将 `.FeatureManagement.ApplicationInsights` 换成 `.FeatureManagement`，并重新编译。现有命名空间和注册方法可继续使用。安装功能开关包会还原微软遥测依赖，遥测默认关闭。

`new KeycloakAdminClient(...)` 提供底层 API 传输。需要在发送前限制支持范围时，使用 `KeycloakSupportedClient.CreateAsync`；托管功能开关使用 `KeycloakFeatureManagedClient.CreateAsync`。配置见 [能力策略](docs/capability-policy.md)、[功能开关与遥测](docs/feature-management.md)，DI 见 [认证与错误处理](docs/authentication-and-errors.md)。

## 请求与响应约定

- 调用方释放 `HttpClient` 和 token provider。请求消费并释放传入的 `HttpContent`，每次调用须新建内容；`OpenStreamAsync` 的返回值由调用方释放。
- 常规响应保留状态码、Location、header、原始内容和可选强类型 `Body`；`HasBody` 区分空响应。Location 不会被自动跟随。
- DTO 的 null 属性默认省略，false、0、空集合会发送。显式 JSON null、动态载荷和自定义源生成模型可通过 `SendAsync` / `SendJsonAsync` 提交；媒体类型示例见 [特殊契约](docs/contracts/six-path-fixes.md)。
- 更新时应构造明确的请求，避免回写只读字段、掩码密钥或 brief 数据。**26.8.1 客户端 PUT 若省略 `authorizationServicesEnabled=true` 会关闭该客户端的授权服务。**
- HTTP 错误抛出 `KeycloakAdminException`；401 恢复默认关闭，可显式开启一次安全读取重放。写入超时后的结果可能未知。详细规则见 [认证与错误处理](docs/authentication-and-errors.md)。

## 支持与验证范围

| 范围 | 操作数 | 验证 |
| --- | --- | --- |
| 完整生成契约 | 520 | 每项独立功能契约单测 |
| `fgap-v2-stable`（默认） | 478 | 托管及 Linux Native AOT 真实业务验收 |
| `fgap-v1-compat` | 492 | 托管及 Linux Native AOT 真实业务验收 |

两条路线均排除 28 项预览/实验接口；v2 另排除 14 项 v1 专用接口。排除项保留生成方法和单测，不计为业务验收成功。最新测试总数与覆盖率见 [覆盖率报告](docs/contracts/test-coverage.md)，逐项业务证据见 [真实验收](docs/contracts/full-live-acceptance.md)。结果仅适用于当前基线与记录的场景，发布边界见 [验证状态](docs/contracts/verification.md)。

## 开发与验证

从仓库根目录执行；真实服务及容器原生验证需要 Docker：

```shell
dotnet run --file tools/Verify.cs -- --skip-native-publish # 构建、单测、覆盖率、打包
dotnet run --file tools/Verify.cs -- --native-container    # 另做 Linux Native AOT 验证
dotnet run --file local/keycloak/Service.cs                # 启动本地 Keycloak + PostgreSQL
```

本地控制台：<http://127.0.0.1:18080/admin/>，默认用户 `admin`，随机密码保存在生成的 `local/keycloak/.env`。数据库持久化、服务命令见 [本地环境](local/keycloak/README.md)；测试入口与报告见 [测试说明](docs/testing.md)。不带参数的 `Verify.cs` 验证当前平台原生程序，所需编译工具见测试说明。

## 文档

- [架构与契约来源](docs/architecture.md)
- [单基线升级与发布](docs/single-target-workflow.md)
- [支持路线](docs/contracts/admin-api-routing.md) · [接口验证索引](docs/contracts/admin-api-validation-list.md)
- [端点与源码](docs/contracts/endpoint-inventory.md) · [源码对齐审计](docs/contracts/keycloak-26.8.1-alignment-audit.md)

[Apache License 2.0](LICENSE)；契约来源及归属见 [第三方说明](THIRD_PARTY_NOTICES.md)。
