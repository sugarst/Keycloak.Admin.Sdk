# Keycloak.Admin.Sdk

简体中文 | [English](README.en.md)

面向 **.NET 10 / Native AOT** 的 Keycloak Admin REST API 客户端，当前仅支持 **Keycloak 26.8.1**。主包引用 Microsoft.Extensions.Http **10.0.14** 和 Microsoft.Extensions.Http.Resilience **10.11.0**，使用源生成 JSON 元数据，默认关闭反射序列化。仓库固定 .NET SDK **10.0.403**。

公开 API 仍可能调整。开发时可引用[核心项目](src/Keycloak.Admin.Sdk/Keycloak.Admin.Sdk.csproj)。

## 快速开始

先在 Keycloak 配置服务账号及目标 realm 的管理权限，再在 ASP.NET Core 或 Generic Host 中注册：

```csharp
using Keycloak.Admin.Sdk;
using Microsoft.Extensions.DependencyInjection;

var configuration = builder.Configuration;
builder.Services.AddKeycloakAdminSdk(options =>
{
    options.Server = new Uri("https://keycloak.example.com/auth/");
    options.AuthenticationRealm = "master";
    options.ClientId = "admin-service";
    options.ClientSecret = (_, ct) => ValueTask.FromResult(
        configuration["Keycloak:ClientSecret"]
        ?? throw new InvalidOperationException("Missing Keycloak client secret"));
});
```

在业务服务中注入客户端：

```csharp
using Keycloak.Admin.Sdk;

public sealed class UserService(IKeycloakAdminClient sdk)
{
    public Task<AdminResponse<List<UserRepresentation>>> GetUsersAsync(
        string realm, CancellationToken cancellationToken)
        => sdk.Users.GetUsersAsync(realm, first: 0, max: 20,
            cancellationToken: cancellationToken);
}
```

宿主应从安全配置源提供 `Keycloak:ClientSecret`。DI 容器管理 HTTP 客户端和 token provider 的生命周期，默认禁用自动重定向。认证 realm 与目标 realm 独立；`realm` 使用名称，客户端路径参数使用内部 UUID，而非 OIDC `clientId`。所有网络方法支持取消；分页直接采用服务端参数，不保证快照或总数。

`IKeycloakAdminClient` 的资源入口返回 `IUsersApi` 等生成接口，便于业务测试替换。DI 同时支持接口和具体类型，同一名称解析到同一客户端实例，详见 [接口与测试替身](docs/authentication-and-errors.md#接口与测试替身)。

该 DI 入口默认注册底层客户端，不自动安装支持策略。需要在请求前限制稳定支持范围时，可先获取可信的服务端能力快照并通过 `options.Client.RequestPolicy` 配置策略，或使用异步的 `KeycloakSupportedClient.CreateAsync`。手动构造、已有 token 接入和策略初始化见 [认证与 DI](docs/authentication-and-errors.md) 和 [能力策略](docs/capability-policy.md)。

DI 入口 `AddKeycloakAdminSdk` 提供 `options.Resilience`，默认关闭。开启后，仅为无内容 GET/HEAD 提供瞬态重试、超时和独立读熔断；写请求与 Token POST 绕过该管道。配置、401 组合次数和异常约定见 [HTTP 弹性策略](docs/authentication-and-errors.md#http-弹性策略)。

## 客户端与功能开关

功能开关包依赖微软遥测组件，遥测默认关闭。

`new KeycloakAdminClient(...)` 提供底层 API 传输。需要在发送前限制支持范围时，使用 `KeycloakSupportedClient.CreateAsync`；统一宿主开关面使用 `Keycloak.Admin.Sdk.Platform` 的 `KeycloakPlatformHost.CreateAsync`。配置见 [能力策略](docs/capability-policy.md)、[平台开关面](docs/platform-feature-gate.md)，DI 见 [认证与错误处理](docs/authentication-and-errors.md)。

## 请求与响应约定

- 调用方释放 `HttpClient` 和 token provider。请求消费并释放传入的 `HttpContent`，每次调用须新建内容；`OpenStreamAsync` 的返回值由调用方释放。
- 常规响应保留状态码、Location、header、原始内容和可选强类型 `Body`；`HasBody` 区分空响应。Location 不会被自动跟随。
- DTO 的 null 属性默认省略，false、0、空集合会发送。显式 JSON null、动态载荷和自定义源生成模型可通过 `SendAsync` / `SendJsonAsync` 提交；媒体类型示例见 [特殊契约](docs/contracts/six-path-fixes.md)。
- 更新时应构造明确的请求，避免回写只读字段、掩码密钥或 brief 数据。**26.8.1 客户端 PUT 若省略 `authorizationServicesEnabled=true` 会关闭该客户端的授权服务。**
- HTTP 错误抛出 `KeycloakAdminException`；401 恢复默认关闭，可显式开启一次安全读取重放。写入超时后的结果可能未知。详细规则见 [认证与错误处理](docs/authentication-and-errors.md)。

## Keycloak 26.8.1 能力边界

本开发分支以两种独立矩阵维护支持范围：[Admin API 操作矩阵](docs/contracts/admin-api-support-matrix.tsv)，以及包含 80 个上游功能开关、52 个应用能力族的[全能力矩阵](docs/contracts/platform-capability-matrix.md)。应用可调用能力按固定版本和运行模式独立验收；部署、数据库、多集群、服务端界面和 Java SPI 的责任边界见[实施说明](docs/full-platform-coverage.md)。下述 520 项覆盖只属于 Admin API。

当前 52/52 个审阅应用能力族已晋升，完整覆盖门禁通过；标准业务验收为 Managed 434 项、Linux Native AOT 391 项，旧版兼容计划各 20 项。支持范围以矩阵中的具体运行模式、RID 和当前输入证据为准。

| 包 | 使用场景 |
| --- | --- |
| `Keycloak.Admin.Sdk` | 管理接口、服务账号认证与支持策略 |
| `Keycloak.Admin.Sdk.Protocols` | 应用 OIDC/OAuth、账户、SCIM、授权、钱包及身份代理；支持 Managed 和已验证的 Linux Native AOT |
| `Keycloak.Admin.Sdk.Hosting` | ASP.NET Core 登录、资源令牌、注销、MCP 元数据及 SAML；仅 Managed |
| `Keycloak.Admin.Sdk.Platform` | 一个宿主开关面控制 Admin 与协议链的全部能力；托管与 Native AOT 均可用 |

preview.3 仍是未发布的开发版本；新增模块使用项目引用或本地构建包。已发布 preview.2 的范围见 [CHANGELOG](CHANGELOG.md)。钱包和认证接入分别见[钱包集成](docs/wallet-integration.md)和[认证集成](docs/authentication-integration.md)。

主包按 HTTP 方法 + 路径生成了 520 项 Admin API 操作。已纳入支持范围的功能包括 realm、用户、组、角色、客户端、客户端作用域、身份提供方、认证流程、授权策略、组织、工作流及管理控制台扩展等。实际可用范围还取决于声明的 FGAP 路线、服务器功能配置和账号权限。

| 范围 | 操作数 | 验证 |
| --- | --- | --- |
| 完整生成契约 | 520 | 每项独立功能契约单测 |
| `fgap-v2-stable`（默认） | 478 | 托管及 Linux Native AOT 真实业务验收 |
| `fgap-v1-compat` | 492 | 托管及 Linux Native AOT 真实业务验收 |

以下接口不计入两条正式路线的默认验收范围；非 Stable 功能通过独立计划按环境逐项验证：

| Keycloak 功能 | 阶段 | 操作数 | 独立支持范围 |
| --- | --- | ---: | --- |
| `oid4vc-vci` | Preview | 7 | v2 路线 Managed／Linux Native AOT 独立验证；需逐功能 Preview 许可与宿主开关 |
| `ssf` | Experimental | 19 | v2 路线 Managed／Linux Native AOT 独立验证；需逐功能 Experimental 许可与宿主开关 |
| `client-types` | Experimental | 2 | v2 路线 Managed／Linux Native AOT 独立验证；默认关闭，需 schema 2 显式许可和宿主开关 |

schema 2 支持 Managed、NativeAot 和 Portable 验证配置。托管与 Native AOT 统一使用 `Keycloak.Admin.Sdk.Platform` 的 `KeycloakFeatureSnapshotGate`；开关不能覆盖版本、阶段或证据拒绝。旧配置保持同时要求托管和 AOT 证据。接入见[能力策略](docs/capability-policy.md#按运行环境开放schema-2)；独立验证、晋升与最后的灰度开关见[非 Stable 功能流程](docs/non-stable-feature-lifecycle.md)。

默认 v2 路线另外排除 14 个 FGAP v1 专用接口；这些接口已在 v1 兼容路线上通过验收。**生成方法存在不等于 SDK 承诺支持该接口**：使用 `KeycloakSupportedClient.CreateAsync` 可在发送请求前执行版本、成熟度、路线、服务器功能及验证状态检查。直接构造 `KeycloakAdminClient` 提供底层传输，不自动应用支持策略。

主包的范围是 Keycloak 26.8.1 Admin API；独立 OAuth/OIDC、Account、SCIM、Client Admin API v2 等由 Protocols／Hosting 模块提供并单独晋升。控制台静态资源及第三方 SPI 实施由服务端承担。结果不自动适用于其他 Keycloak 版本，也不代表穷尽所有权限和配置组合。

逐接口状态及排除原因见 [支持矩阵](docs/contracts/admin-api-support-matrix.tsv)，分类汇总见 [验证索引](docs/contracts/admin-api-validation-list.md)，实测环境和证据见 [真实验收](docs/contracts/full-live-acceptance.md)。支持策略的接入方式见 [能力策略](docs/capability-policy.md)。

## 开发与验证

从仓库根目录执行；真实服务及容器原生验证需要 Docker：

```shell
dotnet run --file tools/Verify.cs -- --skip-native-publish # 构建、单测与覆盖率
dotnet run --file tools/Verify.cs -- --native-container    # 另做 Linux Native AOT 验证
dotnet run --file local/keycloak/Service.cs                # 启动本地 Keycloak + PostgreSQL
```

本地控制台：<http://127.0.0.1:18080/admin/>，默认用户 `admin`，随机密码保存在生成的 `local/keycloak/.env`。数据库持久化、服务命令见 [本地环境](local/keycloak/README.md)；测试入口与报告见 [测试说明](docs/testing.md)。不带参数的 `Verify.cs` 验证当前平台原生程序，所需编译工具见测试说明。

## 文档

- [架构与契约来源](docs/architecture.md)
- [版本变更](CHANGELOG.md) · [发布记录与保存规则](docs/releases/README.md)
- [支持路线](docs/contracts/admin-api-routing.md) · [接口验证索引](docs/contracts/admin-api-validation-list.md)
- [端点与源码](docs/contracts/endpoint-inventory.md) · [源码对齐审计](docs/contracts/keycloak-26.8.1-alignment-audit.md)

[Apache License 2.0](LICENSE)；契约来源及归属见 [第三方说明](THIRD_PARTY_NOTICES.md)。
