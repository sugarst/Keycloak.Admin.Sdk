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

`new KeycloakAdminClient(...)` 提供底层 API 传输。需要在发送前限制支持范围时，使用 `KeycloakSupportedClient.CreateAsync`；托管功能开关使用 `KeycloakFeatureManagedClient.CreateAsync`。配置见 [能力策略](docs/capability-policy.md)、[功能开关与遥测](docs/feature-management.md)，DI 见 [认证与错误处理](docs/authentication-and-errors.md)。

## 请求与响应约定

- 调用方释放 `HttpClient` 和 token provider。请求消费并释放传入的 `HttpContent`，每次调用须新建内容；`OpenStreamAsync` 的返回值由调用方释放。
- 常规响应保留状态码、Location、header、原始内容和可选强类型 `Body`；`HasBody` 区分空响应。Location 不会被自动跟随。
- DTO 的 null 属性默认省略，false、0、空集合会发送。显式 JSON null、动态载荷和自定义源生成模型可通过 `SendAsync` / `SendJsonAsync` 提交；媒体类型示例见 [特殊契约](docs/contracts/six-path-fixes.md)。
- 更新时应构造明确的请求，避免回写只读字段、掩码密钥或 brief 数据。**26.8.1 客户端 PUT 若省略 `authorizationServicesEnabled=true` 会关闭该客户端的授权服务。**
- HTTP 错误抛出 `KeycloakAdminException`；401 恢复默认关闭，可显式开启一次安全读取重放。写入超时后的结果可能未知。详细规则见 [认证与错误处理](docs/authentication-and-errors.md)。

## Keycloak 26.8.1 能力边界

主包按 HTTP 方法 + 路径生成了 520 项 Admin API 操作。已纳入支持范围的功能包括 realm、用户、组、角色、客户端、客户端作用域、身份提供方、认证流程、授权策略、组织、工作流及管理控制台扩展等。实际可用范围还取决于声明的 FGAP 路线、服务器功能配置和账号权限。

| 范围 | 操作数 | 验证 |
| --- | --- | --- |
| 完整生成契约 | 520 | 每项独立功能契约单测 |
| `fgap-v2-stable`（默认） | 478 | 托管及 Linux Native AOT 真实业务验收 |
| `fgap-v1-compat` | 492 | 托管及 Linux Native AOT 真实业务验收 |

以下接口保留生成方法和契约单测，但不属于两条路线的支持范围，也未计入真实业务验收成功：

| Keycloak 功能 | 阶段 | 操作数 | 不支持的原因 |
| --- | --- | ---: | --- |
| `oid4vc-vci` | Preview | 7 | 凭证管理功能处于预览阶段，按当前支持策略排除 |
| `ssf` | Experimental | 19 | 功能处于实验阶段，按当前支持策略排除 |
| `client-types` | Experimental | 2 | 功能处于实验阶段，按当前支持策略排除 |

默认 v2 路线另外排除 14 个 FGAP v1 专用接口；这些接口已在 v1 兼容路线上通过验收。**生成方法存在不等于 SDK 承诺支持该接口**：使用 `KeycloakSupportedClient.CreateAsync` 可在发送请求前执行版本、成熟度、路线、服务器功能及验证状态检查。直接构造 `KeycloakAdminClient` 提供底层传输，不自动应用支持策略。

范围以 Keycloak 26.8.1 的 Admin API 为准，不涵盖控制台静态资源、独立 OAuth/OIDC、Account、SCIM 或实验性 Admin API v2 等协议，也不能预先枚举第三方 SPI 扩展。结果不自动适用于其他 Keycloak 版本，也不代表已覆盖所有权限和配置组合。

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
- [支持路线](docs/contracts/admin-api-routing.md) · [接口验证索引](docs/contracts/admin-api-validation-list.md)
- [端点与源码](docs/contracts/endpoint-inventory.md) · [源码对齐审计](docs/contracts/keycloak-26.8.1-alignment-audit.md)

[Apache License 2.0](LICENSE)；契约来源及归属见 [第三方说明](THIRD_PARTY_NOTICES.md)。
