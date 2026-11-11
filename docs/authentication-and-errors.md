# 认证、错误与依赖注入

主包的 DI 模块提供 Microsoft DI、Options、HttpClientFactory 与可选的 HTTP 弹性管道。[README](../README.md) 展示了 DI 注册。已有 HTTP 客户端或 token 系统时，也可手动构造：

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
```

也可使用 `StaticAccessTokenProvider` 或实现 `IAccessTokenProvider`。调用方须在所有调用及共享 token 获取结束后释放自己创建的 HTTP 客户端和 provider。

## 结构化错误

`KeycloakAdminException` 继承 `HttpRequestException`，保留 `StatusCode`、`Method`，并提供：

| 属性 | 含义 |
| --- | --- |
| `Stage` | Unknown、AdminApi、TokenEndpoint；旧两参数构造函数为 Unknown |
| `ErrorKind` | 400/401/403/404/409 对应 BadRequest/Unauthorized/Forbidden/NotFound/Conflict；其他为 Unknown |
| `Operation` | 生成方法的固定标识，如 `Users.CreateUserAsync`；原始请求和 token 端点为 null |
| `ErrorCode` | 当前始终为 null |

错误体不读取；SDK 构造的 HTTP 异常不附加实际 URL、查询、凭据或错误正文。错误类别只表示 HTTP 分类，409 不等同于用户名重复。网络失败和取消保留自身类型；成功响应的 JSON 格式错误抛出 `KeycloakResponseFormatException`。

```csharp
try
{
    await sdk.Users.CreateUserAsync(realm, new UserRepresentation { Username = username });
}
catch (KeycloakAdminException error) when (
    error.Stage == KeycloakFailureStage.AdminApi &&
    error.ErrorKind == KeycloakErrorKind.Conflict)
{
    // 由业务层确认冲突原因。
}
```

## 可选 401 恢复

```csharp
var sdk = new KeycloakAdminClient(http, server, tokens,
    new KeycloakAdminClientOptions { EnableUnauthorizedRecovery = true });
```

默认关闭。开启后，仅当 `/admin/` 请求实际携带 provider token，且 provider 实现 `IRefreshableAccessTokenProvider`，才在 401 时条件失效缓存。失效必须比较被拒 token 与当前缓存，避免旧响应清除新 token；失效本身不发送网络请求。

生成的无内容 GET/HEAD 最多重放一次；写请求或带内容请求只失效，不重放。第二次 401 仍失效后抛出。403、token 端点失败、网络故障及超时不触发恢复；`StaticAccessTokenProvider` 不支持失效。

原始 `SendAsync`、`SendJsonAsync` 和 `OpenStreamAsync` 还需逐次允许重放：

```csharp
var replay = new KeycloakRequestOptions { AllowUnauthorizedReplay = true };
var response = await sdk.SendAsync(replay, HttpMethod.Get, "/admin/serverinfo",
    cancellationToken: cancellationToken);
```

重放仍要求客户端恢复已开启、无内容且为 admin GET/HEAD。每次使用新请求消息并释放失败响应，查询只枚举一次，不修改共享认证头。流只在交付前恢复。为整个业务调用设置取消/总时间预算；`HttpClient.Timeout` 只约束单次 HTTP 调用。写入超时后的结果可能未知。

## Token 并发与生命周期

`ClientCredentialsTokenProvider` 按实例隔离地址、认证 realm、client ID 和密钥解析器。并发调用共享一次获取；单个等待者取消不取消共享任务。默认共享获取超时 30 秒，覆盖密钥解析、HTTP 及读取；解析器和 handler 须遵守取消令牌。失败结果共享 1 秒，冷却后才允许重新获取，不自动重试失败获取。

```csharp
using var tokens = new ClientCredentialsTokenProvider(http, server, "master", "service",
    ct => secretStore.GetSecretAsync(ct), TimeProvider.System,
    new ClientCredentialsTokenProviderOptions
    {
        RequestTimeout = TimeSpan.FromSeconds(20),
        FailureCooldown = TimeSpan.FromSeconds(1)
    });
```

`RequestTimeout` 必须为正、`FailureCooldown` 可为零，两者不能超过 4294967294 毫秒。仅更新密钥存储不会替换缓存 token；轮换后条件失效当前 token，或在调用结束后重建 provider。所有等待者取消后共享获取仍可能运行，应等待调用及共享获取结束再释放 provider 和 HTTP 客户端。

## 依赖注入

引用 `Keycloak.Admin.Sdk` 后注册：

```csharp
using Keycloak.Admin.Sdk;
using Microsoft.Extensions.DependencyInjection;

services.AddKeycloakAdminSdk(options =>
{
    options.Server = new Uri("https://keycloak.example.com/auth/");
    options.AuthenticationRealm = "master";
    options.ClientId = "admin-service";
    options.ClientSecret = (sp, ct) =>
        sp.GetRequiredService<ISecretStore>().GetSecretAsync(ct);
    options.Client = new() { EnableUnauthorizedRecovery = true };
});
```

`ISecretStore` 由宿主定义，示例方法返回 `ValueTask<string>`。解析器保存在单例 provider 中，应使用根容器可解析的单例服务，不捕获 scoped 服务。客户端、provider、factory 创建的 HTTP 客户端由容器以单例持有并释放；宿主关闭前先结束调用。

注册返回 `IHttpClientBuilder`，可配置 handler。默认禁用自动重定向，连接最多复用 5 分钟；自定义 handler 自行管理重定向、重试和连接策略。业务层应避免叠加相同的 401 重试。

多服务器或身份使用唯一名称：

```csharp
services.AddKeycloakAdminSdk("secondary", options => { /* 另一组地址和凭据 */ });
var secondary = serviceProvider.GetRequiredKeyedService<IKeycloakAdminClient>("secondary");
```

每个名称（含默认）仅注册一次，分别持有 HTTP 客户端、Options 和 token 缓存。Options 启动校验拒绝不完整配置且不输出配置值；客户端创建后配置固定，切换身份需新注册或重建容器。

## 接口与测试替身

`AddKeycloakAdminSdk` 同时注册 `IKeycloakAdminClient` 和 `KeycloakAdminClient`，默认注册和每个命名注册分别映射到同一个单例。业务服务可直接通过构造函数注入接口，示例见 [README](../README.md)。命名接口使用 `GetRequiredKeyedService<IKeycloakAdminClient>(name)` 解析。

主接口包含全部资源入口和原始请求的六个重载。资源属性使用 `IUsersApi`、`IClientsApi` 等生成接口，业务测试可以模拟资源接口，再将它设置为主接口的对应属性。测试依赖由宿主测试项目自行引用。

具体类型继续公开原来的具体资源属性。异步工厂仍返回 `KeycloakAdminClient`，可直接赋给接口变量：

```csharp
IKeycloakAdminClient sdk = await KeycloakSupportedClient.CreateAsync(
    http, server, tokens, support);
```

功能开关工厂也支持同样的赋值方式。接口调用经过相同的认证、支持策略、功能开关和 HTTP 管道。HTTP 客户端和 token provider 的所有权规则同上。

## HTTP 弹性策略

主包直接引用 Microsoft.Extensions.Http 10.0.15 与 Microsoft.Extensions.Http.Resilience 10.11.0，使用微软 ResilienceHandler 和 Polly 管道，无反射式配置绑定。通过既有 DI 入口统一配置，不再叠加 AddStandardResilienceHandler、Http.Polly 或其他重试 handler：

```csharp
services.AddKeycloakAdminSdk(options =>
{
    options.Server = new Uri("https://keycloak.example.com/auth/");
    options.ClientId = "admin-service";
    options.ClientSecret = (sp, ct) => sp.GetRequiredService<ISecretStore>().GetSecretAsync(ct);
    options.Client = new() { EnableUnauthorizedRecovery = true };
    options.Resilience = new()
    {
        Enabled = true,
        MaxRetryAttempts = 2,
        RetryDelay = TimeSpan.FromMilliseconds(200),
        TotalRequestTimeout = TimeSpan.FromSeconds(30),
        AttemptTimeout = TimeSpan.FromSeconds(10)
    };
});
```

默认 Enabled=false；不开启时不安装有效重试、超时或熔断策略。开启后，仅无 HttpContent 的 GET/HEAD 进入管道（包括原始请求与流式请求）。所有写方法、GET/HEAD 携带内容以及 Token POST 都绕过整个管道，包括已打开的读熔断。Token 获取仍受 provider 自己的超时和失败冷却控制。默认不添加 hedging、限流、HTTP 正文日志或远端遥测导出。

管道顺序为：总超时 → 可选瞬态重试 → 可选熔断 → 单次超时。瞬态错误使用微软默认分类：408、429、5xx、HttpRequestException、Polly 的 TimeoutRejectedException；采用指数退避，可加抖动，遵守 Retry-After，等待仍受总超时和调用取消控制。失败响应在重试时释放，最终 HTTP 失败仍转换为 SDK 的结构化异常。

| 配置 | 默认值 | 允许范围/含义 |
| --- | --- | --- |
| Enabled | false | 开启本命名客户端的读取管道 |
| MaxRetryAttempts | 2 | 0–10；额外重试次数，0 关闭瞬态重试 |
| RetryDelay | 200 ms | 0–1 分钟；初始退避 |
| UseJitter | true | 退避抖动 |
| TotalRequestTimeout | 30 秒 | 不小于 AttemptTimeout，不超过 1 天 |
| AttemptTimeout | 10 秒 | 至少 1 ms，不大于 TotalRequestTimeout |
| EnableCircuitBreaker | true | 开启读取熔断，MaxRetryAttempts=0 时仍可启用 |
| CircuitBreakerFailureRatio | 0.5 | 大于 0、不超过 1；拒绝 NaN |
| CircuitBreakerMinimumThroughput | 20 | 至少 2；每次物理尝试均参与统计 |
| CircuitBreakerSamplingDuration | 30 秒 | 500 ms–1 天 |
| CircuitBreakerBreakDuration | 5 秒 | 500 ms–1 天 |

配置即使关闭也会校验，Resilience 不能为 null。不同命名客户端/handler 实例不共享熔断状态；重建 handler 后使用新管道。熔断打开后，读取抛出 Polly.CircuitBreaker.BrokenCircuitException；弹性超时抛出 Polly.Timeout.TimeoutRejectedException；调用方取消仍为 OperationCanceledException。这些异常不转换成 HTTP 状态异常，调用方可分别处理。

401/403 不属于瞬态分类。401 仍由上文 SDK 条件失效流程处理：每次逻辑调用最多两个管理请求发送，每个发送允许 MaxRetryAttempts 次瞬态重试。因此物理管理请求上限为 `2 × (1 + MaxRetryAttempts)`（默认开启两种能力时最多 6 次）；不开启 401 恢复则为 `1 + MaxRetryAttempts`。Token 获取不计入该数，支持策略仍只评估一次。403、404、409 不自动重试。

TotalRequestTimeout 仅约束单个 HTTP 发送及其瞬态重试/退避，不覆盖 Token 获取、后续 401 恢复或 ResponseHeadersRead 之后的响应体读取。宿主应使用同一个 CancellationToken 为整个逻辑操作设置总时间预算。流一旦交付，读取故障不透明重试。

此配置仅作用于 AddKeycloakAdminSdk 创建的命名 HttpClient；手动 new KeycloakAdminClient(http, ...) 使用宿主传入的管道。增加额外 HTTP handler 的宿主须自行避免重复重试。原始请求的瞬态读取重试由本命名客户端配置控制，与原始请求针对 401 的 AllowUnauthorizedReplay 相互独立。
