# 认证、错误与依赖注入

核心客户端的手动初始化见 [README](../README.md)。可选 `Keycloak.Admin.Sdk.DependencyInjection` 提供 Microsoft DI、Options 与 HttpClientFactory。

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

引用 `Keycloak.Admin.Sdk.DependencyInjection` 后注册：

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
var secondary = serviceProvider.GetRequiredKeyedService<KeycloakAdminClient>("secondary");
```

每个名称（含默认）仅注册一次，分别持有 HTTP 客户端、Options 和 token 缓存。Options 启动校验拒绝不完整配置且不输出配置值；客户端创建后配置固定，切换身份需新注册或重建容器。
