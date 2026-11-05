# 认证恢复、结构化错误与依赖注入

核心 SDK 使用 .NET 10、主构造函数和显式 JSON 元数据，保持零运行时 NuGet 包依赖。原有构造函数和请求方法继续有效。可选 `Keycloak.Admin.Sdk.DependencyInjection` 项目提供 Microsoft DI、Options 与 HttpClientFactory 集成，单独依赖 Microsoft.Extensions.Http。

## 结构化错误

`KeycloakAdminException` 继续继承 HttpRequestException，保留 StatusCode 和 Method；新增 Stage（Unknown/AdminApi/TokenEndpoint）、ErrorKind（Unknown/BadRequest/Unauthorized/Forbidden/NotFound/Conflict）、Operation 及 ErrorCode。

400/401/403/404/409 分别映射到上述 HTTP 类别，其他状态为 Unknown，实际状态码始终保留。这些类别不表示具体业务原因。生成接口提供固定操作标识，例如 Users.CreateUserAsync；原始入口和 Token 端点的 Operation 为 null。旧的两参数异常构造函数使用 Unknown 阶段。

错误响应体完全不读取，避免不可信内容的体积、延迟和信息泄露；ErrorCode 当前始终为 null。异常属性、Message、ToString、Data 和内部异常不附加原始错误体、实际 URL、查询参数或凭据。成功响应的反序列化失败仍为 KeycloakResponseFormatException，网络失败和取消保留自身类型。

```csharp
try
{
    await sdk.Users.CreateUserAsync(realm, new UserRepresentation { Username = username });
}
catch (KeycloakAdminException error) when (
    error.Stage == KeycloakFailureStage.AdminApi &&
    error.ErrorKind == KeycloakErrorKind.Conflict)
{
    // 由业务适配层确认冲突原因。409 不等同于用户名重复。
}
```

业务恢复历史用户时，应在同一 Realm 精确查询，再确认服务端用户 ID 与本地历史 Keycloak ID 一致，并满足归属规则。同名用户可能已经删除重建，不能只凭用户名恢复。

## 手动构造与 401 恢复

```csharp
var sdk = new KeycloakAdminClient(http, server, tokens,
    new KeycloakAdminClientOptions { EnableUnauthorizedRecovery = true });
```

不开启选项时，保持原有的不失效、不重试行为。开启后，仅对 /admin/ 下实际携带 provider Token、且 provider 实现 IRefreshableAccessTokenProvider 的 401 条件失效缓存。生成的无请求体 GET/HEAD 最多重发一次；写请求及带内容请求只失效，不重发。第二次 401 也条件失效，然后抛出最终错误。

403、Token 端点请求、网络故障和超时不会触发重试。StaticAccessTokenProvider 不支持失效；自定义 provider 可选择实现新接口，必须比较 rejectedToken 与当前缓存，避免旧响应清除新 Token。失效本身不发起请求。

每次重放创建新的 HttpRequestMessage，释放首次失败响应，并复用首次确定的 URI（查询序列只枚举一次）。HttpContent 仍由一次请求消费并释放，不可复用。不修改 HttpClient 的共享认证头。

原始 SendAsync、SendJsonAsync 和 OpenStreamAsync 默认不重放。针对已确认安全的原始读取，可使用首参数为 KeycloakRequestOptions 的重载：

```csharp
var replay = new KeycloakRequestOptions { AllowUnauthorizedReplay = true };
var response = await sdk.SendAsync(replay, HttpMethod.Get, "/admin/serverinfo",
    cancellationToken: cancellationToken);
```

必须同时开启客户端恢复选项，且请求为无内容的 admin GET/HEAD。流式响应只在交付前恢复，交付后不透明重试。调用方应为整个业务调用设置 CancellationToken/总时间预算；HttpClient.Timeout 是单次 HTTP 调用的限制，不代表含 Token 获取和重试的总时限。

## Token 获取的并发与生命周期

ClientCredentialsTokenProvider 的缓存属于单个实例：固定地址、认证 Realm、Client ID 和密钥解析器。并发调用共享正在进行的获取，单个等待者取消只结束自己的等待，共享获取继续供其他调用使用。

共享获取默认总超时 30 秒，覆盖密钥解析、Token 请求和响应读取；解析器和 HTTP handler 必须遵守传入的取消令牌。失败结果默认共享 1 秒，防止并发/迟到请求连续冲击认证端点。冷却结束后允许重新获取，不自动重复失败的获取。可通过完整主构造函数定制：

```csharp
using var tokens = new ClientCredentialsTokenProvider(http, server, "master", "service",
    ct => secretStore.GetSecretAsync(ct), TimeProvider.System,
    new ClientCredentialsTokenProviderOptions
    {
        RequestTimeout = TimeSpan.FromSeconds(20),
        FailureCooldown = TimeSpan.FromSeconds(1)
    });
```

FailureCooldown 可设置为零。RequestTimeout 必须为正数、FailureCooldown 必须非负，两者均不能超过 .NET timer 支持的 4294967294 毫秒。凭据轮换后可条件失效当前 Token，或在所有调用结束后重建 provider。仅变更密钥存储不会立即替换缓存 Token。

HttpClient 和 provider 由调用方持有；应在所有调用及共享获取结束后释放。取消所有等待者仍可能留下尚未结束的共享获取，其上限由 RequestTimeout 控制。

## 依赖注入

引用可选 Keycloak.Admin.Sdk.DependencyInjection 项目/包，使用标准注册入口：

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

// 业务服务也可使用主构造函数。
public sealed class UserDirectory(KeycloakAdminClient sdk)
{
    public Task<AdminResponse<List<UserRepresentation>>> ListAsync(string realm, CancellationToken ct)
        => sdk.Users.GetUsersAsync(realm, first: 0, max: 20, cancellationToken: ct);
}
```

ISecretStore 为宿主自行定义的秘密读取服务。解析器保存在单例 provider 中，需使用可从根容器解析的单例服务，不应捕获 scoped 服务。注册返回 IHttpClientBuilder，可继续配置 HTTP handler；自定义 handler 负责其重定向、重试和连接生命周期策略。默认 handler 禁用自动重定向，连接最多复用 5 分钟。

客户端、provider 和 factory 创建的 HttpClient 均以单例保存，由容器管理释放。宿主关闭前应先结束业务调用。默认入口注册 KeycloakAdminClient；多服务端或多凭据使用唯一名称：

```csharp
services.AddKeycloakAdminSdk("secondary", options => { /* 配置另一组地址和凭据 */ });
var secondary = serviceProvider.GetRequiredKeyedService<KeycloakAdminClient>("secondary");
```

不同名称具有独立的 HttpClient、Options 和 Token 缓存。每个名称（含默认名称）只注册一次；配置在客户端创建后固定，需要切换身份时使用新的注册或重建容器。Options 启动校验拒绝不完整配置，错误提示不包含配置值。

SDK 负责一次只读恢复后，业务层应避免叠加相同的 401 重试。当前契约基线为 Keycloak 26.8.1；其他服务端版本需独立验证。
