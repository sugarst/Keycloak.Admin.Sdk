# Keycloak.Admin.Sdk.Hosting

当前开发模块提供固定 Keycloak 目标的 Managed 宿主集成。依赖成熟的 ASP.NET Core OIDC/JWT 与 ITfoxtec SAML 实现；引用依赖不产生完整协议验收，实际支持以应用能力矩阵为准。

要求 .NET/ASP.NET Core 10.0.14 或更新的 10.0 补丁版本。

通过 `ProtocolTransport.CreateSupported` 创建传输后，宿主集成也必须先通过独立支持策略和 `Keycloak.Admin.Sdk.Platform` 的统一开关面。普通构造传输只用于显式协议开发及候选验收。

宿主管理 HTTPS、代理信任、签名/解密证书的生命周期、各浏览器会话绑定和持久化原子重放存储。本模块不声明 Native AOT 支持。

## ASP.NET Core OIDC 和资源服务器

```csharp
using Keycloak.Admin.Sdk.Hosting;
using Keycloak.Admin.Sdk.Protocols;

// transport 使用 CreateSupported 建立；ticketStore/logoutStore 由宿主提供并持久化。
// client 的 secret/assertion 回调每次兑换时读取当前凭据，支持轮换。
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = "keycloak.cookie";
    options.DefaultChallengeScheme = "keycloak";
})
.AddKeycloakWebApp("keycloak", transport, client, ticketStore, logoutStore)
.AddKeycloakBearer("resource", transport, "https://api.example.com/mcp");
builder.Services.AddAuthorization();

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
app.MapKeycloakBackchannelLogout("/backchannel-logout", transport, client.ClientId, logoutStore);

var resource = new KeycloakProtectedResource(transport,
    new Uri("https://api.example.com/mcp"), ["tools:read"]);
resource.MapMetadata(app);
```

配置客户端回调 `/signin-keycloak`、注销回调 `/signout-callback-keycloak`、前通道 `/frontchannel-keycloak` 与后通道注销 URL。前通道仅清除匹配当前浏览器的本地票据；后通道必须是经过 realm 签名、issuer/audience/时效/event 校验的通知，按 issuer/sid 或 issuer/sub 撤销，不能仅凭 URL 参数注销他人的服务端会话。持久化撤销后才确认通知，重复通知保持幂等；存储故障不能确认成功。

票据存储 `ITicketStore` 是必填项：ID/access/refresh token 留在服务端，Cookie 只携带受保护的票据引用。宿主必须保护票据内容、共享 Data Protection 密钥、按票据有效期清理记录，并在多实例间共享原子注销存储。`InMemoryKeycloakLogoutStore` 有容量限制，只适用于单进程开发。会话最长八小时，不滑动延长；注销标记保留覆盖这个期限。

默认强制 HTTPS 和 Secure Cookie。`allowLoopbackHttp: true` 仅用于显式的本地验收，不能允许远程 HTTP issuer。API 验证固定 realm 的 JWKS、issuer、精确 audience、有效期和 Bearer 类型，拒绝 ID Token 与 DPoP Token 替代；DPoP 使用协议包的请求验证器。

MCP 元数据遵循 RFC 9728，路径例如 `/.well-known/oauth-protected-resource/mcp`；401 响应应设置 `WWW-Authenticate` 为 `resource.Challenge`。资源请求必须使用 `resource` 的精确 audience，并为每个工具/操作检查 scope 与业务权限。`HasScope` 只判断已认证主体的 scope，不自动授权整个 MCP 服务。

## SAML SP

`KeycloakSamlMetadata.LoadSigningCertificatesAsync` 从固定 realm 获取 IdP 元数据。`KeycloakSamlServiceProvider` 提供 POST/Redirect AuthnRequest 与响应、Artifact SOAP、ECP、受保护的 IdP 发起事务、签名/加密断言及双向注销。证书、SP entityId、ACS、SLO 和解密密钥由宿主显式配置。只信任固定 IdP 证书，禁止 DTD，验证签名、audience、recipient、时效、请求关联和原子重放记录。

```csharp
var login = await saml.StartLoginAsync(new SamlLoginOptions
{
    RequestBinding = SamlBrowserBinding.Post,
    ResponseBinding = SamlBrowserBinding.Post,
    AuthenticationContexts = [new Uri("urn:example:assurance:2")]
}, cancellationToken);
// 将 login 保存在当前浏览器独享的受保护服务端存储。
// POST login.FormFields 到 login.AuthorizationUri；回调只读取原事务。
var session = await login.CompleteAsync(actualCallback,
    form["SAMLResponse"], form["RelayState"], cancellationToken);
```

认证上下文须配置到服务端实际 LoA/认证流程，并检查签名断言达到要求；独立开关 `KeycloakSdk.Protocols.SamlStepUp` 可关闭逐级认证。`StartIdpInitiatedLoginAsync` 仍要求宿主保存预先创建的浏览器事务，禁止按外来的 RelayState 重建。Artifact 解析只访问固定 realm 的 SOAP 端点；ECP 在开关检查后才读取每次调用的用户凭据，生产环境强制 HTTPS。

入站注销使用 `HandleLogoutPostAsync`、`HandleLogoutRedirectAsync` 或 `HandleLogoutSoapAsync`，配合宿主 `ISamlLogoutSessionStore`。宿主须在同一个持久化事务中完成指定 issuer/SP/NameID/session-index 的会话失效与 `ReplayKey` 收据记录；重复请求成功返回，存储失败不能占用收据，也不能确认成功。SDK 在验证签名、目标、身份、时效后才调用存储，提交成功后才生成签名响应。固定目标可能省略可选 `NotOnOrAfter`，此时严格限制已签名 IssueInstant 的五分钟期限。证据仍须与当前源码、Managed 运行模式一致后才能晋升；该模块不声明 Native AOT 支持。

## 验证门禁 / Verification

Hosting 的 35 项独立测试要求自有源码方法、行和分支覆盖率均为 100%。测试包含框架事件与 Options 重建、注销存储、MCP 元数据、签名 SAML Redirect/Artifact/ECP、签名后校验与 XML/HTTP 边界。覆盖率不包含第三方库和 `obj/` 生成代码，真实 Keycloak 业务与包消费还须通过单独发布门禁。

The 35 Hosting tests enforce 100% source method, line and branch coverage. Signed SAML bindings, host events, logout, resource metadata and failure boundaries are tested independently; live Keycloak acceptance and package consumption remain separate release gates.
