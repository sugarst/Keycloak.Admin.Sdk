# Keycloak.Admin.Sdk.Protocols

Keycloak 26.8.1 的应用协议客户端开发模块，与 Admin API 操作目录分别统计。

当前提供 OIDC/OAuth、PKCE 一次性登录事务、ID/access token 验证、Device/CIBA、PAR、标准/旧版/委托交换、JWT Grant、资源指示器、参数化 scope、客户端断言、SCIM、动态注册、UMA、账户、AuthZen、Client Admin v2、OpenAPI、Docker、DPoP、身份代理和 SSF。客户端接受明确的用户令牌或客户端认证，不隐式复用管理员身份。

钱包开发接口包括 `Oid4vcIssuerClient`、`Oid4vcTokenClient`、`Oid4vcAccountClient`、`Oid4vcProofKey`、`Oid4vcCredentialValidator`、`MdocCredentialValidator` 和 `Oid4vpClient`。凭证签发、预授权码、REST Offer、mdoc、OID4VP 与钱包客户端证明分别验证和晋升；详细使用方式和固定版本约束见 [钱包集成](../../../docs/wallet-integration.md)。

JAR 使用 `OidcRequestObjectSigner` 配合 `OidcLoginTransaction.StartSignedAsync`；`StartReferencedAsync` 将原事务的签名对象发布到宿主 HTTPS URI，并由 Keycloak 按注册的 request_uri 白名单取回。JARM 使用 `OidcAuthorizationOptions.ResponseMode` 选择 query、fragment、form_post 及其签名模式；form_post 通过原事务的 `CompleteFormPostAsync` 接收。签名请求、签名响应和浏览器兼容流程分别受 `OidcRequestObjects`、`OidcSignedResponses`、`OidcBrowserCompatibility` 开关控制，并分别晋升。

默认交互登录使用 code + PKCE。显式兼容集成可使用 `OidcBrowserTransaction` 的隐式／混合／none 响应；前端 ID Token 强制绑定适用的 access token/code hash，OAuth-only 与 none 不产生登录身份。JWE 支持宿主提供的解密密钥及 RSA-OAEP／RSA-OAEP-256，禁止 RSA1_5 解包。宿主始终负责保护并绑定原始浏览器事务。

本开发包尚未发布。ASP.NET Core 会话和 SAML SP 位于单独的 Managed `Keycloak.Admin.Sdk.Hosting` 包。每项协议、认证和钱包能力都按独立运行时证据晋升；具体支持以矩阵为准。服务端版本、功能阶段、授权和同意须独立核验。

服务器托管认证可通过 `OidcAuthorizationOptions.Action` 与 `RequiredAuthenticationCapabilities` 声明独立依赖。WebAuthn、Passkey、恢复码、邮箱确认、Kerberos、临时身份与弃用兼容流程分别控制；验证刷新身份时使用 `ValidateRefreshedIdTokenAsync` 绑定原先已验证的用户和客户端。详见[认证集成](../../../docs/authentication-integration.md)。

```csharp
using Keycloak.Admin.Sdk.Protocols;

// server、realm、clientId、secretStore、cancellationToken 由宿主管理。
using var http = new HttpClient(new SocketsHttpHandler { AllowAutoRedirect = false });
var transport = new ProtocolTransport(http, server, realm);
var oidc = new OidcClient(transport);
var client = OAuthClientAuthentication.SecretBasic(clientId,
    ct => secretStore.GetSecretAsync(ct));
var result = await oidc.ClientCredentialsAsync(client, cancellationToken: cancellationToken);
```

所有异步入口传递取消令牌，写入及令牌请求不会自动重试。宿主管理 HTTP、配置、密钥及各用户会话的生命周期。原始授权响应不代表已验证身份；使用 `OidcLoginTransaction.CompleteAsync` 和 `OidcTokenValidator` 校验签名、固定 issuer/audience、有效期、nonce、azp 及适用的 at_hash。密钥仅从固定 realm 的 JWKS 获取，令牌内的 jku/x5u/jwk 不建立信任。

```csharp
// 开始登录：将 transaction 保存在当前浏览器用户独享的受保护服务端会话中。
var transaction = await OidcLoginTransaction.StartAsync(oidc, client, callbackUri,
    cancellationToken: cancellationToken);
// 将浏览器重定向至 transaction.AuthorizationUri。

// 回调：只允许读取该浏览器会话原先保存的 transaction，禁止按外来 state 创建事务。
var login = await transaction.CompleteAsync(receivedCallbackUri, client,
    new OidcTokenValidator(oidc, clientId), cancellationToken);
string subject = login.Identity.Subject;
```

应用需要强制逐级认证时，设置 `OidcAuthorizationOptions.RequiredAssurance`，例如 `new OidcAssuranceRequirement(["urn:app:loa:2"], TimeSpan.FromMinutes(5), ["pwd", "otp"])`。先在 Keycloak 配置对应的 ACR/LoA、认证执行器方法引用及 AMR mapper。SDK 检查已验签 ID Token 中原始 JSON 类型的 `acr`、`auth_time`、`amr`；较低等级、缺失因素或过期认证均不能满足要求，令牌新签发时间不延长 `auth_time`。该流程独立受 `OidcAssurance` 开关控制。Managed 宿主还需独立的 `BrowserOidcAssurance` 开关，并在本地会话校验中持续检查认证时效。

事务最多有效 15 分钟，只允许一次兑换。宿主负责浏览器绑定、存储保护和自己的登录会话；跨节点宿主应使用框架 OIDC 中间件及原子共享事务存储。不得把事务或原始令牌放入未受保护的 Cookie/日志。ID Token 校验不代替资源服务器的 access token 校验和授权。

Device/CIBA 使用 `OAuthPollingLease` 配合 `PollDeviceAsync` / `PollBackchannelAsync`；pending 等待，slow_down 持续增加五秒，拒绝、到期、网络错误和取消终止轮询。CIBA ping 使用 `CibaPingNotificationValidator` 验证随机通知密钥、auth_req_id、过期和原子重放存储后才兑换令牌；通知令牌、RP 请求标识和认证设备回调凭据互不替代。签名请求使用 `CibaRequestSigner`，设备完成使用 `CompleteBackchannelAuthenticationAsync`。Keycloak 26.8.1 仅支持 poll/ping，拒绝 push 和 user_code；其返回的 expires_in 可能长于 requested_expiry，可传 `FromCibaResponse(..., maximumLifetime: requestedLifetime)` 在本地缩短期限。

资源指示器通过 `OidcAuthorizationOptions.Resources` 或令牌方法的 `resources` 参数传入，26.8.1 只支持一个资源，SDK 拒绝多个值及 query/fragment。刷新不能改换原资源。参数化 scope 使用 `OidcParameterizedScope`、`OidcAuthorizationOptions.ParameterizedScopes` 和 `ClientCredentialsWithParameterizedScopesAsync`，独立经过 `OidcParameterizedScopes` 开关。服务端负责 scope 分配、参数类型、重复性及同意。

`ClientAssertionSigner` 每次生成绑定固定 token endpoint 的短期断言，可接入 `OAuthClientAuthentication.JwtAssertion`；`ProjectedWorkloadToken` 每次读取宿主配置的本地投射文件，支持文件轮换。这些原语不等于 SPIFFE/Kubernetes 联合信任已经验收。

工作负载认证使用 `FederatedAssertion` 或 `SpiffeAssertion`；后者发送独立的 `jwt-spiffe` assertion type，并使用 `SpiffeClientAuth` 能力键。SPIFFE 在本目标是 Preview，必须单独 opt-in；Stable 联合/Kubernetes 认证通过 `FederatedClientAuth` 键控制，不受 SPIFFE 的阶段约束。断言的 issuer/subject/audience、有效期、签名和服务账号映射由配置的 Keycloak provider 校验；SDK 每次读取凭据源，支持投射文件的原子替换。测试使用受控外部发行者验证协议适配，不代替 Kubernetes/SPIRE 部署验收。上游允许有效期内的工作负载凭据复用，不能套用 private_key_jwt 的一次性 jti 规则。

```csharp
var projected = new ProjectedWorkloadToken("/var/run/secrets/keycloak/token");
var authentication = OAuthClientAuthentication.FederatedAssertion(clientId, projected.ReadAsync);
var result = await oidc.ClientCredentialsAsync(authentication, cancellationToken: cancellationToken);
// SPIFFE JWT-SVID 改用 SpiffeAssertion(clientId, projected.ReadAsync)。
```

mTLS 使用专用、正确验证服务端证书的 HttpClient，并配置实际 TLS 客户端证书；传输构造/工厂传入 `mutualTls: true`，使后续发现、令牌和 UserInfo 请求均检查 `MutualTls` 能力开关。令牌端点使用 `OAuthClientAuthentication.MutualTls(clientId)`，不发送 client secret。资源端先用 `KeycloakAccessTokenValidator` 验证令牌，再用 `MutualTlsTokenBinding.Matches` 将 `cnf.x5t#S256` 与宿主 TLS 层已认证的对端证书匹配；不接受客户端自行提交的证书头作为可信 TLS 身份。

委托调用使用 `ExchangeDelegatedAsync(client, subjectToken, actorToken, ...)`，必须先取得真实用户同意并配置 FGAP v2 的 delegate 权限。26.8.1 在主体令牌刷新时重新检查权限并可移除 may_act；删除权限不意味着已签发的 access token 立即失效。需即时停止业务时同时关闭宿主开关并按服务端语义注销/撤销会话。客户端委托令牌不能用于 Admin API。

使用专用 HTTP 客户端，不在默认 Authorization/Cookie 头中持有管理员或跨用户身份；后通道处理器应关闭自动重定向及 Cookie 共享。上例普通构造传输用于显式协议开发和候选验收；业务集成使用 `ProtocolTransport.CreateSupported`，核对当前输入对应的独立支持配置、实际服务端版本/feature、运行模式/RID 和逐能力非 Stable opt-in。最后再通过注入的主包 `IKeycloakFeatureGate` 检查总开关 `KeycloakSdk.Protocols` 和全部所需能力开关；快照 gate 读取同一代不可变快照。开关不产生支持证据。

标准交换的 `requestedTokenType` 支持 AccessToken、IdToken 和 RefreshToken。后者要求服务端客户端显式启用 `standard.token.exchange.enableRefreshRequestedTokenType=SAME_SESSION`，并持有在线用户会话。交换得到的 ID Token 放在 OAuth 响应的 `access_token` 字段，使用 `ValidateExchangedIdTokenAsync` 验证；它没有浏览器 nonce，不能用于接收浏览器登录回调。旧版交换使用独立的 `ExchangeLegacyAsync` / `ImpersonateLegacyAsync`，依赖 FGAP v1 及逐能力 Preview、Deprecated opt-in；旧版 Refresh Token 绑定请求客户端。其 SAML2 响应入口不代表全部 SAML profile 已验收。

ID-JAG 使用 `IdentityAssertionGrantAsync`，独立于 Stable JWT Grant 的 Experimental 开关；26.8.1 仅消费 `oauth-id-jag+jwt`，不提供 ID-JAG 签发端点。通用 `JwtGrantAsync` 也会识别该类型并应用独立开关，防止绕过。服务端校验受信 issuer、签名、audience、client_id、iat 和强制重放保护。

CIMD 使用 `CimdClientMetadata` 构造或读取公开元数据，再调用 `CreateAuthentication`。SDK 不从任意外来 URL 抓取文档；宿主发布公开文档，Keycloak 依服务端策略限制可信域名、client_id、redirect_uris 和认证密钥。文档不能包含 client secret 或私钥。私钥认证通过每次调用的断言回调提供，密钥轮换后必须同步公开 JWKS。

SSF 接收使用 `SecurityEventProcessor` 和宿主实现的 `ISecurityEventInbox`。该接口必须在同一个持久化事务中完成业务效果和 `ReceiptKey` 去重记录；重复投递应成功返回，存储失败应抛出异常以允许重试。只在 `ProcessAsync` 完成后返回 push 成功状态；poll 使用 `ProcessPollResponseAsync` 返回的 ID 作为下一次请求的 ack，同时继续处理新返回的 SET。不要在持久化前占用重放记录。业务代码只处理已订阅、已验签的 CAEP/RISC 事件，并负责 issuer、用户、会话和租户命名空间的映射；管理员注销所有会话时，26.8.1 的会话标识是 `ALL`。旧版 `SSE_CAEP` 是 Shared Signals 格式兼容，不是 HTTP Server-Sent Events。
