# 服务端认证与应用接入

固定目标为 Keycloak 26.8.1。应用通过 OIDC 或 SAML 接收已经验证的身份；WebAuthn、Passkey、OTP、恢复码、邮箱确认和 Kerberos 的认证流程由 Keycloak、用户浏览器及其可信基础设施执行。SDK 不接收浏览器认证器的私钥，也不要求应用代收用户密码。

## 发起登录与账号操作

```csharp
var transaction = await OidcLoginTransaction.StartAsync(
    oidc,
    OAuthClientAuthentication.Public("my-application"),
    new Uri("https://application.example/callback"),
    options: new OidcAuthorizationOptions
    {
        Action = "webauthn-register-passwordless",
        RequiredAuthenticationCapabilities =
            [KeycloakAuthenticationCapability.Passkeys]
    },
    cancellationToken: cancellationToken);

// 保存在发起请求的用户浏览器对应的受保护服务端事务中，再跳转。
// 回调时必须找回同一事务；不能从查询参数重建该事务。
var login = await transaction.CompleteAsync(
    callbackUri, clientAuthentication, idTokenValidator, cancellationToken);
```

`Action` 传递 Keycloak 的 `kc_action`。SDK 自动为 WebAuthn 注册、恢复码配置和邮箱更新检查相应能力；`idp_link:` 保留独立的账号关联能力。其他认证流程可以通过 `RequiredAuthenticationCapabilities` 声明额外依赖。声明只控制可用性，不证明实际使用了某种认证方式。

成功的 OIDC 登录只证明身份验证完成。用户可能取消账号操作；未经签名的 `kc_action_status` 也不能证明数据库已经改变。需要确认注册、解绑或邮箱变化的业务，应使用具备相应授权的 Account API 或 Admin API 独立读取最终状态。

ASP.NET Core 宿主可以使用受保护的挑战属性，继续由框架维护 state、nonce、关联 cookie 和 PKCE：

```csharp
var properties = new AuthenticationProperties { RedirectUri = "/account" }
    .WithKeycloakAuthentication(
        [KeycloakAuthenticationCapability.Passkeys],
        action: "webauthn-register-passwordless");
await httpContext.ChallengeAsync("keycloak", properties);
```

宿主适配会在跳转前和兑换授权码前重新检查对应能力。属性应由可信应用路由构造，不能直接复制任意用户查询参数。

## 刷新与临时身份

刷新响应不是新的浏览器登录。保留原先已经验证的身份，只对直接来自认证刷新响应的 ID Token 调用刷新专用校验器：

```csharp
var refreshedIdentity = await idTokenValidator.ValidateRefreshedIdTokenAsync(
    refreshedIdToken, originalLogin.Identity, refreshedAccessToken, cancellationToken);
```

它重新检查签名、固定 issuer、audience、有效期、subject 以及返回的认证上下文。刷新响应可以省略 nonce；如果返回 nonce 或 auth_time，它们必须匹配原认证。需要认证强度的应用仍须重新应用自己的 assurance 策略。不能用此入口接收未经请求的令牌或浏览器回调。

临时代理用户由 Keycloak 的 `transient-users` 实验功能提供。应用不应把这类 subject 当作永久账户主键，也不能假定再次登录会得到相同 subject。SDK 将这一依赖与普通持久身份代理登录分开控制。

## 分开控制稳定与非稳定能力

普通认证、WebAuthn、Passkey、Kerberos、恢复码和更新邮箱分别登记。临时代理用户、旧版全会话退出、旧版条件式 Passkey UI、Instagram 和 Twitter 兼容配置单独登记，保留固定上游的 Experimental 或 Deprecated 标记。

固定源码中的 `TWITTER_BROKER` 同时具有 Stable 类型和 `deprecated=true` 标记，因此支持策略仍要求单独的 Deprecated 许可。`logout-all-sessions:v1` 的旧行为只退出其他普通会话，保留离线会话；当前验收同时检查被撤销的普通刷新凭据和仍可用的离线刷新凭据，保留这一服务端兼容语义。

使用生产支持工厂时，流程先检查固定版本、当前源码对应的独立运行时验收、服务端功能状态及每项非稳定能力的显式选择，再检查平台开关面的最终主开关和能力开关。仅开启 `KeycloakSdk.Protocols.Authentication` 不会连带开放其非稳定子能力。原始 `ProtocolTransport` 构造函数用于开发与候选验证，不能代替支持策略工厂。

## 对实际认证强度提出要求

如果业务必须使用双因素或指定认证方法，应配置 `OidcAssuranceRequirement`，检查已经验签的 `acr`、`auth_time`、`amr`，并使 Keycloak 的认证流与映射匹配策略。不能仅凭 `kc_idp_hint`、认证能力声明、用户名、某个凭证的存在或 `iat` 推断本次登录的认证强度。

## 验证边界

认证软件夹具只属于测试项目，用于向真实 Keycloak 提交完整的 WebAuthn 创建与断言仪式，验证挑战、RP、来源、用户验证及签名。它不作为浏览器 WebAuthn 库发布。生产环境仍应使用 Keycloak 的浏览器 UI，并对目标浏览器、认证器与企业 Kerberos 环境完成部署验收。

认证界面、KDC/Active Directory、社交服务账户、邮件投递和凭证安全存储由对应服务端、浏览器或宿主负责。它们的配置责任不等于 SDK 已验收。每项当前支持与运行时状态以[独立能力矩阵](contracts/platform-capability-matrix.md)为准。

认证能力声明用于应用入口的策略检查，不会远程改写 Keycloak 的浏览器流、登录页面或服务器功能开关。管理员必须使这些服务端配置与应用策略匹配；若要限制本次登录实际使用的方法，还须验证可信的认证强度声明。

Kerberos 验收使用独立的 MIT KDC 容器和仅监听共享测试网络回环地址的 SPNEGO 对端。产品的 Managed 与 NativeAOT 运行时镜像不安装 KDC、Python 或 Kerberos 客户端工具。测试基础镜像使用固定摘要，最终业务证据保留实际构建的对端镜像摘要；票据、密钥表和主密钥只存在于本轮测试的临时容器或被忽略目录中。

Twitter 与 Instagram 验收使用受控 HTTPS 协议对端，并将 DNS 覆盖限定在本轮测试容器中。测试检查 OAuth1 请求签名或 OAuth2 授权码、broker state 和已关联的最终身份，不访问真实社交账户。真实服务是否仍提供对应 API、账号许可和服务条款，属于外部服务的可用性与接入责任。
