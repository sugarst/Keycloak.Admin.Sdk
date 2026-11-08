# 钱包协议集成（26.8.1 开发版）

钱包属于独立应用协议矩阵。Admin API 的 520 个操作不代表钱包功能已经验收。当前接口和真实互操作测试已加入开发分支；正式开放仍须当前输入下的运行时证据及逐项晋升，不能把本页理解为已发布支持承诺。

| 能力 | Keycloak 阶段 | 最终宿主开关键（前缀 `KeycloakSdk.Protocols.`） |
| --- | --- | --- |
| OID4VCI 元数据、授权码签发、JWT/SD-JWT、proof、刷新及账户凭证管理 | Preview | `Wallet` |
| 预授权码 | Experimental | `WalletPreAuthorized`，同时需要 `Wallet` |
| REST Offer 与二维码 | Experimental | `WalletOffers`，同时需要 `Wallet` |
| mdoc 签发与验证 | Experimental | `WalletMdoc`，同时需要 `Wallet` |
| OID4VP 出示 | Experimental | `WalletPresentation` |
| Attestation-Based Client Authentication | Experimental | `WalletAttestation` |

`ProtocolTransport.CreateSupported` 先检查独立支持证据、实际版本、运行时/RID、服务端特性和对应能力的 Preview/Experimental opt-in，再读取平台开关面的最终开关。总开关 `KeycloakSdk.Protocols` 同时必须打开。普通传输构造器仅用于明确的开发与候选验证，不会产生支持证据。

## 签发和验证

使用固定 realm 的标准元数据端点，SDK 不根据外部 Offer、令牌或证书中的 URL 转发访问令牌。授权请求同时包含配置对应的凭证 scope 及 `authorization_details`。将 PKCE 事务绑定到原始浏览器的受保护服务端会话，按正常 OIDC 回调完成后读取 token response 的 `credential_identifiers`。

```csharp
var wallet = new Oid4vcIssuerClient(transport);
var metadata = await wallet.GetIssuerMetadataAsync(cancellationToken);
var configuration = metadata.Configurations[credentialConfigurationId];

// accessToken、credentialIdentifier 来自该配置的授权码 + PKCE 响应。
// holderKey 是宿主保护并随凭证持久保存的 Oid4vcProofKey。
var nonceResponse = await wallet.RequestNonceAsync(cancellationToken);
string nonce = nonceResponse.Json!.Value.GetProperty("c_nonce").GetString()!;
string proof = holderKey.CreateIssuanceProof(transport.Issuer, nonce, clientId);
var response = await wallet.RequestCredentialAsync(configuration, accessToken,
    jwtProofs: [proof], credentialIdentifier: credentialIdentifier,
    cancellationToken: cancellationToken);

string compact = response.Json!.Value.GetProperty("credentials")[0]
    .GetProperty("credential").GetString()!;
var verified = await new Oid4vcCredentialValidator(oidc)
    .ValidateAsync(compact, configuration, holderKey.Thumbprint, cancellationToken);
```

HTTP 成功和 JSON 解析不代表凭证可信。JWT/SD-JWT 验证固定发行者、显式签名算法、签名、有效期、凭证类型和预期持有者；SD-JWT 还验证披露摘要、递归/数组披露、重复声明及覆盖攻击。令牌中的 `jku`、`x5u`、`x5c` 不会自行建立信任。签名算法默认 RS256；使用 ES256 等其他允许算法时须显式配置。凭证不是浏览器登录身份，也不代替资源授权。

`Oid4vcTokenClient.RedeemPreAuthorizedCodeAsync` 单次兑换预授权码，不自动重试；交易码在宿主另行取得后显式传入。`RefreshCredentialTokenAsync` 使用正常的 OAuth `refresh_token` grant，保留凭证授权约束。`Oid4vcAccountClient` 使用当前用户的普通账户访问令牌管理 entitlement 和 issued credential；限定到凭证端点的签发令牌不能代替账户令牌。

## 加密及 mdoc

`Oid4vcCredentialEncryption` 支持 RSA-OAEP / RSA-OAEP-256 与认证内容加密。请求使用发行者元数据提供的加密公钥及其 `kid`、`alg`；响应公钥 JWK 必须显式选择发行者公布的 `alg`，并与宿主持有的私钥匹配。不能假定发行者一定公布 RSA-OAEP-256。

26.8.1 实际要求：申请加密响应时，请求本身必须是 JWE。SDK 构造器因此始终要求请求加密配置，响应加密可选。收到密文后调用 `DecryptResponse`，再独立验证其中的凭证；解密成功不证明发行者或业务身份。

mdoc 使用微软 CBOR/COSE 库验证 IssuerAuth、MSO、数据元素摘要、有效期和设备密钥。`MdocCredentialValidator` 要求宿主显式提供受信 CA 根；嵌入证书不能建立信任。默认启用证书撤销校验，离线测试须明确配置自己的撤销模式。当前验证 profile 接受 EC 签名与 P-256 设备密钥，不能将其扩大解释为所有算法配置均已验证。

## 出示及客户端证明

`Oid4vpClient` 的 verifier client ID 必须来自宿主独立信任的配置，不能直接信任钱包链接中提交的 `client_id`。SDK 验证固定 broker 的签名 request object、`x509_hash` 证书指纹、时效、nonce、state 及响应目的地。宿主向用户展示 verifier 与 DCQL 请求，在明确同意后向 `PresentAsync` 传入选定的披露项；SDK 不自动披露所有声明。普通及 ECDH-ES/GCM 加密的 direct_post、同设备与跨设备流程分别有真实验证。

26.8.1 verifier 当前只处理一个 SD-JWT 出示，并只接受 ES256 的发行者及持有者签名。SDK 还在发出请求前检查选定披露满足该 profile 的 DCQL 类型、必要声明及适用的 claim set；不能依赖服务端尚未实现的 DCQL 完整检查。完成登录必须回到发起事务的原浏览器。远程钱包返回成功不是宿主登录完成，跨设备状态轮询也必须使用原浏览器的 Cookie 会话。

钱包客户端证明通过 `OAuthClientAuthentication.Attestation` 接入。宿主每次提供 attester 签发的 attestation 和新的 PoP；`Oid4vcProofKey.CreateClientAttestationProof` 生成绑定授权服务器及客户端的新 PoP。服务端独立配置 attester 信任，SDK 不代替 attester 基础设施。入站客户端认证仍以服务端校验为准。

## 固定服务端的共存条件

26.8.1 的 SSF 默认创建 `ssf.read`、`ssf.manage` 时没有设置 `protocol`，而 OID4VC Offer 查找会直接调用该字段，二者在同一 realm 共存可能触发 500。配置此组合时，管理员应显式将这两个 scope 的协议设为 `openid-connect`。测试在自己创建的 realm 中执行这一配置；SDK 不在普通请求中自动修改服务端或通过重试掩盖错误。

SD-JWT 和 mdoc 签发必须使用适用的、由 CA 签发的签名证书；默认的自签名 realm 证书不能满足这两个签发 profile。服务器主题、Java SPI、CA、attester 和终端钱包的部署仍由对应宿主或基础设施负责。

另一个已验证的服务端限制：预授权 Offer 创建后撤销用户 entitlement，再兑换该码时，26.8.1 在创建 issued credential 的路径抛出异常并返回 500。SDK 保留这个终止错误，不把它改成成功或自动重试。测试还独立检查没有新凭证落库。此行为不能表述为标准的 OAuth 拒绝响应；修复服务端状态码不属于客户端 SDK 的实施范围。
