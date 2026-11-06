# Keycloak 26.8.1 全能力扩展

本分支的目标是覆盖固定 Keycloak 26.8.1 中供应用调用的 API、认证与授权协议。部署、数据库、多集群、服务端 UI 和 Java SPI 的实施由 Keycloak 或外部工具承担，并保留明确责任记录。目标不包含用户任意安装的第三方扩展。

## 两种支持矩阵

| 范围 | 可审阅输入 | 生成结果 | 校验 |
| --- | --- | --- | --- |
| Admin API 操作 | `contracts/capability-rules.json`、固定 OpenAPI 和源码 | `contracts/capabilities.json`、操作支持矩阵 | `Generate-CapabilityCatalog.cs -- --check`、既有操作及真实验收 |
| 上游全能力与应用协议 | `contracts/platform-coverage-rules.json`、固定源码 `Profile.java` | `contracts/platform-capabilities.json`、全能力矩阵 | `Generate-PlatformMatrix.cs -- --check`、独立协议测试及工作流 |

当前发现 80 个上游功能开关，全部有唯一、显式责任映射；另外登记 52 个应用协议和宿主集成能力族，包含未对应独立 feature flag 的基础 OIDC、SAML 和动态注册。标准交换、旧版交换、委托、JWT Grant、Device、CIBA、PAR、参数化 scope、资源指示器、身份断言和 CIMD 分别登记，避免基础登录的证据替代其他授权流程。SPIFFE Preview 与 Stable 联合/Kubernetes 客户端认证独立晋升和 opt-in。功能开关数、能力族数和 REST 操作数不能相加，也不能相互替代。

上游 `Stable/Preview/Experimental/Deprecated` 来自固定源码；SDK 的 `NotImplemented/Partial/Implemented` 与实际业务验收分开登记。已有 Admin API 证据不能证明协议已实现；存在通用 HTTP 方法也不能证明协议完整。

## 模块与身份边界

- `Keycloak.Admin.Sdk`：管理接口和服务账号管理认证。
- `Keycloak.Admin.Sdk.Protocols`：realm 绑定协议传输、显式客户端认证、用户令牌、钱包签发及出示，以及服务器托管认证的应用入口。开发包尚未发布。
- `Keycloak.Admin.Sdk.FeatureManagement`：宿主的最后开放与关闭；协议模块可注入 `KeycloakMicrosoftFeatureGate`，Native AOT 可用快照 gate。
- `Keycloak.Admin.Sdk.Hosting`：Managed ASP.NET Core OIDC/JWT、服务端票据、注销接收、MCP 资源元数据和 SAML SP；依赖 ASP.NET Core 与 ITfoxtec。该包不声明 Native AOT 支持，各宿主能力仍须逐项晋升。

管理 token 不会自动传入用户协议调用。每个用户的令牌、刷新和交换状态由各自调用上下文持有；协议模块不跨用户缓存，也不把解析 JWT 当作验证身份。

## 实现范围与验收

当前实现包括 OIDC 发现/JWKS/UserInfo、PKCE 登录事务与防重放、签名及加密 JAR、宿主发布的 request_uri、7 种回调传输与 JARM、隐式／混合／none 响应、ID/access token 验签及 JWE 解密、Device/CIBA poll/ping、签名 CIBA 请求和设备回调、PAR/注销、标准/旧版/客户端与管理员委托交换、JWT Grant、资源指示器和参数化 scope、私钥/HMAC 客户端断言、轮换工作负载令牌、SCIM、账户、动态注册、UMA、AuthZen、Client Admin v2、管理端 OpenAPI、Docker、DPoP、身份代理 v1/v2、SSF 和宿主集成。存在调用入口仍不等于该能力族验收完成。专用协议测试独立于 520 项 Admin API 测试，源码行和分支覆盖率均要求 100%。

钱包范围包括 JWT VC、SD-JWT、mdoc、nonce/proof/batch、请求及响应加密、授权码与预授权码、REST Offer/二维码、刷新与账户撤销、OID4VP 同设备及跨设备出示，以及客户端 attestation。认证范围包括 WebAuthn、Passkey、恢复码、邮箱确认、Kerberos、临时代理身份和独立控制的弃用兼容流程。使用与约束分别见[钱包集成](wallet-integration.md)和[认证集成](authentication-integration.md)。

`Test-ApplicationProtocols.cs` 在固定镜像的临时容器中验证选定工作流，失败先移除旧结果，退出清理本次容器与 realm。产物明确标记 `promoted=false`，不能代替全能力验收。

验收夹具针对每种协议执行真实业务效果及拒绝场景，包含用户同意、持久化结果、独立令牌验签、策略撤销、重放与过期。Managed 另外验证真实 ASP.NET Core 登录/本地会话/注销，以及 SAML 签名、加密断言和单点注销。运行模式、当前输入、程序哈希和不可变报告见 [选定协议工作流验收](contracts/application-protocol-workflows.md)。历史结果不支持已修改的代码，契约覆盖率也不替代业务验收，见 [独立协议覆盖率报告](contracts/protocol-coverage.md)。

```shell
dotnet run --file tools/Generate-PlatformMatrix.cs
dotnet run --file tools/Generate-PlatformMatrix.cs -- --check
dotnet run --file tools/Test-ApplicationProtocols.cs
dotnet run --file tools/Test-ApplicationProtocols.cs -- --native-aot
dotnet run --file tools/Test-ApplicationProtocols.cs -- --legacy
dotnet run --file tools/Test-ApplicationProtocols.cs -- --legacy --native-aot
# 仅用于宿主定位问题，不生成验收报告，也不能晋升能力：
dotnet run --file tools/Test-ApplicationProtocols.cs -- --hosting-only
dotnet run --file tools/Test-ApplicationProtocols.cs -- --oidc-only
dotnet run --file tools/Check-ApplicationProtocols.cs -- --archive
dotnet run --file tools/Check-ApplicationProtocols.cs -- --archive --legacy
dotnet run --file tools/Generate-PlatformMatrix.cs -- --require-complete
dotnet run --file tools/Test-ApplicationProtocols.cs -- --support-only
dotnet run --file tools/Test-ApplicationProtocols.cs -- --support-only --native-aot
dotnet run --file tools/Verify.cs -- --native-container
```

后续每个应用能力都必须完成以下验收后才能宣布支持：

1. 实现该能力的全部必要操作与状态机，不仅是发送表单或 JSON。
2. 正确处理版本、功能阶段、服务器依赖、用户同意和授权边界。
3. 验证签名、issuer、audience、时效、nonce、重放与撤销等适用的协议约束。
4. 针对明确运行模式和原生 RID，完成真实业务效果、权限拒绝、取消和宿主开关关闭场景。
5. 归档与当前输入及构建程序绑定的证据，并完成独立应用能力晋升。

独立晋升计划维护于 `contracts/application-validation-plans.json`。`Check-ApplicationProtocols.cs -- --archive` 验证两种运行模式后，将证据内容寻址归档，并更新 `contracts/application-verification-profiles.json`；只有实现完成且全部验收标准都有证明的能力族才获得对应支持配置。宿主断言放入 Managed 专属检查组，不能晋升 Native AOT。旧报告、缺失断言、错误 RID、篡改哈希、未启用的服务器特性均不能晋升。FeatureManagement 仍只负责最终开放与关闭。

验证输入包含协议与宿主安全测试及 AOT smoke。生成的 Admin/平台支持目录和应用证据注册表不作为验证输入，避免晋升改变自身指纹；规则、计划、目标与实现仍全部绑定。修改这些输入后旧证据自动退出当前支持，历史归档保留。

全覆盖门禁根据全部应用能力与 Admin API 的支持配置计算完成状态，`Release.cs` 首先执行此门禁。当前 52/52 个审阅应用能力族均已完成实现与独立晋升，矩阵 `complete=true`；520 项 Admin API 中 506 项为 Supported，14 项保留 FGAP v1 Compatibility。标准计划 Managed 434/434、Native AOT 391/391；旧版兼容计划分别 20/20。此完成状态只适用于矩阵记录的版本、运行环境和责任边界。

preview.3 仍是未发布的开发版本。覆盖门禁通过不代表已经发布 NuGet，也不替代完整构建、包消费、严格原生程序、Admin API 真实验收和非 Stable 受保护复验。

委托撤销遵循固定服务端语义：删除 delegate 权限后，主体令牌刷新移除 may_act；刷新后的令牌不能继续委托。已经签发的 access token 有自己的有效期，不能把删除权限表述为即时撤销所有令牌。即时关闭业务还须使用宿主开关及适用的会话注销/撤销。

## 验证范围与宿主责任

| 能力族 | 实现及验收范围 |
| --- | --- |
| OIDC | JAR/JARM、加密 ID Token、隐式／混合／none、认证强度和原身份绑定的刷新校验；应用保护原始浏览器事务 |
| 旧版交换、旧版身份代理、SSF | 独立的兼容配置、SET push/poll 与原子业务提交；非 Stable 能力须显式选择 |
| 钱包 | 签发、出示、认证及 7 个 Admin 操作；宿主管理钱包私钥、信任根、用户同意及安全存储 |
| SAML | Managed POST/Redirect、Artifact/ECP、受保护的 IdP 发起、双向注销和 OTP 逐级认证；宿主管理票据及原子会话撤销 |
| 认证 | WebAuthn/Passkey 的服务端仪式、恢复码、邮箱确认、临时用户、真实 Kerberos 票据和兼容社交协议；浏览器、认证器、KDC 与外部社交服务由对应环境提供 |

此外，mTLS 和联合工作负载适配必须在每次输入变更后重新通过对应运行时证据。联合认证测试使用真实 Keycloak 与受控外部 OIDC/JWKS/SPIFFE bundle，证明 SDK 的投射文件读取、轮换与服务端信任约束；不声称部署或验收了 Kubernetes 集群、SPIRE 或工作负载签发基础设施，这些属于既定外部责任边界。

实现、规则或计划改变后必须重新验证。每种能力的当前支持、运行模式与责任范围见[全能力矩阵](contracts/platform-capability-matrix.md)。

固定版本中的 `SSE_CAEP` 指旧版 Shared Signals and Events 的 CAEP 兼容格式，不是 HTTP Server-Sent Events。服务端实现的事件投递方式是 SET push/poll，不能把它描述为尚待补齐的 event-stream 接口。

OIDC 的 JAR、JARM 和浏览器兼容响应分别登记并独立晋升。默认交互登录仍使用 code + PKCE。`OidcBrowserTransaction` 对前端 ID Token 强制验证适用的 `at_hash` 和 `c_hash`；OAuth-only 与 none 响应不产生登录身份。JWE 解密支持显式宿主密钥及 RSA-OAEP／RSA-OAEP-256，不允许 RSA1_5 解包。固定 26.8.1 的 JARM 会重复写入 `iss`，仅在两个值均与固定 realm 完全一致时兼容；其他重复声明一律拒绝。

SSF 的未知主体默认以成功响应保护存在性隐私，验收通过独立签名 claim 确认没有订阅效果；不能只看 HTTP 200。接收方移除主体会保留服务端宽限时间戳，再添加会清除该时间戳；这与即时撤销已有会话不同。

钱包的 Preview 签发与 5 个 Experimental 子能力分别登记，不把实验能力作为基础签发的统一开放条件。固定版本的 SSF scope 共存条件、CA 签名证书、响应加密约束及 OID4VP profile 边界见 [钱包集成](wallet-integration.md)。这些要求属于可审阅的服务端配置和协议责任边界，不会通过重试、隐藏修改或继承 Admin 验收来掩盖。
