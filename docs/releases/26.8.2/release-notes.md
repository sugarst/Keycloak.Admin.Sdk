# Keycloak.Admin.Sdk 26.8.2

## 中文升级说明

本地候选面向 **Keycloak 26.8.2** 和 **.NET 10**。从 26.8.1 升级时，自建管理客户端最先需要配置 `kc-admin-api`。同时检查委派管理员的 Protocol Mapper 写入权限、动态客户端注册策略，以及应用对会话统计和令牌有效期的假设。`Keycloak.Admin.Sdk`、`Keycloak.Admin.Sdk.Protocols`、`Keycloak.Admin.Sdk.Hosting` 和 `Keycloak.Admin.Sdk.Platform` 统一使用 `26.8.2`，NuGet 发布状态为待发布。

### 管理认证与权限

| 变化 | 对现有调用方的影响 |
| --- | --- |
| Admin REST API 校验 scope 和 audience | 在**签发令牌的 realm** 中为自建管理客户端分配内置 `kc-admin-api` client scope。Keycloak 以该 realm 的前端 URL 解析管理 API audience，例如 `https://auth.example.com/admin/realms/ops`。内置 `admin-cli` 和 `security-admin-console` 已分配默认 scope。默认 scope 随令牌签发，可选 scope 需要客户端显式请求。自行传入 bearer token 时也要满足两项校验。 |
| 客户端与 client scope 的 Protocol Mapper 写入 | 持有 `manage-realm` 的管理员可以执行写入。委派的客户端管理员还需要 realm 中配置允许的 mapper 类型，空名单会阻止委派写入。适用场景包括新增、更新、删除、批量写入及经资源表示提交的 mapper 变更。已验证原样回写既有 mapper 可以成功。 |
| Dynamic Client Registration（DCR） | 可用 mapper 类型取 realm 级名单与注册策略名单的交集。更新时可保留既有 mapper。默认注册策略拒绝通过 `defaultRoles` 修改 realm 默认角色，并将注册客户端的 `fullScopeAllowed` 设为 `false`。更新尝试开启完整作用域时返回 `403`。用授权的 Admin REST API 管理默认角色和作用域。专项也验证了读改写可保留后通道注销撤销离线令牌的设置。 |
| FGAP v2 内部客户端 | `admin-permissions` 作为内部客户端保护。委派管理员尝试更新或删除时会收到 `403`。授权策略继续通过相应的 realm 权限配置。 |
| Realm 客户端会话统计 | `client-session-stats` 仍要求 realm 查看或管理权限，结果按可见客户端过滤。仅有 realm 查看权限时结果可能为空。在 FGAP v2 的细粒度授权中，客户端 `manage` 和 `view` 独立。依赖统计结果判断会话存量的调用方应考虑可见性。 |

SDK 新增 `ClientCredentialsTokenProviderOptions.Scope`，用于客户端凭据令牌请求。可选 scope 在 `AddKeycloakAdminSdk` 的配置回调中这样传入。如果同一配置还设置了令牌超时或失败冷却时间，将这些属性放在同一个 `Token` 配置对象中。默认 scope 场景可将 `Scope` 设为 `null`，由 Keycloak 的默认配置选择。

```csharp
options.Token = new() { Scope = "kc-admin-api" };
```

实测 access token 缺少管理 scope 时，Admin API 返回 `401`。有管理 scope 但权限不足时返回 `403`。scope、audience 和资源权限齐备时返回 `200`。SDK 异常的 `Stage` 可区分令牌端点和 Admin API 失败。 [SDK 认证与错误处理](../../authentication-and-errors.md) · [Keycloak 26.8.2 升级指南](https://www.keycloak.org/docs/26.8.2/upgrading/)

### 上游协议与服务端兼容性

| 功能 | 26.8.2 行为与升级检查 |
| --- | --- |
| 标准令牌交换 | 默认限制换出的 access token 和 ID token，原始 subject token 到期时它们一同到期或更早到期。应用按实际 `expires_in` 和 `exp` 调度刷新或重新认证。刷新令牌由独立的客户端设置控制。 |
| CIBA | 保留的协议 claim 作为独立表单参数传入时，Keycloak 返回 `invalid_request`。调用方应改名自定义字段，并保留签名请求对象所需的 JWT claim。 |
| SAML SOAP 和旧协议 | SOAP 消息默认上限为 `120000` 字节。SAML 1.1 解析器默认关闭。检查 SOAP 客户端真实消息大小及使用的协议版本。 |
| SAML 身份代理 | 上游断言须有有效的 bearer subject confirmation，且代理默认拒绝带 `ProxyRestriction` 的断言。检查上游 IdP 的断言格式与联邦约定。 |
| SAML 适配器和注销 | 上游 Keycloak SAML 适配器核对 IdP issuer，生成的安装配置使用实际 realm URL。使用占位 IdP ID 的适配器需要更新配置。以 `SessionIndex` 执行 SAML 后通道注销的客户端须启用签名并签署请求。混合版本节点上的浏览器注销可能重新开始。 |
| 身份自动关联与组织入会 | 自动关联依赖已验证邮件或受信的 IdP 邮件。按域名自动加入组织也需要邮件验证。OIDC IdP 明确返回 `email_verified=false` 或用户在首登时修改邮箱时，Keycloak 会要求本地验证。检查对接 IdP 的验证语义和 realm SMTP。 |
| 命令行信任和用户同步 | 指定自定义信任库的 `kcadm` 与 `kcreg` 要求自签名服务器证书已导入库中。用户存储同步重新按配置周期执行，曾为双倍间隔配置的值需要复核。 |

上游同时将 Quarkus 更新为 `3.40.1.1`，并修复组织与认证边界、SAML 处理、管理权限、登录失败计数、主题缓存、数据库锁和 Operator 等问题。官方升级指南指出，新 DCR 策略 provider 与旧节点混用不支持滚动切换。这里的验收使用 26.8.2 新建数据。 [Keycloak 26.8.2 已解决问题](https://github.com/keycloak/keycloak/releases/tag/26.8.2) · [Keycloak 26.8.2 升级指南](https://www.keycloak.org/docs/26.8.2/upgrading/)

### SDK 基线与工程变更

- 固定上游提交 `e514445f9dcdabc5bdcf67cab56c1e49655de067`、源码归档哈希和 `linux/amd64` 镜像 digest。真实验收使用本地 `quay.io/keycloak/keycloak:26.8.2-3`，工具链为 .NET SDK `10.0.403`。 [固定基线](../../../contracts/baseline.json)
- 26.8.1 与 26.8.2 的固定 OpenAPI SHA-256 相同。升级差异记录有 **0** 个新增、删除或签名变化的 Admin 操作。SDK 仍生成 **520** 项，包含 OpenAPI 记录的 415 项及源码补充的 105 项。随版本刷新了源码位置、能力目录、测试矩阵和证据。 [源码对齐审计](../../contracts/keycloak-26.8.2-alignment-audit.md)
- 管理令牌测试覆盖默认和可选 scope，以及命名 DI 客户端的 scope 隔离。更新 FGAP、SSF 和应用协议夹具以反映 26.8.2 的管理令牌要求。Hosting 夹具从测试输出目录加载配置。本地验收可选择独立 Compose 项目、凭据和端口。升级工具会携带兼容应用协议的验证计划。矩阵测试逐项校验无证据能力的状态以及 Managed 和 Native AOT 的空列。 [测试入口](../../testing.md) · [单目标工作流](../../single-target-workflow.md)

### 验收结果与适用范围

| 验收 | Managed | Linux Native AOT `linux-musl-x64` |
| --- | ---: | ---: |
| Admin FGAP v2 稳定路线 | 478/478 | 478/478 |
| Admin FGAP v1 兼容路线 | 492/492 | 492/492 |
| 标准应用协议 | 434/434 | 391/391 |
| 兼容应用协议 | 20/20 | 20/20 |
| 26.8.2 专项 HTTP 观察 | 115 | 115 |

两种运行模式各有 520 项 Admin 业务证据，来自 v2 稳定路线、v1 专属 14 项以及独立验收的 28 项非 Stable 操作。Managed 具备 52 个应用能力族的证据，Native AOT 具备 50 个。ASP.NET Core 浏览器 OIDC 和 SAML 宿主集成的证据适用于 Managed。完整本地候选通过 740 项测试、覆盖率、严格原生包消费、两条路线各 14 项负向门禁，以及 Client Types、SSF、OID4VC VCI 六组受保护复验。 [Admin 真实验收](../../contracts/full-live-acceptance.md) · [全能力矩阵](../../contracts/platform-capability-matrix.md) · [候选清单与包哈希](9f7dc595c7ad385c6b3baa2b5caa4e895fa98cc94aef3991b16050807ea42415.json)

28 项服务端专项中，23 项通过具体本地场景。新增证据覆盖声明式 `UiPage` 的实际浏览器渲染、保存和重载，滚动更新 v1/v2 各两节点同版在线替换，以及 PostgreSQL 优化启动下的混合 OTLP。Collector 经 HTTP/protobuf 收到日志，经 gRPC 收到跟踪和指标。外置缓存与多站点、TiDB、IPA/Tuura 和合规 FIPS 仍需专用环境。 [28 项服务端观察与补齐方案](server-validation.md)

## English upgrade notes

The local candidate targets **Keycloak 26.8.2** and **.NET 10**. When moving from 26.8.1, assign `kc-admin-api` to custom management clients first. Review delegated protocol mapper writes, dynamic registration policies, and assumptions about session statistics and token lifetimes. `Keycloak.Admin.Sdk`, `Keycloak.Admin.Sdk.Protocols`, `Keycloak.Admin.Sdk.Hosting`, and `Keycloak.Admin.Sdk.Platform` all use version `26.8.2`. NuGet publication is pending.

### Admin authentication and permissions

| Change | Impact on existing callers |
| --- | --- |
| The Admin REST API checks scope and audience | Assign the built-in `kc-admin-api` client scope in the **realm that issues the token**. Keycloak derives an audience such as `https://auth.example.com/admin/realms/ops` from that realm's frontend URL. The built-in `admin-cli` and `security-admin-console` clients have the scope by default. Request optional scopes explicitly. External bearer-token providers need the same scope and audience. |
| Protocol mapper writes on clients and client scopes | Administrators with `manage-realm` can write mappers. Delegated client administrators also need the realm's mapper-type allowlist. An empty list blocks delegated writes. This affects create, update, delete, bulk operations, and mapper changes submitted in resource representations. An unchanged representation containing existing mappers passed the regression test. |
| Dynamic Client Registration (DCR) | The realm and registration-policy allowlists must both permit a mapper type. Updates can retain existing mappers. The default policies reject changes to realm default roles through `defaultRoles` and set `fullScopeAllowed` to `false` for registered clients. An update that tries to enable full scope returns `403`. Manage default roles and scope through the authorized Admin REST API. A focused regression also confirmed that a read-modify-write round trip preserves offline-token revocation on back-channel logout. |
| Internal client in FGAP v2 | Keycloak protects `admin-permissions` as an internal client. Delegated update and delete requests return `403`. Realm authorization policies remain configurable through the appropriate realm permissions. |
| Realm client session statistics | `client-session-stats` still requires realm view or management permission and filters the result by client visibility. Realm view alone can return an empty array. Under FGAP v2, fine-grained client `manage` and `view` are independent scopes. Consumers that use the result to estimate session counts should account for visibility. |

The SDK adds `ClientCredentialsTokenProviderOptions.Scope` for client-credentials requests. Set it in the `AddKeycloakAdminSdk` configuration callback for an optional scope. Include any custom token timeouts or cooldowns in the same `Token` options object. A `null` scope leaves scope selection to Keycloak's configured defaults.

```csharp
options.Token = new() { Scope = "kc-admin-api" };
```

Live Admin API checks returned `401` for a token missing the management scope, `403` for a scoped token with insufficient permissions, and `200` when scope, audience, and permissions were valid. The SDK exception's `Stage` distinguishes a failure at the token endpoint from a failure at the Admin API. [SDK authentication and errors](../../authentication-and-errors.md) · [Keycloak 26.8.2 upgrading guide](https://www.keycloak.org/docs/26.8.2/upgrading/)

### Upstream protocol and server compatibility

| Area | Behavior in 26.8.2 and upgrade checks |
| --- | --- |
| Standard token exchange | By default, exchanged access and ID tokens expire at or before the subject token's expiration. Schedule renewal or reauthentication using the returned `expires_in` and `exp`. A separate client setting governs refresh tokens. |
| CIBA | Keycloak returns `invalid_request` when reserved protocol claims appear as standalone form parameters. Rename custom fields while keeping the required JWT claims in signed request objects. |
| SAML SOAP and legacy parsing | SOAP requests have a default limit of `120000` bytes. SAML 1.1 parsing is disabled by default. Check the actual message sizes and protocol versions of SOAP clients. |
| SAML identity brokering | Upstream assertions need valid bearer subject confirmation. The broker rejects assertions with `ProxyRestriction` by default. Check the upstream IdP's assertion format and federation agreement. |
| SAML adapters and logout | The upstream Keycloak SAML adapter checks the configured IdP issuer, and generated installation files use the realm URL. Update installations that still use a placeholder IdP ID. Clients using back-channel SAML logout by `SessionIndex` must enable client signatures and sign their requests. In-flight browser logout can restart across mixed-version nodes. |
| Identity auto-linking and organization enrollment | Automatic linking requires a verified email or an IdP whose emails are trusted. Domain-based automatic organization enrollment also requires verified email. Keycloak requires local verification when an OIDC IdP explicitly returns `email_verified=false` or when a user changes their email at first login. Check the IdP verification semantics and realm SMTP. |
| CLI trust and user-storage synchronization | With a custom truststore, `kcadm` and `kcreg` require a self-signed server certificate to be imported. Periodic user-storage sync follows its configured interval again. Revisit intervals that had been tuned to compensate for the doubled schedule. |

Upstream also updates Quarkus to `3.40.1.1` and fixes issues in organization and authentication boundaries, SAML processing, delegated management, login-failure counts, theme caching, database locking, and the Operator. The upgrading guide flags the new DCR policy provider as incompatible with rolling changes across old and new nodes. The validation here uses freshly initialized 26.8.2 data. [Keycloak 26.8.2 resolved issues](https://github.com/keycloak/keycloak/releases/tag/26.8.2) · [Keycloak 26.8.2 upgrading guide](https://www.keycloak.org/docs/26.8.2/upgrading/)

### SDK baseline and engineering changes

- Pin upstream commit `e514445f9dcdabc5bdcf67cab56c1e49655de067`, the source archive hash, and the `linux/amd64` image digest. Live acceptance uses the local `quay.io/keycloak/keycloak:26.8.2-3` image and .NET SDK `10.0.403`. [Pinned baseline](../../../contracts/baseline.json)
- The pinned OpenAPI SHA-256 is the same for both versions. The upgrade diff records **zero** added, removed, or signature-changed Admin operations. The SDK generates **520** operations, including the 415 in OpenAPI and 105 additional operations found in source. Source locations, capability catalogs, test matrices, and evidence were refreshed. [Source alignment audit](../../contracts/keycloak-26.8.2-alignment-audit.md)
- Management-token tests cover default and optional scopes and scope isolation for named DI clients. FGAP, SSF, and protocol fixtures reflect 26.8.2 token requirements. Hosting fixtures load configuration from their test output. Local acceptance can select a separate Compose project, credentials, and ports. The upgrade tool includes the legacy application validation plan. The matrix test checks the status and empty Managed and Native AOT columns for each capability without evidence. [Test entry points](../../testing.md) · [Single-target workflow](../../single-target-workflow.md)

### Validation results and scope

| Validation | Managed | Linux Native AOT `linux-musl-x64` |
| --- | ---: | ---: |
| Stable FGAP v2 Admin route | 478/478 | 478/478 |
| FGAP v1 Admin compatibility route | 492/492 | 492/492 |
| Standard application protocols | 434/434 | 391/391 |
| Legacy application protocols | 20/20 | 20/20 |
| Focused 26.8.2 HTTP observations | 115 | 115 |

Each runtime has live evidence for 520 Admin operations, drawn from stable v2, 14 v1-only operations, and 28 independently verified non-Stable operations. Managed has evidence for 52 application capability families, and Native AOT for 50. The ASP.NET Core browser OIDC and SAML hosting results apply to Managed. The full local candidate passed 740 tests, coverage and strict native package consumption, 14 negative controls per FGAP route, and six guarded runs for Client Types, SSF, and OID4VC VCI. [Live Admin acceptance](../../contracts/full-live-acceptance.md) · [Platform matrix](../../contracts/platform-capability-matrix.md) · [Candidate manifest and package hashes](9f7dc595c7ad385c6b3baa2b5caa4e895fa98cc94aef3991b16050807ea42415.json)

Twenty-three of the 28 server flags passed specific local scenarios. The new evidence covers browser rendering, editing, and reloading for a declarative `UiPage` provider, live replacement of both nodes for each same-release rolling mode, and mixed OTLP with optimized PostgreSQL startup. The Collector received logs over HTTP/protobuf and traces and metrics over gRPC. External caches and multi-site operation, TiDB, IPA/Tuura, and compliant FIPS still need dedicated environments. [28 server observations and follow-up plan](server-validation.md)
