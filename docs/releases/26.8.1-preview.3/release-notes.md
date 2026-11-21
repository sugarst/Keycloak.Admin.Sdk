# Keycloak.Admin.Sdk 26.8.1-preview.3 发布说明 / Release Notes

**26.8.1-preview.3 已发布至 NuGet / Now available on NuGet.**

- 发布日期 / Release date: **2026-11-09**
- 目标服务端 / Exact server target: **Keycloak 26.8.1**
- 运行平台 / Target framework: **.NET 10**
- 开源协议 / License: **Apache-2.0**
- 项目 / Repository: [sugarst/Keycloak.Admin.Sdk](https://github.com/sugarst/Keycloak.Admin.Sdk)

## NuGet 包 / Packages

四个包采用相同版本号，可按需安装。 / All four packages share the same version and can be selected by scenario.

| NuGet | 职责 / Responsibility | Native AOT |
| --- | --- | --- |
| [Keycloak.Admin.Sdk](https://www.nuget.org/packages/Keycloak.Admin.Sdk/26.8.1-preview.3) | Admin REST API、模型、认证、DI 与支持策略 / Admin REST API, models, authentication, DI and support policies | 支持 / Supported |
| [Keycloak.Admin.Sdk.Protocols](https://www.nuget.org/packages/Keycloak.Admin.Sdk.Protocols/26.8.1-preview.3) | 应用认证、授权、账户、钱包与身份协议 / Application authentication, authorization, account, wallet and identity protocols | 按能力和 RID 验证 / Capability- and RID-specific |
| [Keycloak.Admin.Sdk.Hosting](https://www.nuget.org/packages/Keycloak.Admin.Sdk.Hosting/26.8.1-preview.3) | ASP.NET Core 登录、资源令牌、注销、MCP 元数据与 SAML SP / ASP.NET Core login, resource tokens, logout, MCP metadata and SAML SP | 仅 Managed / Managed only |
| [Keycloak.Admin.Sdk.Platform](https://www.nuget.org/packages/Keycloak.Admin.Sdk.Platform/26.8.1-preview.3) | 统一宿主开关、微软功能管理与可选遥测 / Unified host switches, Microsoft feature management and optional telemetry | 仅 Managed / Managed only |

项目引用方向如下，箭头表示“依赖”。 / Arrows indicate package dependencies.

```text
Keycloak.Admin.Sdk.Protocols ──> Keycloak.Admin.Sdk
Keycloak.Admin.Sdk.Hosting  ──> Keycloak.Admin.Sdk.Protocols
Keycloak.Admin.Sdk.Platform ──> Keycloak.Admin.Sdk.Protocols
```

Hosting 与 Platform 互不依赖，可由同一宿主组合使用。 / Hosting and Platform are independent extensions that can be composed by the same host.

## 安装 / Installation

按需选择以下命令，四包版本保持一致。 / Run the commands for the packages you need and keep their versions aligned.

```shell
dotnet add package Keycloak.Admin.Sdk --version 26.8.1-preview.3
dotnet add package Keycloak.Admin.Sdk.Protocols --version 26.8.1-preview.3
dotnet add package Keycloak.Admin.Sdk.Hosting --version 26.8.1-preview.3
dotnet add package Keycloak.Admin.Sdk.Platform --version 26.8.1-preview.3
```

## 中文发布说明

### 主要更新

1. **从管理 API 扩展到应用协议与宿主集成。** 保持 520 项生成 Admin API 契约，新增 Protocols、Hosting 和 Platform 三个职责明确的模块。管理服务账号与普通用户协议凭据分别处理，应用协议不会隐式继承管理员身份。

2. **完善应用认证与授权协议。** Protocols 提供 OIDC/OAuth、PKCE、ID Token 与访问令牌验证、刷新与注销、Device、CIBA、PAR、JAR/JARM、令牌交换、委托、JWT Grant、mTLS、DPoP、客户端断言与工作负载认证适配；扩展账户、注册、SCIM、UMA、AuthZen、Client Admin v2、OpenAPI、Docker Registry、身份代理及 SSF 等流程。

3. **补齐钱包与认证能力。** 增加 JWT VC、SD-JWT、mdoc、凭证签发证明、加密签发、Offer/二维码、预授权、刷新与撤销、OID4VP 和客户端 attestation；提供 WebAuthn、Passkey、Kerberos、恢复码、邮箱确认、临时用户及显式控制的旧版兼容入口。SDK 负责协议适配和验证，私钥、安全存储、认证器和 KDC 等基础设施仍由宿主或外部环境负责。

4. **提供 Managed Hosting 集成。** 支持 ASP.NET Core OIDC 登录、JWT 资源服务器、服务端票据、前后通道注销、MCP 保护资源元数据，以及 SAML SP 的 POST、Redirect、Artifact、ECP、签名/加密断言和单点注销。补齐 Cookie/OIDC 事件、Options 重建、注销存储、证书清理和 XML/HTTP 边界测试；独立验证 SAML 签名后规则，OIDC 认证强度检查复用已完成绑定校验的 token claims。

5. **统一功能开关，并采用微软官方可选遥测。** Platform 在同一个包中提供布尔快照和 `Microsoft.FeatureManagement` 4.8.0 适配，统一管理 66 项 Admin/协议宿主开关。Application Insights 使用官方 `Microsoft.FeatureManagement.Telemetry.ApplicationInsights` 4.8.0，移除自写 HTTP/JSON 遥测发送器，不新增独立遥测包。遥测默认关闭，需要显式注册 publisher，并为相应开关启用遥测；关闭遥测不会移除 Platform 的微软 NuGet 依赖。

6. **加强能力晋升与工程验证。** Client Types、SSF、OID4VC 共 28 项可选 Admin 操作完成 FGAP v2 的 Managed 与 Linux Native AOT 独立晋升和受保护复验。14 项 FGAP v1 专用操作继续保留 Compatibility 阶段。应用矩阵对 80 个上游功能开关和 52 个应用能力族分别记录责任边界，52/52 个能力族完成独立晋升。解决方案整理为 13 个工程，按 Unit、Integration、PackageConsumption 分组；测试与工具共享源码集中到 `tests/Shared`、`tools/Shared`，生产 NuGet 包数量保持四个。

### 从 preview.2 升级

- 将原有 `Keycloak.Admin.Sdk.FeatureManagement` 引用迁移到 `Keycloak.Admin.Sdk.Platform`，相应适配命名空间调整为 `Keycloak.Admin.Sdk.Platform`。preview.3 不再产出独立 FeatureManagement 包。
- 只调用管理 API 时可继续仅引用主包；需要应用协议时添加 Protocols；Web 宿主集成和统一开关分别选择 Hosting、Platform。
- 将原有开关配置与新的 66 项目录对齐。快照模式要求完整、已知的开关集合；开关只控制最终开放与关闭，不替代服务端配置、功能阶段许可、能力晋升或业务权限。
- Preview、Experimental、Deprecated 能力继续要求明确选择及对应服务端开关。完成验证不会把上游阶段改为 Stable，也不会自动启用这些功能。

### 支持范围

主包与 Protocols 保留 Native AOT 支持，本次实际原生发布和执行验证使用 Linux `linux-musl-x64`。Hosting、Platform 声明 Managed 支持；即使关闭 Application Insights，也不将 Platform 视为 AOT 兼容包。

本版本精确面向 Keycloak 26.8.1，仍属于 Preview，公开 API 后续可能调整。能力矩阵与覆盖率不代表穷尽所有服务端配置、权限组合、第三方 SPI 或外部基础设施。官方遥测已验证本地通道接收事件，未据此宣称 Azure 云端端到端投递已验收。

## English Release Notes

### Highlights

1. **Expand from Admin APIs to application protocols and host integration.** Retain 520 generated Admin API contracts and introduce Protocols, Hosting and Platform with distinct responsibilities. Administrative service-account credentials and end-user protocol credentials are handled separately; application protocols do not implicitly inherit administrator identity.

2. **Extend application authentication and authorization.** Protocols covers OIDC/OAuth, PKCE, ID/access token validation, refresh and logout, Device, CIBA, PAR, JAR/JARM, token exchange, delegation, JWT Grant, mTLS, DPoP, client assertions and workload authentication adapters. Additional flows include Account, registration, SCIM, UMA, AuthZen, Client Admin v2, OpenAPI, Docker Registry, identity brokering and SSF.

3. **Add wallet and authentication capabilities.** Support JWT VC, SD-JWT, mdoc, issuance proofs, encrypted issuance, offers/QR codes, pre-authorization, refresh/revocation, OID4VP and client attestation. Add WebAuthn, Passkeys, Kerberos, recovery codes, email updates, transient users and explicitly gated legacy compatibility. The SDK handles protocol adaptation and validation; hosts or external infrastructure retain responsibility for private keys, secure storage, authenticators and KDCs.

4. **Introduce Managed Hosting integration.** Provide ASP.NET Core OIDC login, JWT resource-server integration, server-side tickets, front-/back-channel logout, MCP protected-resource metadata, and SAML SP support for POST, Redirect, Artifact, ECP, signed/encrypted assertions and single logout. Extend tests for Cookie/OIDC events, options reload, logout storage, certificate cleanup and XML/HTTP bounds. Independently verify post-signature SAML checks and reuse the exact bound token claims for OIDC assurance.

5. **Unify host switches with optional Microsoft telemetry.** Platform provides snapshot and Microsoft.FeatureManagement 4.8.0 integration within one package, covering 66 Admin/protocol host switches. Application Insights uses the official Microsoft.FeatureManagement.Telemetry.ApplicationInsights 4.8.0 publisher, replacing the custom HTTP/JSON sender without adding a separate telemetry package. Telemetry is disabled by default and requires explicit publisher registration and per-flag enablement. Disabling telemetry does not remove Platform's Microsoft NuGet dependencies.

6. **Strengthen capability promotion and engineering validation.** Independently promote and revalidate all 28 optional Client Types, SSF and OID4VC Admin operations for FGAP v2 Managed and Linux Native AOT. Retain 14 FGAP v1-only operations as Compatibility. Track 80 upstream feature flags separately from 52 application capability families and their responsibility boundaries; all 52 families have independent promotion. Organize the 13-project solution into Unit, Integration and PackageConsumption groups, with shared sources in `tests/Shared` and `tools/Shared`. The number of shipping NuGet packages remains four.

### Upgrading from preview.2

- Replace `Keycloak.Admin.Sdk.FeatureManagement` with `Keycloak.Admin.Sdk.Platform` and migrate adapter namespaces to `Keycloak.Admin.Sdk.Platform`. preview.3 no longer produces the separate FeatureManagement package.
- Keep only the core package for Admin-only applications. Add Protocols for application protocols, Hosting for Web integration, and Platform for unified host switches.
- Align configuration with the 66-flag catalog. Snapshot mode requires a complete set of known flags. Host switches control final exposure and do not replace server configuration, stage opt-ins, capability promotion or business authorization.
- Preview, Experimental and Deprecated features retain explicit opt-ins and server-side requirements. Verification does not change their upstream stage to Stable or enable them automatically.

### Support boundaries

Core and Protocols retain Native AOT support, with actual native publishing and execution verified on Linux `linux-musl-x64`. Hosting and Platform are Managed-only. Turning off Application Insights does not make Platform an AOT-compatible package.

This Preview targets exactly Keycloak 26.8.1; public APIs may still change. Capability matrices and coverage results do not exhaust every server configuration, permission combination, third-party SPI or external infrastructure. Official telemetry was verified through a local channel; this does not constitute end-to-end Azure cloud delivery acceptance.

## 验证结果 / Validation results

本版本共 **728 项 MSTest 测试通过，无失败或跳过**。 / **All 728 MSTest tests passed without failures or skips.**

| 测试集 / Test suite | 通过 / Passed |
| --- | --- |
| Core | 567/567 |
| Protocols | 96/96 |
| Hosting | 35/35 |
| Platform | 5/5 |
| 工程与证据 / Engineering and evidence | 25/25 |

| 实测范围 / Verified scope | 结果 / Result |
| --- | --- |
| Core 自有源码方法、行、分支 / Core source methods, lines and branches | 100% / 100% / 100% |
| Protocols 自有源码行、分支 / Protocols source lines and branches | 100% / 100% |
| Hosting 自有源码方法、行、分支 / Hosting source methods, lines and branches | 100% / 100% / 100% |
| Platform 自有源码方法、行、分支 / Platform source methods, lines and branches | 100% / 100% / 100% |
| FGAP v2 Admin | Managed 478/478; Native AOT 478/478 |
| FGAP v1 Admin | Managed 492/492; Native AOT 492/492 |
| 标准应用协议 / Standard application protocols | Managed 434/434; Native AOT 391/391 |
| 旧版兼容协议 / Legacy compatibility | Managed 20/20; Native AOT 20/20 |
| 门禁负向控制 / Negative release-gate controls | 28/28 |
| 非 Stable 受保护复验 / Guarded non-Stable reruns | 6/6 runtime/route combinations |
| 实际包消费 / Package consumption | Managed Hosting/Platform and Linux Native AOT Core/Protocols passed |

覆盖率采用各模块报告的自有源码口径，不包含 `obj/` 生成实现或第三方库；原始 Cobertura 保留。Hosting、Platform 的源码方法、行、分支发布门槛均固定为 100%。单元覆盖率与真实服务器验收分别执行，不相互替代。

Coverage follows each module's source-code scope, excluding `obj/` generated implementations and third-party libraries; raw Cobertura data is retained. Hosting and Platform enforce 100% source method, line and branch release gates. Unit coverage and live-server acceptance are separate checks and do not substitute for each other.

## 相关文档 / Further reading

- [工程结构 / Project architecture](../../project-architecture.md)
- [功能开关 / Host feature gates](../../platform-feature-gate.md)
- [Application Insights](../../platform-application-insights.md)
- [认证接入 / Authentication integration](../../authentication-integration.md)
- [钱包接入 / Wallet integration](../../wallet-integration.md)
- [测试与门禁 / Testing and gates](../../testing.md)
- [真实 Admin 验收 / Live Admin acceptance](../../contracts/full-live-acceptance.md)
- [发布验收候选 / Release acceptance candidate](08658c88f857619ff947e05dcc5d5ff4d278aaf4bce3cf4bc16d02a4be56728f.json)

维护者已确认手动上传，四个公开版本已通过 NuGet 官方注册元数据核对；候选记录中的 `local-candidate` / `published=false` 保留验收时的历史状态。

The maintainer confirmed manual publication, and all four public versions were checked against NuGet's official registration metadata. The candidate's `local-candidate` / `published=false` fields retain their historical acceptance-time meaning.
