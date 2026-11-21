# Keycloak.Admin.Sdk 26.8.1

## 中文

这是面向 **Keycloak 26.8.1** 的正式版，目标框架为 **.NET 10**。四个包统一使用 `26.8.1`。

- `Keycloak.Admin.Sdk` 提供管理 API 客户端，覆盖固定版本的 520 项管理操作。
- `Keycloak.Admin.Sdk.Protocols` 提供 OIDC、令牌交换、SCIM、UMA、钱包等应用协议客户端。
- `Keycloak.Admin.Sdk.Hosting` 提供 ASP.NET Core OIDC、JWT、SAML 和注销集成。
- `Keycloak.Admin.Sdk.Platform` 提供能力策略、宿主功能开关和可选的 Application Insights 遥测。

从 `26.8.1-preview.3` 升级时，请将项目中使用的 SDK 包统一升级至 `26.8.1`。本版通过 `System.Security.Cryptography.Cose` `10.0.15` 传递解析 `System.Formats.Cbor` `10.0.15`，修复 CBOR 拒绝服务漏洞 `CVE-2026-118747`。ASP.NET Core 认证、HTTP 和加密依赖也更新至 `10.0.15`，`ITfoxtec.Identity.Saml2` 更新至 `4.21.1`。[微软安全公告](https://github.com/dotnet/runtime/security/advisories/GHSA-vmv3-wvjp-wqpj)

主包和 Protocols 已验证 `linux-musl-x64` Native AOT，Hosting 和 Platform 面向托管运行时。FGAP v1 继续作为兼容路线，服务端的 Preview 和 Experimental 功能仍需按能力显式启用。

## English

This stable release targets **Keycloak 26.8.1** and **.NET 10**. All four packages use version `26.8.1`.

- `Keycloak.Admin.Sdk` provides the Admin API client for all 520 operations in the pinned release.
- `Keycloak.Admin.Sdk.Protocols` provides application protocol clients for OIDC, token exchange, SCIM, UMA, and wallet flows.
- `Keycloak.Admin.Sdk.Hosting` provides ASP.NET Core integration for OIDC, JWT, SAML, and logout.
- `Keycloak.Admin.Sdk.Platform` provides capability policies, host feature switches, and optional Application Insights telemetry.

When upgrading from `26.8.1-preview.3`, move all SDK packages used by your application to `26.8.1` together. This release resolves `System.Formats.Cbor` `10.0.15` through `System.Security.Cryptography.Cose` `10.0.15` to address the CBOR denial-of-service vulnerability `CVE-2026-118747`. It also updates ASP.NET Core authentication, HTTP, and cryptography dependencies to `10.0.15`, and `ITfoxtec.Identity.Saml2` to `4.21.1`. [Microsoft security advisory](https://github.com/dotnet/runtime/security/advisories/GHSA-vmv3-wvjp-wqpj)

The core and Protocols packages were validated with Native AOT on `linux-musl-x64`. Hosting and Platform target managed runtimes. FGAP v1 remains available as a compatibility route. Server Preview and Experimental features require explicit opt-in for each capability.

## NuGet

以下链接在维护者上传并完成 NuGet.org 索引后可用。 The links below become available after the maintainer uploads the packages and NuGet.org indexes them.

- [Keycloak.Admin.Sdk](https://www.nuget.org/packages/Keycloak.Admin.Sdk/26.8.1)
- [Keycloak.Admin.Sdk.Protocols](https://www.nuget.org/packages/Keycloak.Admin.Sdk.Protocols/26.8.1)
- [Keycloak.Admin.Sdk.Hosting](https://www.nuget.org/packages/Keycloak.Admin.Sdk.Hosting/26.8.1)
- [Keycloak.Admin.Sdk.Platform](https://www.nuget.org/packages/Keycloak.Admin.Sdk.Platform/26.8.1)

## 验收 / Validation

740 项测试和 5 项 GitHub CI 任务全部通过。正式候选通过托管与 Linux Native AOT 包消费、两条 FGAP 路线和 52 个应用能力族的验收。All 740 tests and five GitHub CI jobs passed. The candidate passed managed and Linux Native AOT package consumption, both FGAP routes, and acceptance for 52 application capability families.

[GitHub CI](https://github.com/sugarst/Keycloak.Admin.Sdk/actions/runs/43170855393) · [候选清单及包 SHA-256 / Candidate manifest and package SHA-256](https://github.com/sugarst/Keycloak.Admin.Sdk/blob/v26.8.1/docs/releases/26.8.1/00a525ca47d4cb14cd4bab44c39618cc88c437b921e1a5459050c393a6743d9c.json)
