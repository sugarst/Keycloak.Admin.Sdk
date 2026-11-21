# Keycloak 全能力覆盖矩阵 / Platform capability coverage

固定目标 / Exact target: Keycloak 26.8.2, upstream `e514445f9dcdabc5bdcf67cab56c1e49655de067`.

本表登记上游功能及责任边界。应用协议和 HostIntegration 的支持范围按下表的运行模式、服务端配置和验收证据确定。ServerRuntime 和 ServerExtension 由 Keycloak 或外部工具承担。用户自定义 SPI 需要独立契约。

Admin API 的 520 项操作独立维护于 [操作支持矩阵](admin-api-support-matrix.tsv)。下表的上游功能数不能与操作数相加。

## 上游功能 / Upstream features

| Feature | Upstream stage | Deprecated | Responsibility |
| --- | --- | --- | --- |
| `ACCOUNT_API` | Stable | false | SdkProtocol |
| `ACCOUNT_V3` | Stable | false | ServerExtension |
| `ADMIN_API` | Stable | false | SdkAdmin |
| `ADMIN_FINE_GRAINED_AUTHZ` | Deprecated | true | SdkAdmin |
| `ADMIN_FINE_GRAINED_AUTHZ_V2` | Stable | false | SdkAdmin |
| `ADMIN_V2` | Stable | false | ServerExtension |
| `AUTHORIZATION` | Stable | false | SdkProtocol |
| `AUTHZEN` | Experimental | false | SdkProtocol |
| `CIBA` | Stable | false | SdkProtocol |
| `CIMD` | Experimental | false | SdkProtocol |
| `CLIENT_ADMIN_API_V2` | Preview | false | SdkProtocol |
| `CLIENT_AUTH_ABCA` | Experimental | false | HostIntegration |
| `CLIENT_AUTH_FEDERATED` | Stable | false | HostIntegration |
| `CLIENT_POLICIES` | Stable | false | SdkAdmin |
| `CLIENT_SECRET_ROTATION` | Stable | false | SdkAdmin |
| `CLIENT_TYPES` | Experimental | false | SdkAdmin |
| `CLUSTERLESS` | Experimental | false | ServerRuntime |
| `DB_TIDB` | Experimental | false | ServerRuntime |
| `DECLARATIVE_UI` | Experimental | false | ServerExtension |
| `DEVICE_FLOW` | Stable | false | SdkProtocol |
| `DOCKER` | Stable | false | SdkProtocol |
| `DPOP` | Stable | false | SdkProtocol |
| `FIPS` | Stable | false | ServerRuntime |
| `HOSTNAME_V2` | Stable | false | ServerRuntime |
| `HTTP_CLIENT` | Stable | false | ServerRuntime |
| `HTTP_CLIENT_V2` | Experimental | false | ServerRuntime |
| `HTTP_OPTIMIZED_SERIALIZERS` | Preview | false | ServerRuntime |
| `IDENTITY_ASSERTION_JWT` | Experimental | false | SdkProtocol |
| `IDENTITY_BROKERING_API_V1` | Stable | true | SdkProtocol |
| `IDENTITY_BROKERING_API_V2` | Stable | false | SdkProtocol |
| `IMPERSONATION` | Stable | false | SdkAdmin |
| `INSTAGRAM_BROKER` | Deprecated | true | HostIntegration |
| `IPA_TUURA_FEDERATION` | Experimental | false | ServerExtension |
| `JWT_AUTHORIZATION_GRANT` | Stable | false | SdkProtocol |
| `KERBEROS` | Stable | false | HostIntegration |
| `KUBERNETES_SERVICE_ACCOUNTS` | Stable | false | HostIntegration |
| `LDAP_METRICS` | Experimental | false | ServerRuntime |
| `LOGIN_FAILURES_V1` | Deprecated | true | ServerRuntime |
| `LOGIN_FAILURES_V2` | Stable | false | ServerRuntime |
| `LOGIN_V1` | Deprecated | true | ServerExtension |
| `LOGIN_V2` | Stable | false | ServerExtension |
| `LOGOUT_ALL_SESSIONS_V1` | Deprecated | true | HostIntegration |
| `LOG_MDC` | Stable | false | ServerRuntime |
| `MULTI_SITE` | Deprecated | true | ServerRuntime |
| `OID4VC_MDOC` | Experimental | false | SdkProtocol |
| `OID4VC_VCI` | Preview | false | SdkProtocol |
| `OID4VC_VCI_PREAUTH_CODE` | Experimental | false | SdkProtocol |
| `OID4VC_VCI_REST_CREDENTIAL_OFFER` | Experimental | false | SdkProtocol |
| `OID4VC_VP` | Experimental | false | SdkProtocol |
| `OPENAPI` | Experimental | false | ServerRuntime |
| `OPENTELEMETRY` | Stable | false | ServerRuntime |
| `OPENTELEMETRY_LOGS` | Preview | false | ServerRuntime |
| `OPENTELEMETRY_METRICS` | Experimental | false | ServerRuntime |
| `ORGANIZATION` | Stable | false | SdkAdmin |
| `PAR` | Stable | false | SdkProtocol |
| `PARAMETERIZED_SCOPES` | Preview | false | SdkProtocol |
| `PASSKEYS` | Stable | false | HostIntegration |
| `PASSKEYS_CONDITIONAL_UI_AUTHENTICATOR` | Deprecated | true | HostIntegration |
| `PERSISTENT_USER_SESSIONS` | Stable | false | ServerRuntime |
| `QUICK_THEME` | Experimental | false | ServerExtension |
| `RECOVERY_CODES` | Stable | false | HostIntegration |
| `RESOURCE_INDICATORS` | Experimental | false | SdkProtocol |
| `ROLLING_UPDATES_V1` | Deprecated | true | ServerRuntime |
| `ROLLING_UPDATES_V2` | Stable | false | ServerRuntime |
| `SCIM_API` | Stable | false | SdkProtocol |
| `SCRIPTS` | Preview | false | ServerExtension |
| `SPIFFE` | Preview | false | HostIntegration |
| `SSF` | Experimental | false | SdkProtocol |
| `STATELESS` | Stable | false | ServerRuntime |
| `STEP_UP_AUTHENTICATION` | Stable | false | HostIntegration |
| `STEP_UP_AUTHENTICATION_SAML` | Stable | false | HostIntegration |
| `TOKEN_EXCHANGE` | Preview | true | SdkProtocol |
| `TOKEN_EXCHANGE_DELEGATION` | Preview | false | SdkProtocol |
| `TOKEN_EXCHANGE_STANDARD_V2` | Stable | false | SdkProtocol |
| `TRANSIENT_USERS` | Experimental | false | HostIntegration |
| `TWITTER_BROKER` | Stable | true | HostIntegration |
| `UPDATE_EMAIL` | Stable | false | HostIntegration |
| `USER_EVENT_METRICS` | Stable | false | ServerRuntime |
| `WEB_AUTHN` | Stable | false | HostIntegration |
| `WORKFLOWS` | Stable | false | SdkAdmin |

## 应用协议与运行时 / Application protocols and runtime

运行时列给出通过验收的服务端配置。Native AOT 同时标明 RID。`—` 表示该运行模式暂无通过的证据。

| Capability | Responsibility | Implementation | Managed | Native AOT |
| --- | --- | --- | --- | --- |
| `oidc` | SdkProtocol | Implemented | standard | standard (linux-musl-x64) |
| `oidc-standard-exchange` | SdkProtocol | Implemented | standard | standard (linux-musl-x64) |
| `oidc-legacy-exchange` | SdkProtocol | Implemented | legacy | legacy (linux-musl-x64) |
| `oidc-delegation` | SdkProtocol | Implemented | standard | standard (linux-musl-x64) |
| `oidc-jwt-grant` | SdkProtocol | Implemented | standard | standard (linux-musl-x64) |
| `oidc-device` | SdkProtocol | Implemented | standard | standard (linux-musl-x64) |
| `oidc-ciba` | SdkProtocol | Implemented | standard | standard (linux-musl-x64) |
| `oidc-par` | SdkProtocol | Implemented | standard | standard (linux-musl-x64) |
| `oidc-parameterized-scopes` | SdkProtocol | Implemented | standard | standard (linux-musl-x64) |
| `oidc-resources` | SdkProtocol | Implemented | standard | standard (linux-musl-x64) |
| `oidc-identity-assertion` | SdkProtocol | Implemented | standard | standard (linux-musl-x64) |
| `oidc-client-metadata` | SdkProtocol | Implemented | standard | standard (linux-musl-x64) |
| `account` | SdkProtocol | Implemented | standard | standard (linux-musl-x64) |
| `scim` | SdkProtocol | Implemented | standard | standard (linux-musl-x64) |
| `registration` | SdkProtocol | Implemented | standard | standard (linux-musl-x64) |
| `uma` | SdkProtocol | Implemented | standard | standard (linux-musl-x64) |
| `authzen` | SdkProtocol | Implemented | standard | standard (linux-musl-x64) |
| `client-admin-v2` | SdkProtocol | Implemented | standard | standard (linux-musl-x64) |
| `identity-brokering-legacy` | SdkProtocol | Implemented | legacy | legacy (linux-musl-x64) |
| `identity-brokering` | SdkProtocol | Implemented | standard | standard (linux-musl-x64) |
| `wallet` | SdkProtocol | Implemented | standard | standard (linux-musl-x64) |
| `wallet-pre-authorized` | SdkProtocol | Implemented | standard | standard (linux-musl-x64) |
| `wallet-offers` | SdkProtocol | Implemented | standard | standard (linux-musl-x64) |
| `wallet-mdoc` | SdkProtocol | Implemented | standard | standard (linux-musl-x64) |
| `wallet-presentation` | SdkProtocol | Implemented | standard | standard (linux-musl-x64) |
| `wallet-attestation` | HostIntegration | Implemented | standard | standard (linux-musl-x64) |
| `signals` | SdkProtocol | Implemented | standard | standard (linux-musl-x64) |
| `docker-registry` | SdkProtocol | Implemented | standard | standard (linux-musl-x64) |
| `browser-oidc` | HostIntegration | Implemented | standard | — |
| `saml` | HostIntegration | Implemented | standard | — |
| `dpop` | HostIntegration | Implemented | standard | standard (linux-musl-x64) |
| `authentication` | HostIntegration | Implemented | standard | standard (linux-musl-x64) |
| `federated-client-auth` | HostIntegration | Implemented | standard | standard (linux-musl-x64) |
| `runtime-openapi` | SdkProtocol | Implemented | standard | standard (linux-musl-x64) |
| `mutual-tls` | HostIntegration | Implemented | standard | standard (linux-musl-x64) |
| `spiffe-client-auth` | HostIntegration | Implemented | standard | standard (linux-musl-x64) |
| `identity-broker-login` | HostIntegration | Implemented | standard | standard (linux-musl-x64) |
| `identity-linking` | HostIntegration | Implemented | standard | standard (linux-musl-x64) |
| `oidc-request-objects` | SdkProtocol | Implemented | standard | standard (linux-musl-x64) |
| `oidc-signed-responses` | SdkProtocol | Implemented | standard | standard (linux-musl-x64) |
| `oidc-browser-compatibility` | SdkProtocol | Implemented | standard | standard (linux-musl-x64) |
| `oidc-assurance` | SdkProtocol | Implemented | standard | standard (linux-musl-x64) |
| `authentication-webauthn` | HostIntegration | Implemented | standard | standard (linux-musl-x64) |
| `authentication-passkeys` | HostIntegration | Implemented | standard | standard (linux-musl-x64) |
| `authentication-kerberos` | HostIntegration | Implemented | standard | standard (linux-musl-x64) |
| `authentication-recovery-codes` | HostIntegration | Implemented | standard | standard (linux-musl-x64) |
| `authentication-update-email` | HostIntegration | Implemented | standard | standard (linux-musl-x64) |
| `authentication-transient-users` | HostIntegration | Implemented | standard | standard (linux-musl-x64) |
| `authentication-legacy-logout` | HostIntegration | Implemented | standard | standard (linux-musl-x64) |
| `authentication-legacy-passkey-ui` | HostIntegration | Implemented | standard | standard (linux-musl-x64) |
| `authentication-instagram` | HostIntegration | Implemented | standard | standard (linux-musl-x64) |
| `authentication-twitter` | HostIntegration | Implemented | standard | standard (linux-musl-x64) |

按通过验收的配置统计，Managed 覆盖 52/52 个应用能力族，Native AOT 覆盖 50/52 个。


`Partial` 表示仅有部分调用实现；不表示完整协议支持，也不继承 Admin API 的验收。晋升引用绑定输入指纹、运行模式、RID 和不可变业务证据；修改代码后旧证据自动退出当前支持。

全部审阅应用能力和 Admin API 已有支持配置。每个应用能力至少有一种运行模式通过验收。发布仍须通过完整契约、原生构建和真实验收门禁。

