# Keycloak 全能力覆盖矩阵 / Platform capability coverage

固定目标 / Exact target: Keycloak 26.8.1, upstream `24ed1dadf3f246a555adb6d3d4a99e9b3003fb3b`.

本表登记上游功能及责任边界，不把登记、生成或 HTTP 可调用视为完成支持。HostIntegration 仍属于应用全覆盖待完成项；ServerRuntime 和 ServerExtension 明确由服务端或外部工具承担。用户自定义 SPI 不属于有限上游清单。

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

| Capability | Responsibility | Implementation | Verified runtime profiles |
| --- | --- | --- | --- |
| `oidc` | SdkProtocol | Implemented | 2; verified for referenced profiles only |
| `oidc-standard-exchange` | SdkProtocol | Implemented | 2; verified for referenced profiles only |
| `oidc-legacy-exchange` | SdkProtocol | Implemented | 2; verified for referenced profiles only |
| `oidc-delegation` | SdkProtocol | Implemented | 2; verified for referenced profiles only |
| `oidc-jwt-grant` | SdkProtocol | Implemented | 2; verified for referenced profiles only |
| `oidc-device` | SdkProtocol | Implemented | 2; verified for referenced profiles only |
| `oidc-ciba` | SdkProtocol | Implemented | 2; verified for referenced profiles only |
| `oidc-par` | SdkProtocol | Implemented | 2; verified for referenced profiles only |
| `oidc-parameterized-scopes` | SdkProtocol | Implemented | 2; verified for referenced profiles only |
| `oidc-resources` | SdkProtocol | Implemented | 2; verified for referenced profiles only |
| `oidc-identity-assertion` | SdkProtocol | Implemented | 2; verified for referenced profiles only |
| `oidc-client-metadata` | SdkProtocol | Implemented | 2; verified for referenced profiles only |
| `account` | SdkProtocol | Implemented | 2; verified for referenced profiles only |
| `scim` | SdkProtocol | Implemented | 2; verified for referenced profiles only |
| `registration` | SdkProtocol | Implemented | 2; verified for referenced profiles only |
| `uma` | SdkProtocol | Implemented | 2; verified for referenced profiles only |
| `authzen` | SdkProtocol | Implemented | 2; verified for referenced profiles only |
| `client-admin-v2` | SdkProtocol | Implemented | 2; verified for referenced profiles only |
| `identity-brokering-legacy` | SdkProtocol | Implemented | 2; verified for referenced profiles only |
| `identity-brokering` | SdkProtocol | Implemented | 2; verified for referenced profiles only |
| `wallet` | SdkProtocol | Implemented | 2; verified for referenced profiles only |
| `wallet-pre-authorized` | SdkProtocol | Implemented | 2; verified for referenced profiles only |
| `wallet-offers` | SdkProtocol | Implemented | 2; verified for referenced profiles only |
| `wallet-mdoc` | SdkProtocol | Implemented | 2; verified for referenced profiles only |
| `wallet-presentation` | SdkProtocol | Implemented | 2; verified for referenced profiles only |
| `wallet-attestation` | HostIntegration | Implemented | 2; verified for referenced profiles only |
| `signals` | SdkProtocol | Implemented | 2; verified for referenced profiles only |
| `docker-registry` | SdkProtocol | Implemented | 2; verified for referenced profiles only |
| `browser-oidc` | HostIntegration | Implemented | 1; verified for referenced profiles only |
| `saml` | HostIntegration | Implemented | 1; verified for referenced profiles only |
| `dpop` | HostIntegration | Implemented | 2; verified for referenced profiles only |
| `authentication` | HostIntegration | Implemented | 2; verified for referenced profiles only |
| `federated-client-auth` | HostIntegration | Implemented | 2; verified for referenced profiles only |
| `runtime-openapi` | SdkProtocol | Implemented | 2; verified for referenced profiles only |
| `mutual-tls` | HostIntegration | Implemented | 2; verified for referenced profiles only |
| `spiffe-client-auth` | HostIntegration | Implemented | 2; verified for referenced profiles only |
| `identity-broker-login` | HostIntegration | Implemented | 2; verified for referenced profiles only |
| `identity-linking` | HostIntegration | Implemented | 2; verified for referenced profiles only |
| `oidc-request-objects` | SdkProtocol | Implemented | 2; verified for referenced profiles only |
| `oidc-signed-responses` | SdkProtocol | Implemented | 2; verified for referenced profiles only |
| `oidc-browser-compatibility` | SdkProtocol | Implemented | 2; verified for referenced profiles only |
| `oidc-assurance` | SdkProtocol | Implemented | 2; verified for referenced profiles only |
| `authentication-webauthn` | HostIntegration | Implemented | 2; verified for referenced profiles only |
| `authentication-passkeys` | HostIntegration | Implemented | 2; verified for referenced profiles only |
| `authentication-kerberos` | HostIntegration | Implemented | 2; verified for referenced profiles only |
| `authentication-recovery-codes` | HostIntegration | Implemented | 2; verified for referenced profiles only |
| `authentication-update-email` | HostIntegration | Implemented | 2; verified for referenced profiles only |
| `authentication-transient-users` | HostIntegration | Implemented | 2; verified for referenced profiles only |
| `authentication-legacy-logout` | HostIntegration | Implemented | 2; verified for referenced profiles only |
| `authentication-legacy-passkey-ui` | HostIntegration | Implemented | 2; verified for referenced profiles only |
| `authentication-instagram` | HostIntegration | Implemented | 2; verified for referenced profiles only |
| `authentication-twitter` | HostIntegration | Implemented | 2; verified for referenced profiles only |

`Partial` 表示仅有部分调用实现；不表示完整协议支持，也不继承 Admin API 的验收。晋升引用绑定输入指纹、运行模式、RID 和不可变业务证据；修改代码后旧证据自动退出当前支持。

全部审阅应用能力和 Admin API 已有支持配置。发布仍须通过完整契约、原生构建和真实验收门禁。

