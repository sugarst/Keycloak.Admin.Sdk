# Keycloak 26.8.1 已落地接口与验证清单

计数单位：HTTP 方法 + 路径模板，共 520 项（官方 OpenAPI 415 项、发布源码补充 105 项）。每项均有 SDK 方法和独立契约单测。

本表整理已有验收证据，不代表本次重新执行全部容器测试。真实验收环境为 Keycloak 26.8.1 + PostgreSQL 18.0，.NET SDK 10.0.403，Native AOT 目标 linux-musl-x64。

| 路线 | 托管已验证 | AOT 已验证 | 未完成 | 政策排除 |
| --- | --- | --- | --- | --- |
| v2 正式（默认） | 478 | 478 | 0 | 42 |
| v1 兼容（显式启用） | 492 | 492 | 0 | 28 |

两条路线的已验证集合有重叠：合计 492 个不同接口已有真实业务验证；28 个接口没有真实容器验收。v2 的 42 项排除 = 28 项预览/实验 + 14 项仅供 v1 兼容的接口。排除不能记为通过。

## 实跑时间（北京时间）

- `fgap-v2-stable` / `managed`：2026-11-05 12:06:48（UTC+08:00）
- `fgap-v2-stable` / `native-aot`：2026-11-05 12:07:12（UTC+08:00）
- `fgap-v1-compat` / `managed`：2026-11-05 12:05:05（UTC+08:00）
- `fgap-v1-compat` / `native-aot`：2026-11-05 12:06:00（UTC+08:00）

## 没有真实容器验收的 28 项

下表项目保留 wire 方法及契约单测；未开启对应预览/实验功能，也未记为业务验收成功。路径均相对于 `/admin/realms/{realm}`。

| 方法 | 路径 | 未验证原因 |
| --- | --- | --- |
| GET | `/client-types` | Client Types：26.8.1 为 EXPERIMENTAL，按要求不做真实验收 |
| PUT | `/client-types` | Client Types：26.8.1 为 EXPERIMENTAL，按要求不做真实验收 |
| DELETE | `/ssf/clients/{clientId}/events` | SSF：26.8.1 为 EXPERIMENTAL，按要求不做真实验收 |
| POST | `/ssf/clients/{clientId}/events/emit` | SSF：26.8.1 为 EXPERIMENTAL，按要求不做真实验收 |
| DELETE | `/ssf/clients/{clientId}/events/queued` | SSF：26.8.1 为 EXPERIMENTAL，按要求不做真实验收 |
| GET | `/ssf/clients/{clientId}/events/stats` | SSF：26.8.1 为 EXPERIMENTAL，按要求不做真实验收 |
| GET | `/ssf/clients/{clientId}/pending-events/{jti}` | SSF：26.8.1 为 EXPERIMENTAL，按要求不做真实验收 |
| DELETE | `/ssf/clients/{clientId}/stream` | SSF：26.8.1 为 EXPERIMENTAL，按要求不做真实验收 |
| GET | `/ssf/clients/{clientId}/stream` | SSF：26.8.1 为 EXPERIMENTAL，按要求不做真实验收 |
| PATCH | `/ssf/clients/{clientId}/stream` | SSF：26.8.1 为 EXPERIMENTAL，按要求不做真实验收 |
| POST | `/ssf/clients/{clientId}/stream` | SSF：26.8.1 为 EXPERIMENTAL，按要求不做真实验收 |
| POST | `/ssf/clients/{clientId}/stream/status` | SSF：26.8.1 为 EXPERIMENTAL，按要求不做真实验收 |
| POST | `/ssf/clients/{clientId}/stream/verify` | SSF：26.8.1 为 EXPERIMENTAL，按要求不做真实验收 |
| POST | `/ssf/clients/{clientId}/subjects/add` | SSF：26.8.1 为 EXPERIMENTAL，按要求不做真实验收 |
| POST | `/ssf/clients/{clientId}/subjects/check` | SSF：26.8.1 为 EXPERIMENTAL，按要求不做真实验收 |
| POST | `/ssf/clients/{clientId}/subjects/ignore` | SSF：26.8.1 为 EXPERIMENTAL，按要求不做真实验收 |
| POST | `/ssf/clients/{clientId}/subjects/remove` | SSF：26.8.1 为 EXPERIMENTAL，按要求不做真实验收 |
| GET | `/ssf/config` | SSF：26.8.1 为 EXPERIMENTAL，按要求不做真实验收 |
| DELETE | `/ssf/events` | SSF：26.8.1 为 EXPERIMENTAL，按要求不做真实验收 |
| DELETE | `/ssf/events/queued` | SSF：26.8.1 为 EXPERIMENTAL，按要求不做真实验收 |
| GET | `/ssf/events/stats` | SSF：26.8.1 为 EXPERIMENTAL，按要求不做真实验收 |
| GET | `/users/{user-id}/vc/credentials` | OID4VC：26.8.1 为 PREVIEW，按要求不做真实验收 |
| POST | `/users/{user-id}/vc/credentials` | OID4VC：26.8.1 为 PREVIEW，按要求不做真实验收 |
| PUT | `/users/{user-id}/vc/credentials/send-credential-offer` | OID4VC：26.8.1 为 PREVIEW，按要求不做真实验收 |
| DELETE | `/users/{user-id}/vc/credentials/{credentialScopeName}` | OID4VC：26.8.1 为 PREVIEW，按要求不做真实验收 |
| PUT | `/users/{user-id}/vc/credentials/{credentialScopeName}` | OID4VC：26.8.1 为 PREVIEW，按要求不做真实验收 |
| GET | `/users/{user-id}/vc/issued-credentials` | OID4VC：26.8.1 为 PREVIEW，按要求不做真实验收 |
| DELETE | `/users/{user-id}/vc/issued-credentials/{id}` | OID4VC：26.8.1 为 PREVIEW，按要求不做真实验收 |

## 仅在 v1 兼容路线验证的 14 项

这些接口已通过托管/AOT 实跑，v2 正式路线不调用旧版管理权限接口。

| 方法 | 路径（相对 realm） | v1 托管 | v1 AOT |
| --- | --- | --- | --- |
| GET | `/clients/{client-uuid}/management/permissions` | 通过 200 | 通过 200 |
| PUT | `/clients/{client-uuid}/management/permissions` | 通过 200 | 通过 200 |
| GET | `/clients/{client-uuid}/roles/{role-name}/management/permissions` | 通过 200 | 通过 200 |
| PUT | `/clients/{client-uuid}/roles/{role-name}/management/permissions` | 通过 200 | 通过 200 |
| GET | `/groups/{group-id}/management/permissions` | 通过 200 | 通过 200 |
| PUT | `/groups/{group-id}/management/permissions` | 通过 200 | 通过 200 |
| GET | `/identity-provider/instances/{alias}/management/permissions` | 通过 200 | 通过 200 |
| PUT | `/identity-provider/instances/{alias}/management/permissions` | 通过 200 | 通过 200 |
| GET | `/roles-by-id/{role-id}/management/permissions` | 通过 200 | 通过 200 |
| PUT | `/roles-by-id/{role-id}/management/permissions` | 通过 200 | 通过 200 |
| GET | `/roles/{role-name}/management/permissions` | 通过 200 | 通过 200 |
| PUT | `/roles/{role-name}/management/permissions` | 通过 200 | 通过 200 |
| GET | `/users-management-permissions` | 通过 200 | 通过 200 |
| PUT | `/users-management-permissions` | 通过 200 | 通过 200 |

## 全部 520 项逐接口明细

按 SDK 资源入口分组。通过代表该方法/路径至少一个真实业务场景通过，包含写入后的持久化或协议效果断言、读取已知真实数据等；不代表穷尽该接口的所有参数、权限组合、策略类型和第三方 SPI 行为。业务证明保留测试中的原文。

### AttackDetection（3 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| DELETE | `/admin/realms/{realm}/attack-detection/brute-force/users` | `AttackDetection.ClearAllBruteForceAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Clearing realm attacks resets newly recorded failures |
| DELETE | `/admin/realms/{realm}/attack-detection/brute-force/users/{userId}` | `AttackDetection.ClearBruteForceForUserAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Clearing selected user's attacks resets recorded failures |
| GET | `/admin/realms/{realm}/attack-detection/brute-force/users/{userId}` | `AttackDetection.BruteForceUserStatusAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Clearing realm attacks resets newly recorded failures |

### AuthenticationManagement（39 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GET | `/admin/realms/{realm}/authentication/authenticator-providers` | `AuthenticationManagement.GetAuthenticatorProvidersAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Discovery contains installed executable authentication provider: auth-cookie |
| GET | `/admin/realms/{realm}/authentication/client-authenticator-providers` | `AuthenticationManagement.GetClientAuthenticatorProvidersAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Discovery contains installed executable authentication provider: client-secret |
| POST | `/admin/realms/{realm}/authentication/config` | `AuthenticationManagement.CreateAuthenticatorConfigAsync` | 通过 201 | 通过 201 | 通过 201 | 通过 201 | Standalone authenticator config persists settings |
| GET | `/admin/realms/{realm}/authentication/config-description/{providerId}` | `AuthenticationManagement.GetAuthenticatorConfigDescriptionAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Provider configuration description exposes supported defaultProvider option |
| DELETE | `/admin/realms/{realm}/authentication/config/{id}` | `AuthenticationManagement.RemoveAuthenticatorConfigAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Authenticator configuration deletion removes stored object |
| GET | `/admin/realms/{realm}/authentication/config/{id}` | `AuthenticationManagement.GetAuthenticatorConfigAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Authenticator configuration update persists changed value |
| PUT | `/admin/realms/{realm}/authentication/config/{id}` | `AuthenticationManagement.UpdateAuthenticatorConfigAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Authenticator configuration update persists changed value |
| POST | `/admin/realms/{realm}/authentication/executions` | `AuthenticationManagement.AddExecutionAsync` | 通过 201 | 通过 201 | 通过 201 | 通过 201 | Both execution creation endpoints persist provider and parent flow |
| DELETE | `/admin/realms/{realm}/authentication/executions/{executionId}` | `AuthenticationManagement.RemoveExecutionAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Execution deletion removes graph node |
| GET | `/admin/realms/{realm}/authentication/executions/{executionId}` | `AuthenticationManagement.GetExecutionAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Execution configuration creates stored settings and a real execution link |
| POST | `/admin/realms/{realm}/authentication/executions/{executionId}/config` | `AuthenticationManagement.NewExecutionConfigAsync` | 通过 201 | 通过 201 | 通过 201 | 通过 201 | Execution configuration creates stored settings and a real execution link |
| GET | `/admin/realms/{realm}/authentication/executions/{executionId}/config/{id}` | `AuthenticationManagement.GetAuthenticatorConfigGETAdminRealmsRealmAuthenticationExecutionsExecutionIdConfigIdAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Execution configuration creates stored settings and a real execution link |
| POST | `/admin/realms/{realm}/authentication/executions/{executionId}/lower-priority` | `AuthenticationManagement.LowerPriorityAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Lower execution priority changes persisted ordering |
| POST | `/admin/realms/{realm}/authentication/executions/{executionId}/raise-priority` | `AuthenticationManagement.RaisePriorityAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Raise execution priority changes persisted ordering |
| GET | `/admin/realms/{realm}/authentication/flows` | `AuthenticationManagement.GetFlowsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Authentication flow update persists and appears in realm flow list |
| POST | `/admin/realms/{realm}/authentication/flows` | `AuthenticationManagement.CreateFlowAsync` | 通过 201 | 通过 201 | 通过 201 | 通过 201 | Authentication flow creation persists alias and generated ID |
| POST | `/admin/realms/{realm}/authentication/flows/{flowAlias}/copy` | `AuthenticationManagement.CopyAsync` | 通过 201 | 通过 201 | 通过 201 | 通过 201 | Flow copy duplicates the complete execution graph |
| GET | `/admin/realms/{realm}/authentication/flows/{flowAlias}/executions` | `AuthenticationManagement.GetExecutionsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Execution deletion removes graph node |
| PUT | `/admin/realms/{realm}/authentication/flows/{flowAlias}/executions` | `AuthenticationManagement.UpdateExecutionsAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Execution requirement update persists in flow graph |
| POST | `/admin/realms/{realm}/authentication/flows/{flowAlias}/executions/execution` | `AuthenticationManagement.AddExecutionToFlowAsync` | 通过 201 | 通过 201 | 通过 201 | 通过 201 | Both execution creation endpoints persist provider and parent flow |
| POST | `/admin/realms/{realm}/authentication/flows/{flowAlias}/executions/flow` | `AuthenticationManagement.AddExecutionFlowAsync` | 通过 201 | 通过 201 | 通过 201 | 通过 201 | Nested flow endpoint creates flow and linking execution |
| DELETE | `/admin/realms/{realm}/authentication/flows/{id}` | `AuthenticationManagement.DeleteFlowAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Authentication flow deletion removes its graph |
| GET | `/admin/realms/{realm}/authentication/flows/{id}` | `AuthenticationManagement.GetFlowAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Authentication flow update persists and appears in realm flow list |
| PUT | `/admin/realms/{realm}/authentication/flows/{id}` | `AuthenticationManagement.UpdateFlowAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Authentication flow update persists and appears in realm flow list |
| GET | `/admin/realms/{realm}/authentication/form-action-providers` | `AuthenticationManagement.GetFormActionProvidersAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Discovery contains installed executable authentication provider: registration-user-creation |
| GET | `/admin/realms/{realm}/authentication/form-providers` | `AuthenticationManagement.GetFormProvidersAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Discovery contains installed executable authentication provider: registration-page-form |
| GET | `/admin/realms/{realm}/authentication/per-client-config-description` | `AuthenticationManagement.GetPerClientConfigDescriptionAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Per-client authentication settings describe installed client-secret authenticator |
| POST | `/admin/realms/{realm}/authentication/register-required-action` | `AuthenticationManagement.RegisterRequiredActionAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Required-action registration persists provider alias |
| GET | `/admin/realms/{realm}/authentication/required-actions` | `AuthenticationManagement.GetRequiredActionsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Required-action registration persists provider alias |
| DELETE | `/admin/realms/{realm}/authentication/required-actions/{alias}` | `AuthenticationManagement.RemoveRequiredActionAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Unregistered actions expose removed installed provider |
| GET | `/admin/realms/{realm}/authentication/required-actions/{alias}` | `AuthenticationManagement.GetRequiredActionAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Required-action raise-priority restores ordering |
| PUT | `/admin/realms/{realm}/authentication/required-actions/{alias}` | `AuthenticationManagement.UpdateRequiredActionAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Required-action update changes persisted display name |
| DELETE | `/admin/realms/{realm}/authentication/required-actions/{alias}/config` | `AuthenticationManagement.RemoveRequiredActionConfigAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Deleting required-action config removes custom value and recreates defaults |
| GET | `/admin/realms/{realm}/authentication/required-actions/{alias}/config` | `AuthenticationManagement.GetRequiredActionConfigAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Deleting required-action config removes custom value and recreates defaults |
| PUT | `/admin/realms/{realm}/authentication/required-actions/{alias}/config` | `AuthenticationManagement.UpdateRequiredActionConfigAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Required-action configuration is persisted |
| GET | `/admin/realms/{realm}/authentication/required-actions/{alias}/config-description` | `AuthenticationManagement.GetRequiredActionConfigDescriptionAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Required-action configuration description exposes configurable properties |
| POST | `/admin/realms/{realm}/authentication/required-actions/{alias}/lower-priority` | `AuthenticationManagement.LowerRequiredActionPriorityAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Required-action lower-priority changes ordering |
| POST | `/admin/realms/{realm}/authentication/required-actions/{alias}/raise-priority` | `AuthenticationManagement.RaiseRequiredActionPriorityAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Required-action raise-priority restores ordering |
| GET | `/admin/realms/{realm}/authentication/unregistered-required-actions` | `AuthenticationManagement.GetUnregisteredRequiredActionsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Unregistered actions expose removed installed provider |

### ClearCrlCache（1 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| POST | `/admin/realms/{realm}/clear-crl-cache` | `ClearCrlCache.ClearCrlCacheAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Clearing CRL cache refetches changed signed CRL and rejects revoked certificate authentication |

### ClearKeysCache（1 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| POST | `/admin/realms/{realm}/clear-keys-cache` | `ClearKeysCache.ClearKeysCacheAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Clear keys cache refetches changed JWKS and accepts assertion signed with new RSA key |

### ClearRealmCache（1 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| POST | `/admin/realms/{realm}/clear-realm-cache` | `ClearRealmCache.ClearRealmCacheAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Clearing realm cache exposes actual out-of-band PostgreSQL mutation |

### ClearUserCache（1 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| POST | `/admin/realms/{realm}/clear-user-cache` | `ClearUserCache.ClearUserCacheAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Clearing user cache exposes external LDAP attribute mutation |

### Client（26 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| DELETE | `/admin/realms/{realm}/clients/{client-uuid}` | `Client.DeleteClientAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Deleting client removes actual scope owner |
| GET | `/admin/realms/{realm}/clients/{client-uuid}` | `Client.GetClientAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Unregistering cluster node removes persisted host |
| PUT | `/admin/realms/{realm}/clients/{client-uuid}` | `Client.UpdateAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Client update persists while preserving authorization services |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/client-secret` | `Client.GetClientSecretAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Read client secret matches configured authentication credential |
| POST | `/admin/realms/{realm}/clients/{client-uuid}/client-secret` | `Client.RegenerateSecretAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Secret rotation retains previous secret and new secret authenticates against real OIDC token endpoint |
| DELETE | `/admin/realms/{realm}/clients/{client-uuid}/client-secret/rotated` | `Client.InvalidateRotatedSecretAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Invalidating rotated secret removes stored old credential |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/client-secret/rotated` | `Client.GetClientRotatedSecretAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Secret rotation retains previous secret and new secret authenticates against real OIDC token endpoint |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/default-client-scopes` | `Client.GetDefaultClientScopesAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Client scope relationship removed: default-client-scopes |
| DELETE | `/admin/realms/{realm}/clients/{client-uuid}/default-client-scopes/{clientScopeId}` | `Client.RemoveDefaultClientScopeAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Client scope relationship removed: default-client-scopes |
| PUT | `/admin/realms/{realm}/clients/{client-uuid}/default-client-scopes/{clientScopeId}` | `Client.AddDefaultClientScopeAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Client scope relationship persisted: default-client-scopes |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/installation/providers/{providerId}` | `Client.GetInstallationProviderAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Installation output embeds actual client and realm configuration |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/management/permissions` | `Client.GetManagementPermissionsAsync` | 政策排除 | 政策排除 | 通过 200 | 通过 200 | Disabling legacy permissions changes persisted state: clients/{client-uuid}/management/permissions |
| PUT | `/admin/realms/{realm}/clients/{client-uuid}/management/permissions` | `Client.SetManagementPermissionsEnabledAsync` | 政策排除 | 政策排除 | 通过 200 | 通过 200 | Disabling legacy permissions changes persisted state: clients/{client-uuid}/management/permissions |
| POST | `/admin/realms/{realm}/clients/{client-uuid}/nodes` | `Client.RegisterNodeAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Cluster node registration persists host and registration timestamp |
| DELETE | `/admin/realms/{realm}/clients/{client-uuid}/nodes/{node}` | `Client.UnregisterNodeAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Unregistering cluster node removes persisted host |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/offline-session-count` | `Client.GetOfflineSessionCountAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Offline grant persists user/client offline session and count |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/offline-sessions` | `Client.GetOfflineUserSessionsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Offline grant persists user/client offline session and count |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/optional-client-scopes` | `Client.GetOptionalClientScopesAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Client scope relationship removed: optional-client-scopes |
| DELETE | `/admin/realms/{realm}/clients/{client-uuid}/optional-client-scopes/{clientScopeId}` | `Client.RemoveOptionalClientScopeAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Client scope relationship removed: optional-client-scopes |
| PUT | `/admin/realms/{realm}/clients/{client-uuid}/optional-client-scopes/{clientScopeId}` | `Client.AddOptionalClientScopeAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Client scope relationship persisted: optional-client-scopes |
| POST | `/admin/realms/{realm}/clients/{client-uuid}/push-revocation` | `Client.PushRevocationAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Client revocation propagates actual signed not-before adapter request |
| POST | `/admin/realms/{realm}/clients/{client-uuid}/registration-access-token` | `Client.RegenerateRegistrationAccessTokenAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Regenerated registration access token authorizes real dynamic-registration read |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/service-account-user` | `Client.GetServiceAccountUserAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Service-account endpoint returns persisted client service user |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/session-count` | `Client.GetApplicationSessionCountAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Real password grant creates persisted user/client session and counted client statistics |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/test-nodes-available` | `Client.TestNodesAvailableAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Node availability sends actual signed adapter action over HTTP |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/user-sessions` | `Client.GetUserSessionsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Real password grant creates persisted user/client session and counted client statistics |

### ClientAttributeCertificate（6 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/certificates/{attr}` | `ClientAttributeCertificate.GetKeyInfoAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Generate-and-download returns usable private-key PKCS12 while persisting only the new public certificate |
| POST | `/admin/realms/{realm}/clients/{client-uuid}/certificates/{attr}/download` | `ClientAttributeCertificate.GetKeystoreAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Downloaded PKCS12 contains exact persisted public certificate without private key |
| POST | `/admin/realms/{realm}/clients/{client-uuid}/certificates/{attr}/generate` | `ClientAttributeCertificate.GenerateAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Generated keypair returns private key once and persists public certificate only |
| POST | `/admin/realms/{realm}/clients/{client-uuid}/certificates/{attr}/generate-and-download` | `ClientAttributeCertificate.GenerateAndGetKeystoreAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Generate-and-download returns usable private-key PKCS12 while persisting only the new public certificate |
| POST | `/admin/realms/{realm}/clients/{client-uuid}/certificates/{attr}/upload` | `ClientAttributeCertificate.UploadJksAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Multipart upload persists exact uploaded X509 certificate |
| POST | `/admin/realms/{realm}/clients/{client-uuid}/certificates/{attr}/upload-certificate` | `ClientAttributeCertificate.UploadJksCertificateAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Multipart upload-certificate persists exact uploaded X509 certificate |

### ClientInitialAccess（3 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GET | `/admin/realms/{realm}/clients-initial-access` | `ClientInitialAccess.ListAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Initial access token deletion persisted |
| POST | `/admin/realms/{realm}/clients-initial-access` | `ClientInitialAccess.CreateAsync` | 通过 201 | 通过 201 | 通过 201 | 通过 201 | Initial access token is issued and persisted |
| DELETE | `/admin/realms/{realm}/clients-initial-access/{id}` | `ClientInitialAccess.DeleteAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Initial access token deletion persisted |

### ClientPolicies（2 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GET | `/admin/realms/{realm}/client-policies/policies` | `ClientPolicies.GetPoliciesAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Client policy persists enabled condition and profile association |
| PUT | `/admin/realms/{realm}/client-policies/policies` | `ClientPolicies.UpdatePoliciesAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Client policy persists enabled condition and profile association |

### ClientProfiles（2 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GET | `/admin/realms/{realm}/client-policies/profiles` | `ClientProfiles.GetProfilesAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Client policy profile persists rotation executor settings |
| PUT | `/admin/realms/{realm}/client-policies/profiles` | `ClientProfiles.UpdateProfilesAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Client policy profile persists rotation executor settings |

### ClientRegistrationPolicy（1 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GET | `/admin/realms/{realm}/client-registration-policy/providers` | `ClientRegistrationPolicy.GetProvidersAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Registration policy discovery exposes installed provider |

### ClientRoleMappings（15 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| DELETE | `/admin/realms/{realm}/groups/{group-id}/role-mappings/clients/{client-id}` | `ClientRoleMappings.DeleteClientRoleMappingAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Deleting mappings removes direct role relationships: groups/{group-id}/role-mappings |
| GET | `/admin/realms/{realm}/groups/{group-id}/role-mappings/clients/{client-id}` | `ClientRoleMappings.GetClientRoleMappingsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | UI bulk mapping deletion removes actual direct client role for groups |
| POST | `/admin/realms/{realm}/groups/{group-id}/role-mappings/clients/{client-id}` | `ClientRoleMappings.AddClientRoleMappingAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Assigned roles and effective composite mappings persist: groups/{group-id}/role-mappings |
| GET | `/admin/realms/{realm}/groups/{group-id}/role-mappings/clients/{client-id}/available` | `ClientRoleMappings.GetAvailableClientRoleMappingsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Available mappings contain unassigned real realm and client roles: groups/{group-id}/role-mappings |
| GET | `/admin/realms/{realm}/groups/{group-id}/role-mappings/clients/{client-id}/composite` | `ClientRoleMappings.GetCompositeClientRoleMappingsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Assigned roles and effective composite mappings persist: groups/{group-id}/role-mappings |
| DELETE | `/admin/realms/{realm}/organizations/{org-id}/groups/{group-id}/role-mappings/clients/{client-id}` | `ClientRoleMappings.DeleteClientRoleMappingDELETEAdminRealmsRealmOrganizationsOrgIdGroupsGroupIdRoleMappingsClientsClientIdAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Deleting mappings removes direct role relationships: organizations/{org-id}/groups/{group-id}/role-mappings |
| GET | `/admin/realms/{realm}/organizations/{org-id}/groups/{group-id}/role-mappings/clients/{client-id}` | `ClientRoleMappings.GetClientRoleMappingsGETAdminRealmsRealmOrganizationsOrgIdGroupsGroupIdRoleMappingsClientsClientIdAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Deleting mappings removes direct role relationships: organizations/{org-id}/groups/{group-id}/role-mappings |
| POST | `/admin/realms/{realm}/organizations/{org-id}/groups/{group-id}/role-mappings/clients/{client-id}` | `ClientRoleMappings.AddClientRoleMappingPOSTAdminRealmsRealmOrganizationsOrgIdGroupsGroupIdRoleMappingsClientsClientIdAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Assigned roles and effective composite mappings persist: organizations/{org-id}/groups/{group-id}/role-mappings |
| GET | `/admin/realms/{realm}/organizations/{org-id}/groups/{group-id}/role-mappings/clients/{client-id}/available` | `ClientRoleMappings.GetAvailableClientRoleMappingsGETAdminRealmsRealmOrganizationsOrgIdGroupsGroupIdRoleMappingsClientsClientIdAvailableAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Available mappings contain unassigned real realm and client roles: organizations/{org-id}/groups/{group-id}/role-mappings |
| GET | `/admin/realms/{realm}/organizations/{org-id}/groups/{group-id}/role-mappings/clients/{client-id}/composite` | `ClientRoleMappings.GetCompositeClientRoleMappingsGETAdminRealmsRealmOrganizationsOrgIdGroupsGroupIdRoleMappingsClientsClientIdCompositeAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Assigned roles and effective composite mappings persist: organizations/{org-id}/groups/{group-id}/role-mappings |
| DELETE | `/admin/realms/{realm}/users/{user-id}/role-mappings/clients/{client-id}` | `ClientRoleMappings.DeleteClientRoleMappingDELETEAdminRealmsRealmUsersUserIdRoleMappingsClientsClientIdAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Deleting mappings removes direct role relationships: users/{user-id}/role-mappings |
| GET | `/admin/realms/{realm}/users/{user-id}/role-mappings/clients/{client-id}` | `ClientRoleMappings.GetClientRoleMappingsGETAdminRealmsRealmUsersUserIdRoleMappingsClientsClientIdAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | UI bulk mapping deletion removes actual direct client role for users |
| POST | `/admin/realms/{realm}/users/{user-id}/role-mappings/clients/{client-id}` | `ClientRoleMappings.AddClientRoleMappingPOSTAdminRealmsRealmUsersUserIdRoleMappingsClientsClientIdAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Assigned roles and effective composite mappings persist: users/{user-id}/role-mappings |
| GET | `/admin/realms/{realm}/users/{user-id}/role-mappings/clients/{client-id}/available` | `ClientRoleMappings.GetAvailableClientRoleMappingsGETAdminRealmsRealmUsersUserIdRoleMappingsClientsClientIdAvailableAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Available mappings contain unassigned real realm and client roles: users/{user-id}/role-mappings |
| GET | `/admin/realms/{realm}/users/{user-id}/role-mappings/clients/{client-id}/composite` | `ClientRoleMappings.GetCompositeClientRoleMappingsGETAdminRealmsRealmUsersUserIdRoleMappingsClientsClientIdCompositeAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Assigned roles and effective composite mappings persist: users/{user-id}/role-mappings |

### ClientScope（6 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| DELETE | `/admin/realms/{realm}/client-scopes/{client-scope-id}` | `ClientScope.DeleteClientScopeAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Deleting client scope removes actual scope and its configuration |
| GET | `/admin/realms/{realm}/client-scopes/{client-scope-id}` | `ClientScope.GetClientScopeAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Scope update changes persisted description |
| PUT | `/admin/realms/{realm}/client-scopes/{client-scope-id}` | `ClientScope.UpdateAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Scope update changes persisted description |
| DELETE | `/admin/realms/{realm}/client-templates/{client-scope-id}` | `ClientScope.DeleteClientScopeDELETEAdminRealmsRealmClientTemplatesClientScopeIdAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Legacy template deletion removes scope |
| GET | `/admin/realms/{realm}/client-templates/{client-scope-id}` | `ClientScope.GetClientScopeGETAdminRealmsRealmClientTemplatesClientScopeIdAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Scope update changes persisted description |
| PUT | `/admin/realms/{realm}/client-templates/{client-scope-id}` | `ClientScope.UpdatePUTAdminRealmsRealmClientTemplatesClientScopeIdAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Scope update changes persisted description |

### ClientScopeEvaluate（5 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/evaluate-scopes/generate-example-access-token` | `ClientScopeEvaluate.GenerateExampleAccessTokenAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Evaluated access-token contains actual user ID and claim emitted by persisted mapper |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/evaluate-scopes/generate-example-id-token` | `ClientScopeEvaluate.GenerateExampleIdTokenAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Evaluated id-token contains actual user ID and claim emitted by persisted mapper |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/evaluate-scopes/generate-example-saml-response` | `ClientScopeEvaluate.GenerateExampleSamlResponseAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | SAML evaluation builds an assertion for the actual persisted user |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/evaluate-scopes/generate-example-userinfo` | `ClientScopeEvaluate.GenerateExampleUserinfoAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Evaluated userinfo contains actual user ID and claim emitted by persisted mapper |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/evaluate-scopes/protocol-mappers` | `ClientScopeEvaluate.GetGrantedProtocolMappersAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Effective mapper evaluation includes persisted client mapper |

### ClientScopeEvaluateScopeMappings（2 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/evaluate-scopes/scope-mappings/{roleContainerId}/granted` | `ClientScopeEvaluateScopeMappings.GetGrantedScopeMappingsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Adding client scope mapping changes effective granted roles |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/evaluate-scopes/scope-mappings/{roleContainerId}/not-granted` | `ClientScopeEvaluateScopeMappings.GetNotGrantedScopeMappingsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Evaluation identifies a real realm role outside client scope |

### ClientScopes（4 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GET | `/admin/realms/{realm}/client-scopes` | `ClientScopes.GetClientScopesAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Scope collection lists created scope |
| POST | `/admin/realms/{realm}/client-scopes` | `ClientScopes.CreateClientScopeAsync` | 通过 201 | 通过 201 | 通过 201 | 通过 201 | Client scope creation persists through its collection alias |
| GET | `/admin/realms/{realm}/client-templates` | `ClientScopes.GetClientScopesGETAdminRealmsRealmClientTemplatesAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Scope collection lists created scope |
| POST | `/admin/realms/{realm}/client-templates` | `ClientScopes.CreateClientScopePOSTAdminRealmsRealmClientTemplatesAsync` | 通过 201 | 通过 201 | 通过 201 | 通过 201 | Client scope creation persists through its collection alias |

### ClientTypes（2 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GET | `/admin/realms/{realm}/client-types` | `ClientTypes.GetClientTypesAsync` | 政策排除 | 政策排除 | 政策排除 | 政策排除 | Client Types：26.8.1 为 EXPERIMENTAL，按要求不做真实验收 |
| PUT | `/admin/realms/{realm}/client-types` | `ClientTypes.UpdateClientTypesAsync` | 政策排除 | 政策排除 | 政策排除 | 政策排除 | Client Types：26.8.1 为 EXPERIMENTAL，按要求不做真实验收 |

### Clients（2 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GET | `/admin/realms/{realm}/clients` | `Clients.GetClientsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Client query resolves created internal ID |
| POST | `/admin/realms/{realm}/clients` | `Clients.CreateClientAsync` | 通过 201 | 通过 201 | 通过 201 | 通过 201 | Client creation persisted internal ID and public client ID |

### Component（6 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GET | `/admin/realms/{realm}/components` | `Component.GetComponentsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | LDAP component creation persists provider, parent and discoverable storage name |
| POST | `/admin/realms/{realm}/components` | `Component.CreateAsync` | 通过 201 | 通过 201 | 通过 201 | 通过 201 | LDAP component creation persists provider, parent and discoverable storage name |
| DELETE | `/admin/realms/{realm}/components/{id}` | `Component.RemoveComponentAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Deleting LDAP component removes its persisted provider configuration |
| GET | `/admin/realms/{realm}/components/{id}` | `Component.GetComponentAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Component update persists renamed LDAP provider |
| PUT | `/admin/realms/{realm}/components/{id}` | `Component.UpdateComponentAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Component update persists renamed LDAP provider |
| GET | `/admin/realms/{realm}/components/{id}/sub-component-types` | `Component.GetSubcomponentConfigAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Subcomponent discovery exposes installed LDAP group mapper |

### Group（8 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| DELETE | `/admin/realms/{realm}/groups/{group-id}` | `Group.DeleteGroupAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Deleting group removes actual imported group |
| GET | `/admin/realms/{realm}/groups/{group-id}` | `Group.GetGroupAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Group attribute update persists multivalue data |
| PUT | `/admin/realms/{realm}/groups/{group-id}` | `Group.UpdateGroupAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Group attribute update persists multivalue data |
| GET | `/admin/realms/{realm}/groups/{group-id}/children` | `Group.GetSubGroupsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Child creation persists parent-child relationship |
| POST | `/admin/realms/{realm}/groups/{group-id}/children` | `Group.AddChildAsync` | 通过 201 | 通过 201 | 通过 201 | 通过 201 | Child creation persists parent-child relationship |
| GET | `/admin/realms/{realm}/groups/{group-id}/management/permissions` | `Group.GetManagementPermissionsAsync` | 政策排除 | 政策排除 | 通过 200 | 通过 200 | Disabling legacy permissions changes persisted state: groups/{group-id}/management/permissions |
| PUT | `/admin/realms/{realm}/groups/{group-id}/management/permissions` | `Group.SetManagementPermissionsEnabledAsync` | 政策排除 | 政策排除 | 通过 200 | 通过 200 | Disabling legacy permissions changes persisted state: groups/{group-id}/management/permissions |
| GET | `/admin/realms/{realm}/groups/{group-id}/members` | `Group.GetMembersAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Joining group updates member listing and user membership count |

### Groups（3 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GET | `/admin/realms/{realm}/groups` | `Groups.GetGroupsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | LDAP group mapper sync imports actual directory group |
| POST | `/admin/realms/{realm}/groups` | `Groups.AddTopLevelGroupAsync` | 通过 201 | 通过 201 | 通过 201 | 通过 201 | Group creation persists name |
| GET | `/admin/realms/{realm}/groups/count` | `Groups.GetGroupCountAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Group search and count reflect two created groups |

### IdentityProvider（13 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| DELETE | `/admin/realms/{realm}/identity-provider/instances/{alias}` | `IdentityProvider.DeleteAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Identity provider deletion removes its configuration |
| GET | `/admin/realms/{realm}/identity-provider/instances/{alias}` | `IdentityProvider.GetIdentityProviderAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Provider update persists display name |
| PUT | `/admin/realms/{realm}/identity-provider/instances/{alias}` | `IdentityProvider.UpdateAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Provider update persists display name |
| GET | `/admin/realms/{realm}/identity-provider/instances/{alias}/export` | `IdentityProvider.ExportAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Provider export generates broker-specific SAML metadata |
| GET | `/admin/realms/{realm}/identity-provider/instances/{alias}/management/permissions` | `IdentityProvider.GetManagementPermissionsAsync` | 政策排除 | 政策排除 | 通过 200 | 通过 200 | Disabling legacy permissions changes persisted state: identity-provider/instances/{alias}/management/permissions |
| PUT | `/admin/realms/{realm}/identity-provider/instances/{alias}/management/permissions` | `IdentityProvider.SetManagementPermissionsEnabledAsync` | 政策排除 | 政策排除 | 通过 200 | 通过 200 | Disabling legacy permissions changes persisted state: identity-provider/instances/{alias}/management/permissions |
| GET | `/admin/realms/{realm}/identity-provider/instances/{alias}/mapper-types` | `IdentityProvider.GetMapperTypesAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Mapper-type discovery exposes installed SAML attribute mapper |
| GET | `/admin/realms/{realm}/identity-provider/instances/{alias}/mappers` | `IdentityProvider.GetMappersAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Provider mapper deletion removes stored model |
| POST | `/admin/realms/{realm}/identity-provider/instances/{alias}/mappers` | `IdentityProvider.AddMapperAsync` | 通过 201 | 通过 201 | 通过 201 | 通过 201 | Identity-provider mapper persists config and provider association |
| DELETE | `/admin/realms/{realm}/identity-provider/instances/{alias}/mappers/{id}` | `IdentityProvider.DeleteDELETEAdminRealmsRealmIdentityProviderInstancesAliasMappersIdAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Provider mapper deletion removes stored model |
| GET | `/admin/realms/{realm}/identity-provider/instances/{alias}/mappers/{id}` | `IdentityProvider.GetMapperByIdAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Identity-provider mapper update changes stored attribute target |
| PUT | `/admin/realms/{realm}/identity-provider/instances/{alias}/mappers/{id}` | `IdentityProvider.UpdatePUTAdminRealmsRealmIdentityProviderInstancesAliasMappersIdAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Identity-provider mapper update changes stored attribute target |
| GET | `/admin/realms/{realm}/identity-provider/instances/{alias}/reload-keys` | `IdentityProvider.ReloadKeysAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Reload refetches changed remote key set |

### IdentityProviders（5 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| POST | `/admin/realms/{realm}/identity-provider/import-config` | `IdentityProviders.ImportFromAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | JSON metadata import performs a real HTTP fetch and parses metadata |
| GET | `/admin/realms/{realm}/identity-provider/instances` | `IdentityProviders.GetIdentityProvidersAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Identity-provider creation persists real provider configurations |
| POST | `/admin/realms/{realm}/identity-provider/instances` | `IdentityProviders.CreateAsync` | 通过 201 | 通过 201 | 通过 201 | 通过 201 | Identity-provider creation persists real provider configurations |
| GET | `/admin/realms/{realm}/identity-provider/providers/{provider_id}` | `IdentityProviders.GetIdentityProviderFactoryAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Provider discovery returns installed OIDC implementation |
| POST | `/admin/realms/{realm}/identity-provider/upload-certificate` | `IdentityProviders.UploadCertificateAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Certificate upload parses actual X509 certificate and extracts its public key |

### Key（1 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GET | `/admin/realms/{realm}/keys` | `Key.GetKeyMetadataAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Realm key metadata contains active RSA signing key |

### LdapServerCapabilities（1 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| POST | `/admin/realms/{realm}/ldap-server-capabilities` | `LdapServerCapabilities.LdapServerCapabilitiesAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Keycloak binds to actual OpenLDAP and discovers root-DSE supported capabilities |

### Organization（3 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| DELETE | `/admin/realms/{realm}/organizations/{org-id}` | `Organization.DeleteAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Deleting organization removes persisted entity |
| GET | `/admin/realms/{realm}/organizations/{org-id}` | `Organization.GetAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Organization update persists description |
| PUT | `/admin/realms/{realm}/organizations/{org-id}` | `Organization.UpdateAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Organization update persists description |

### OrganizationGroup（8 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| DELETE | `/admin/realms/{realm}/organizations/{org-id}/groups/{group-id}` | `OrganizationGroup.DeleteGroupAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Deleting organization group removes group subtree |
| GET | `/admin/realms/{realm}/organizations/{org-id}/groups/{group-id}` | `OrganizationGroup.GetGroupAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Organization group update persists description |
| PUT | `/admin/realms/{realm}/organizations/{org-id}/groups/{group-id}` | `OrganizationGroup.UpdateGroupAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Organization group update persists description |
| GET | `/admin/realms/{realm}/organizations/{org-id}/groups/{group-id}/children` | `OrganizationGroup.GetSubGroupsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Organization nested group creation and path lookup agree on persisted child |
| POST | `/admin/realms/{realm}/organizations/{org-id}/groups/{group-id}/children` | `OrganizationGroup.AddSubGroupAsync` | 通过 201 | 通过 201 | 通过 201 | 通过 201 | Organization nested group creation and path lookup agree on persisted child |
| GET | `/admin/realms/{realm}/organizations/{org-id}/groups/{group-id}/members` | `OrganizationGroup.GetMembersAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Organization group leave removes persisted membership |
| DELETE | `/admin/realms/{realm}/organizations/{org-id}/groups/{group-id}/members/{userId}` | `OrganizationGroup.LeaveGroupAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Organization group leave removes persisted membership |
| PUT | `/admin/realms/{realm}/organizations/{org-id}/groups/{group-id}/members/{userId}` | `OrganizationGroup.JoinGroupAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Organization member/group and linked provider group queries reflect actual membership |

### OrganizationGroups（3 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GET | `/admin/realms/{realm}/organizations/{org-id}/groups` | `OrganizationGroups.GetGroupsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Deleting organization group removes group subtree |
| POST | `/admin/realms/{realm}/organizations/{org-id}/groups` | `OrganizationGroups.AddTopLevelGroupAsync` | 通过 201 | 通过 201 | 通过 201 | 通过 201 | Organization group creation persists within its organization |
| GET | `/admin/realms/{realm}/organizations/{org-id}/groups/group-by-path/{path}` | `OrganizationGroups.GetGroupByPathAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Organization nested group creation and path lookup agree on persisted child |

### OrganizationIdentityProviders（6 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GET | `/admin/realms/{realm}/organizations/{org-id}/identity-providers` | `OrganizationIdentityProviders.GetIdentityProvidersAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Organization unlink removes identity-provider association |
| POST | `/admin/realms/{realm}/organizations/{org-id}/identity-providers` | `OrganizationIdentityProviders.AddIdentityProviderAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Organization identity-provider association persists |
| DELETE | `/admin/realms/{realm}/organizations/{org-id}/identity-providers/{alias}` | `OrganizationIdentityProviders.DeleteAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Organization unlink removes identity-provider association |
| GET | `/admin/realms/{realm}/organizations/{org-id}/identity-providers/{alias}` | `OrganizationIdentityProviders.GetIdentityProviderAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Per-organization identity-provider link stores auto-membership setting |
| PUT | `/admin/realms/{realm}/organizations/{org-id}/identity-providers/{alias}` | `OrganizationIdentityProviders.UpdateIdentityProviderLinkAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Per-organization identity-provider link stores auto-membership setting |
| GET | `/admin/realms/{realm}/organizations/{org-id}/identity-providers/{alias}/groups` | `OrganizationIdentityProviders.GetGroupsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Organization member/group and linked provider group queries reflect actual membership |

### OrganizationInvitation（4 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GET | `/admin/realms/{realm}/organizations/{org-id}/invitations` | `OrganizationInvitation.GetInvitationsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Existing-user invitation sends actual user email and persists pending membership invitation |
| DELETE | `/admin/realms/{realm}/organizations/{org-id}/invitations/{id}` | `OrganizationInvitation.DeleteInvitationAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Deleting invitation removes pending invitation record |
| GET | `/admin/realms/{realm}/organizations/{org-id}/invitations/{id}` | `OrganizationInvitation.GetInvitationAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | New-user invitation sends email and persists pending invitation with organization/expiry |
| POST | `/admin/realms/{realm}/organizations/{org-id}/invitations/{id}/resend` | `OrganizationInvitation.ResendInvitationAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Resending sends a second actual email and replaces invitation ID as released source specifies |

### OrganizationMember（10 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GET | `/admin/realms/{realm}/organizations/{org-id}/members` | `OrganizationMember.SearchAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Unmanaged member removal preserves underlying user |
| POST | `/admin/realms/{realm}/organizations/{org-id}/members` | `OrganizationMember.AddMemberAsync` | 通过 201 | 通过 201 | 通过 201 | 通过 201 | Organization membership is visible through member, count and reverse-organization queries |
| GET | `/admin/realms/{realm}/organizations/{org-id}/members/count` | `OrganizationMember.CountAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Organization membership is visible through member, count and reverse-organization queries |
| POST | `/admin/realms/{realm}/organizations/{org-id}/members/invite-existing-user` | `OrganizationMember.InviteExistingUserAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Existing-user invitation sends actual user email and persists pending membership invitation |
| POST | `/admin/realms/{realm}/organizations/{org-id}/members/invite-user` | `OrganizationMember.InviteUserAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | New-user invitation sends email and persists pending invitation with organization/expiry |
| DELETE | `/admin/realms/{realm}/organizations/{org-id}/members/{member-id}` | `OrganizationMember.DeleteAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Unmanaged member removal preserves underlying user |
| GET | `/admin/realms/{realm}/organizations/{org-id}/members/{member-id}` | `OrganizationMember.GetAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Changing membership type restores unmanaged state |
| GET | `/admin/realms/{realm}/organizations/{org-id}/members/{member-id}/groups` | `OrganizationMember.GroupMembershipsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Organization member/group and linked provider group queries reflect actual membership |
| PUT | `/admin/realms/{realm}/organizations/{org-id}/members/{member-id}/membership-type` | `OrganizationMember.UpdateMembershipTypeAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Changing membership type restores unmanaged state |
| GET | `/admin/realms/{realm}/organizations/{org-id}/members/{member-id}/organizations` | `OrganizationMember.GetOrganizationsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Organization membership is visible through member, count and reverse-organization queries |

### Organizations（4 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GET | `/admin/realms/{realm}/organizations` | `Organizations.SearchAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Organization creation persists and participates in search/count |
| POST | `/admin/realms/{realm}/organizations` | `Organizations.CreateAsync` | 通过 201 | 通过 201 | 通过 201 | 通过 201 | Organization creation persists and participates in search/count |
| GET | `/admin/realms/{realm}/organizations/count` | `Organizations.GetOrganizationCountAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Organization creation persists and participates in search/count |
| GET | `/admin/realms/{realm}/organizations/members/{member-id}/organizations` | `Organizations.GetOrganizationsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Organization membership is visible through member, count and reverse-organization queries |

### Policy（42 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/permission` | `Policy.FindAllAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Policy/permission creation persists actual user policy and resource/scope permission |
| POST | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/permission` | `Policy.CreateAsync` | 通过 201 | 通过 201 | 通过 201 | 通过 201 | Policy/permission creation persists actual user policy and resource/scope permission |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/permission/providers` | `Policy.FindPolicyProvidersAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Authorization provider discovery exposes installed provider for permission |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/permission/search` | `Policy.FindByNameAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Policy/permission creation persists actual user policy and resource/scope permission |
| DELETE | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/permission/{type}` | `Policy.DeleteAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Root policy deletion removes persisted permission |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/permission/{type}` | `Policy.FindByIdAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Policy update persists through root or provider-specific ID route |
| POST | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/permission/{type}` | `Policy.CreatePOSTAdminRealmsRealmClientsClientUuidAuthzResourceServerPermissionTypeAsync` | 通过 201 | 通过 201 | 通过 201 | 通过 201 | Provider-specific creation and ID dispatch persist typed policies |
| PUT | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/permission/{type}` | `Policy.UpdateAsync` | 通过 201 | 通过 201 | 通过 201 | 通过 201 | Policy update persists through root or provider-specific ID route |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/permission/{type}/associatedPolicies` | `Policy.GetAssociatedPoliciesAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Policy ID lookup and resource/scope/associated-policy links reflect stored dependency graph |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/permission/{type}/dependentPolicies` | `Policy.GetDependentPoliciesAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Dependent policy query follows persisted permission-to-user-policy edge |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/permission/{type}/providers` | `Policy.FindPolicyProvidersGETAdminRealmsRealmClientsClientUuidAuthzResourceServerPermissionTypeProvidersAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Provider-type listing/search/paging and provider discovery operate on real data |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/permission/{type}/resources` | `Policy.GetResourcesAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Policy ID lookup and resource/scope/associated-policy links reflect stored dependency graph |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/permission/{type}/scopes` | `Policy.GetScopesAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Policy ID lookup and resource/scope/associated-policy links reflect stored dependency graph |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/permission/{type}/search` | `Policy.FindByNameGETAdminRealmsRealmClientsClientUuidAuthzResourceServerPermissionTypeSearchAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Provider-type listing/search/paging and provider discovery operate on real data |
| DELETE | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/permission/{type}/{policy-id}` | `Policy.DeleteDELETEAdminRealmsRealmClientsClientUuidAuthzResourceServerPermissionTypePolicyIdAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Typed policy deletion removes persisted permission |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/permission/{type}/{policy-id}` | `Policy.FindByIdGETAdminRealmsRealmClientsClientUuidAuthzResourceServerPermissionTypePolicyIdAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Policy update persists through root or provider-specific ID route |
| PUT | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/permission/{type}/{policy-id}` | `Policy.UpdatePUTAdminRealmsRealmClientsClientUuidAuthzResourceServerPermissionTypePolicyIdAsync` | 通过 201 | 通过 201 | 通过 201 | 通过 201 | Policy update persists through root or provider-specific ID route |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/permission/{type}/{policy-id}/associatedPolicies` | `Policy.GetAssociatedPoliciesGETAdminRealmsRealmClientsClientUuidAuthzResourceServerPermissionTypePolicyIdAssociatedPoliciesAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Policy ID lookup and resource/scope/associated-policy links reflect stored dependency graph |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/permission/{type}/{policy-id}/dependentPolicies` | `Policy.GetDependentPoliciesGETAdminRealmsRealmClientsClientUuidAuthzResourceServerPermissionTypePolicyIdDependentPoliciesAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Provider-specific dependent-policy lookup follows persisted edge |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/permission/{type}/{policy-id}/resources` | `Policy.GetResourcesGETAdminRealmsRealmClientsClientUuidAuthzResourceServerPermissionTypePolicyIdResourcesAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Policy ID lookup and resource/scope/associated-policy links reflect stored dependency graph |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/permission/{type}/{policy-id}/scopes` | `Policy.GetScopesGETAdminRealmsRealmClientsClientUuidAuthzResourceServerPermissionTypePolicyIdScopesAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Policy ID lookup and resource/scope/associated-policy links reflect stored dependency graph |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/policy` | `Policy.FindAllGETAdminRealmsRealmClientsClientUuidAuthzResourceServerPolicyAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Policy/permission creation persists actual user policy and resource/scope permission |
| POST | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/policy` | `Policy.CreatePOSTAdminRealmsRealmClientsClientUuidAuthzResourceServerPolicyAsync` | 通过 201 | 通过 201 | 通过 201 | 通过 201 | Policy/permission creation persists actual user policy and resource/scope permission |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/policy/providers` | `Policy.FindPolicyProvidersGETAdminRealmsRealmClientsClientUuidAuthzResourceServerPolicyProvidersAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Authorization provider discovery exposes installed provider for policy |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/policy/search` | `Policy.FindByNameGETAdminRealmsRealmClientsClientUuidAuthzResourceServerPolicySearchAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Policy/permission creation persists actual user policy and resource/scope permission |
| DELETE | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/policy/{type}` | `Policy.DeleteDELETEAdminRealmsRealmClientsClientUuidAuthzResourceServerPolicyTypeAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Revoking FGAP policy restores actual 403 and prevents unauthorized data change |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/policy/{type}` | `Policy.FindByIdGETAdminRealmsRealmClientsClientUuidAuthzResourceServerPolicyTypeAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Policy update persists through root or provider-specific ID route |
| POST | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/policy/{type}` | `Policy.CreatePOSTAdminRealmsRealmClientsClientUuidAuthzResourceServerPolicyTypeAsync` | 通过 201 | 通过 201 | 通过 201 | 通过 201 | Declared FGAP v2 policy grants real delegated admin read/write after an initial 403 |
| PUT | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/policy/{type}` | `Policy.UpdatePUTAdminRealmsRealmClientsClientUuidAuthzResourceServerPolicyTypeAsync` | 通过 201 | 通过 201 | 通过 201 | 通过 201 | Policy update persists through root or provider-specific ID route |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/policy/{type}/associatedPolicies` | `Policy.GetAssociatedPoliciesGETAdminRealmsRealmClientsClientUuidAuthzResourceServerPolicyTypeAssociatedPoliciesAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Policy ID lookup and resource/scope/associated-policy links reflect stored dependency graph |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/policy/{type}/dependentPolicies` | `Policy.GetDependentPoliciesGETAdminRealmsRealmClientsClientUuidAuthzResourceServerPolicyTypeDependentPoliciesAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Dependent policy query follows persisted permission-to-user-policy edge |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/policy/{type}/providers` | `Policy.FindPolicyProvidersGETAdminRealmsRealmClientsClientUuidAuthzResourceServerPolicyTypeProvidersAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Provider-type listing/search/paging and provider discovery operate on real data |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/policy/{type}/resources` | `Policy.GetResourcesGETAdminRealmsRealmClientsClientUuidAuthzResourceServerPolicyTypeResourcesAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Policy ID lookup and resource/scope/associated-policy links reflect stored dependency graph |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/policy/{type}/scopes` | `Policy.GetScopesGETAdminRealmsRealmClientsClientUuidAuthzResourceServerPolicyTypeScopesAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Policy ID lookup and resource/scope/associated-policy links reflect stored dependency graph |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/policy/{type}/search` | `Policy.FindByNameGETAdminRealmsRealmClientsClientUuidAuthzResourceServerPolicyTypeSearchAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Provider-type listing/search/paging and provider discovery operate on real data |
| DELETE | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/policy/{type}/{policy-id}` | `Policy.DeleteDELETEAdminRealmsRealmClientsClientUuidAuthzResourceServerPolicyTypePolicyIdAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Typed policy deletion removes persisted permission |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/policy/{type}/{policy-id}` | `Policy.FindByIdGETAdminRealmsRealmClientsClientUuidAuthzResourceServerPolicyTypePolicyIdAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Policy update persists through root or provider-specific ID route |
| PUT | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/policy/{type}/{policy-id}` | `Policy.UpdatePUTAdminRealmsRealmClientsClientUuidAuthzResourceServerPolicyTypePolicyIdAsync` | 通过 201 | 通过 201 | 通过 201 | 通过 201 | Policy update persists through root or provider-specific ID route |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/policy/{type}/{policy-id}/associatedPolicies` | `Policy.GetAssociatedPoliciesGETAdminRealmsRealmClientsClientUuidAuthzResourceServerPolicyTypePolicyIdAssociatedPoliciesAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Policy ID lookup and resource/scope/associated-policy links reflect stored dependency graph |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/policy/{type}/{policy-id}/dependentPolicies` | `Policy.GetDependentPoliciesGETAdminRealmsRealmClientsClientUuidAuthzResourceServerPolicyTypePolicyIdDependentPoliciesAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Provider-specific dependent-policy lookup follows persisted edge |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/policy/{type}/{policy-id}/resources` | `Policy.GetResourcesGETAdminRealmsRealmClientsClientUuidAuthzResourceServerPolicyTypePolicyIdResourcesAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Policy ID lookup and resource/scope/associated-policy links reflect stored dependency graph |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/policy/{type}/{policy-id}/scopes` | `Policy.GetScopesGETAdminRealmsRealmClientsClientUuidAuthzResourceServerPolicyTypePolicyIdScopesAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Policy ID lookup and resource/scope/associated-policy links reflect stored dependency graph |

### PolicyEvaluation（4 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| POST | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/permission/evaluate` | `PolicyEvaluation.EvaluateAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Changing persisted user-policy logic from POSITIVE to NEGATIVE changes real authorization result from PERMIT to DENY |
| POST | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/permission/{type}/evaluate` | `PolicyEvaluation.EvaluatePOSTAdminRealmsRealmClientsClientUuidAuthzResourceServerPermissionTypeEvaluateAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Authorization engine evaluates persisted user/resource/scope policies as PERMIT |
| POST | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/policy/evaluate` | `PolicyEvaluation.EvaluatePOSTAdminRealmsRealmClientsClientUuidAuthzResourceServerPolicyEvaluateAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Authorization engine evaluates persisted user/resource/scope policies as PERMIT |
| POST | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/policy/{type}/evaluate` | `PolicyEvaluation.EvaluatePOSTAdminRealmsRealmClientsClientUuidAuthzResourceServerPolicyTypeEvaluateAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Authorization engine evaluates persisted user/resource/scope policies as PERMIT |

### ProtocolMappers（21 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| POST | `/admin/realms/{realm}/client-scopes/{client-scope-id}/protocol-mappers/add-models` | `ProtocolMappers.CreateMapperAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Bulk mapper creation persists both model definitions |
| GET | `/admin/realms/{realm}/client-scopes/{client-scope-id}/protocol-mappers/models` | `ProtocolMappers.GetMappersAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Mapper deletion removes only selected persisted model |
| POST | `/admin/realms/{realm}/client-scopes/{client-scope-id}/protocol-mappers/models` | `ProtocolMappers.CreateMapperPOSTAdminRealmsRealmClientScopesClientScopeIdProtocolMappersModelsAsync` | 通过 201 | 通过 201 | 通过 201 | 通过 201 | Protocol mapper creation persists and is visible through ID/list/protocol queries: client-scopes/{client-scope-id} |
| DELETE | `/admin/realms/{realm}/client-scopes/{client-scope-id}/protocol-mappers/models/{id}` | `ProtocolMappers.DeleteAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Mapper deletion removes only selected persisted model |
| GET | `/admin/realms/{realm}/client-scopes/{client-scope-id}/protocol-mappers/models/{id}` | `ProtocolMappers.GetMapperByIdAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Protocol mapper update changes stored claim configuration |
| PUT | `/admin/realms/{realm}/client-scopes/{client-scope-id}/protocol-mappers/models/{id}` | `ProtocolMappers.UpdateAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Protocol mapper update changes stored claim configuration |
| GET | `/admin/realms/{realm}/client-scopes/{client-scope-id}/protocol-mappers/protocol/{protocol}` | `ProtocolMappers.GetMappersPerProtocolAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Protocol mapper creation persists and is visible through ID/list/protocol queries: client-scopes/{client-scope-id} |
| POST | `/admin/realms/{realm}/client-templates/{client-scope-id}/protocol-mappers/add-models` | `ProtocolMappers.CreateMapperPOSTAdminRealmsRealmClientTemplatesClientScopeIdProtocolMappersAddModelsAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Bulk mapper creation persists both model definitions |
| GET | `/admin/realms/{realm}/client-templates/{client-scope-id}/protocol-mappers/models` | `ProtocolMappers.GetMappersGETAdminRealmsRealmClientTemplatesClientScopeIdProtocolMappersModelsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Mapper deletion removes only selected persisted model |
| POST | `/admin/realms/{realm}/client-templates/{client-scope-id}/protocol-mappers/models` | `ProtocolMappers.CreateMapperPOSTAdminRealmsRealmClientTemplatesClientScopeIdProtocolMappersModelsAsync` | 通过 201 | 通过 201 | 通过 201 | 通过 201 | Protocol mapper creation persists and is visible through ID/list/protocol queries: client-templates/{client-scope-id} |
| DELETE | `/admin/realms/{realm}/client-templates/{client-scope-id}/protocol-mappers/models/{id}` | `ProtocolMappers.DeleteDELETEAdminRealmsRealmClientTemplatesClientScopeIdProtocolMappersModelsIdAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Mapper deletion removes only selected persisted model |
| GET | `/admin/realms/{realm}/client-templates/{client-scope-id}/protocol-mappers/models/{id}` | `ProtocolMappers.GetMapperByIdGETAdminRealmsRealmClientTemplatesClientScopeIdProtocolMappersModelsIdAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Protocol mapper update changes stored claim configuration |
| PUT | `/admin/realms/{realm}/client-templates/{client-scope-id}/protocol-mappers/models/{id}` | `ProtocolMappers.UpdatePUTAdminRealmsRealmClientTemplatesClientScopeIdProtocolMappersModelsIdAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Protocol mapper update changes stored claim configuration |
| GET | `/admin/realms/{realm}/client-templates/{client-scope-id}/protocol-mappers/protocol/{protocol}` | `ProtocolMappers.GetMappersPerProtocolGETAdminRealmsRealmClientTemplatesClientScopeIdProtocolMappersProtocolProtocolAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Protocol mapper creation persists and is visible through ID/list/protocol queries: client-templates/{client-scope-id} |
| POST | `/admin/realms/{realm}/clients/{client-uuid}/protocol-mappers/add-models` | `ProtocolMappers.CreateMapperPOSTAdminRealmsRealmClientsClientUuidProtocolMappersAddModelsAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Bulk mapper creation persists both model definitions |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/protocol-mappers/models` | `ProtocolMappers.GetMappersGETAdminRealmsRealmClientsClientUuidProtocolMappersModelsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Mapper deletion removes only selected persisted model |
| POST | `/admin/realms/{realm}/clients/{client-uuid}/protocol-mappers/models` | `ProtocolMappers.CreateMapperPOSTAdminRealmsRealmClientsClientUuidProtocolMappersModelsAsync` | 通过 201 | 通过 201 | 通过 201 | 通过 201 | Protocol mapper creation persists and is visible through ID/list/protocol queries: clients/{client-uuid} |
| DELETE | `/admin/realms/{realm}/clients/{client-uuid}/protocol-mappers/models/{id}` | `ProtocolMappers.DeleteDELETEAdminRealmsRealmClientsClientUuidProtocolMappersModelsIdAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Mapper deletion removes only selected persisted model |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/protocol-mappers/models/{id}` | `ProtocolMappers.GetMapperByIdGETAdminRealmsRealmClientsClientUuidProtocolMappersModelsIdAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Protocol mapper update changes stored claim configuration |
| PUT | `/admin/realms/{realm}/clients/{client-uuid}/protocol-mappers/models/{id}` | `ProtocolMappers.UpdatePUTAdminRealmsRealmClientsClientUuidProtocolMappersModelsIdAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Protocol mapper update changes stored claim configuration |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/protocol-mappers/protocol/{protocol}` | `ProtocolMappers.GetMappersPerProtocolGETAdminRealmsRealmClientsClientUuidProtocolMappersProtocolProtocolAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Protocol mapper creation persists and is visible through ID/list/protocol queries: clients/{client-uuid} |

### RealmAdmin（30 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| DELETE | `/admin/realms/{realm}` | `RealmAdmin.DeleteRealmAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Deleting the isolated realm removes its persisted state |
| GET | `/admin/realms/{realm}` | `RealmAdmin.GetRealmAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Clearing realm cache exposes actual out-of-band PostgreSQL mutation |
| PUT | `/admin/realms/{realm}` | `RealmAdmin.UpdateRealmAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Realm configuration writes change persisted fields |
| DELETE | `/admin/realms/{realm}/admin-events` | `RealmAdmin.ClearAdminEventsAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Deleting admin events removes preceding mutation history |
| GET | `/admin/realms/{realm}/admin-events` | `RealmAdmin.GetEventsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Deleting admin events removes preceding mutation history |
| POST | `/admin/realms/{realm}/client-description-converter` | `RealmAdmin.ConvertClientDescriptionAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | SAML metadata converter parses actual entity ID, protocol and assertion consumer URL |
| GET | `/admin/realms/{realm}/client-session-stats` | `RealmAdmin.GetClientSessionStatsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Real password grant creates persisted user/client session and counted client statistics |
| GET | `/admin/realms/{realm}/credential-registrators` | `RealmAdmin.GetCredentialRegistratorsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Credential registrar discovery contains installed WebAuthn provider |
| GET | `/admin/realms/{realm}/default-default-client-scopes` | `RealmAdmin.GetDefaultDefaultClientScopesAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Realm default scope relationship removed: default-default-client-scopes |
| DELETE | `/admin/realms/{realm}/default-default-client-scopes/{clientScopeId}` | `RealmAdmin.RemoveDefaultDefaultClientScopeAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Realm default scope relationship removed: default-default-client-scopes |
| PUT | `/admin/realms/{realm}/default-default-client-scopes/{clientScopeId}` | `RealmAdmin.AddDefaultDefaultClientScopeAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Realm default scope relationship persisted: default-default-client-scopes |
| GET | `/admin/realms/{realm}/default-groups` | `RealmAdmin.GetDefaultGroupsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Removing default group changes realm assignment |
| DELETE | `/admin/realms/{realm}/default-groups/{groupId}` | `RealmAdmin.RemoveDefaultGroupAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Removing default group changes realm assignment |
| PUT | `/admin/realms/{realm}/default-groups/{groupId}` | `RealmAdmin.AddDefaultGroupAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Realm default group assignment persisted |
| GET | `/admin/realms/{realm}/default-optional-client-scopes` | `RealmAdmin.GetDefaultOptionalClientScopesAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Realm default scope relationship removed: default-optional-client-scopes |
| DELETE | `/admin/realms/{realm}/default-optional-client-scopes/{clientScopeId}` | `RealmAdmin.RemoveDefaultOptionalClientScopeAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Realm default scope relationship removed: default-optional-client-scopes |
| PUT | `/admin/realms/{realm}/default-optional-client-scopes/{clientScopeId}` | `RealmAdmin.AddDefaultOptionalClientScopeAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Realm default scope relationship persisted: default-optional-client-scopes |
| DELETE | `/admin/realms/{realm}/events` | `RealmAdmin.ClearEventsAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Deleting events removes persisted login history |
| GET | `/admin/realms/{realm}/events` | `RealmAdmin.GetEventsGETAdminRealmsRealmEventsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Deleting events removes persisted login history |
| GET | `/admin/realms/{realm}/events/config` | `RealmAdmin.GetRealmEventsConfigAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Event configuration persists retention and enabled event types |
| PUT | `/admin/realms/{realm}/events/config` | `RealmAdmin.UpdateRealmEventsConfigAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Event configuration persists retention and enabled event types |
| GET | `/admin/realms/{realm}/group-by-path/{path}` | `RealmAdmin.GetGroupByPathAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Nested group path resolves actual persisted child |
| POST | `/admin/realms/{realm}/logout-all` | `RealmAdmin.LogoutAllAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Realm logout-all removes existing user sessions |
| POST | `/admin/realms/{realm}/partial-export` | `RealmAdmin.PartialExportAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Partial export contains imported client, group and realm role |
| POST | `/admin/realms/{realm}/partialImport` | `RealmAdmin.PartialImportAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Partial import persists all four real resource kinds with added count |
| POST | `/admin/realms/{realm}/push-revocation` | `RealmAdmin.PushRevocationAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Realm revocation reaches configured client adapter |
| DELETE | `/admin/realms/{realm}/sessions/{session}` | `RealmAdmin.DeleteSessionAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Deleting session removes selected persisted user session |
| POST | `/admin/realms/{realm}/testSMTPConnection` | `RealmAdmin.TestSMTPConnectionAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | JSON and form SMTP tests deliver actual messages to authenticated admin |
| GET | `/admin/realms/{realm}/users-management-permissions` | `RealmAdmin.GetUserMgmtPermissionsAsync` | 政策排除 | 政策排除 | 通过 200 | 通过 200 | Disabling legacy permissions changes persisted state: users-management-permissions |
| PUT | `/admin/realms/{realm}/users-management-permissions` | `RealmAdmin.SetUsersManagementPermissionsEnabledAsync` | 政策排除 | 政策排除 | 通过 200 | 通过 200 | Disabling legacy permissions changes persisted state: users-management-permissions |

### RealmLocalization（7 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GET | `/admin/realms/{realm}/localization` | `RealmLocalization.GetRealmLocalizationLocalesAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Locale enumeration reflects persisted translations |
| DELETE | `/admin/realms/{realm}/localization/{locale}` | `RealmLocalization.DeleteRealmLocalizationTextsAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Locale deletion removes all persisted translations |
| GET | `/admin/realms/{realm}/localization/{locale}` | `RealmLocalization.GetRealmLocalizationTextsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Multipart localization import persists UTF8 message |
| POST | `/admin/realms/{realm}/localization/{locale}` | `RealmLocalization.CreateOrUpdateRealmLocalizationTextsFromFileAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Multipart localization import persists UTF8 message |
| DELETE | `/admin/realms/{realm}/localization/{locale}/{key}` | `RealmLocalization.DeleteRealmLocalizationTextAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Deleting a localization key preserves its sibling |
| GET | `/admin/realms/{realm}/localization/{locale}/{key}` | `RealmLocalization.GetRealmLocalizationTextAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Localization key write is readable |
| PUT | `/admin/realms/{realm}/localization/{locale}/{key}` | `RealmLocalization.SaveRealmLocalizationTextAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Localization key write is readable |

### RealmsAdmin（2 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GET | `/admin/realms` | `RealmsAdmin.GetRealmsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Realm listing includes the newly persisted realm |
| POST | `/admin/realms` | `RealmsAdmin.ImportRealmAsync` | 通过 201 | 通过 201 | 通过 201 | 通过 201 | Created realm is persisted and readable by its unique name |

### RoleById（10 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| DELETE | `/admin/realms/{realm}/roles-by-id/{role-id}` | `RoleById.DeleteRoleAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Role deletion by ID removes persisted role |
| GET | `/admin/realms/{realm}/roles-by-id/{role-id}` | `RoleById.GetRoleAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Role-by-ID update persists |
| PUT | `/admin/realms/{realm}/roles-by-id/{role-id}` | `RoleById.UpdateRoleAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Role-by-ID update persists |
| DELETE | `/admin/realms/{realm}/roles-by-id/{role-id}/composites` | `RoleById.DeleteCompositesAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Role-by-ID composite deletion removes persisted children |
| GET | `/admin/realms/{realm}/roles-by-id/{role-id}/composites` | `RoleById.GetRoleCompositesAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Role-by-ID composite deletion removes persisted children |
| POST | `/admin/realms/{realm}/roles-by-id/{role-id}/composites` | `RoleById.AddCompositesAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Role-by-ID composite filters expose actual child roles |
| GET | `/admin/realms/{realm}/roles-by-id/{role-id}/composites/clients/{clientUuid}` | `RoleById.GetClientRoleCompositesAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Role-by-ID composite filters expose actual child roles |
| GET | `/admin/realms/{realm}/roles-by-id/{role-id}/composites/realm` | `RoleById.GetRealmRoleCompositesAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Role-by-ID composite filters expose actual child roles |
| GET | `/admin/realms/{realm}/roles-by-id/{role-id}/management/permissions` | `RoleById.GetManagementPermissionsAsync` | 政策排除 | 政策排除 | 通过 200 | 通过 200 | Disabling legacy permissions changes persisted state: roles-by-id/{role-id}/management/permissions |
| PUT | `/admin/realms/{realm}/roles-by-id/{role-id}/management/permissions` | `RoleById.SetManagementPermissionsEnabledAsync` | 政策排除 | 政策排除 | 通过 200 | 通过 200 | Disabling legacy permissions changes persisted state: roles-by-id/{role-id}/management/permissions |

### RoleContainer（28 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/roles` | `RoleContainer.GetRolesAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Role listing contains newly created role |
| POST | `/admin/realms/{realm}/clients/{client-uuid}/roles` | `RoleContainer.CreateRoleAsync` | 通过 201 | 通过 201 | 通过 201 | 通过 201 | Role creation persists a unique role and ID |
| DELETE | `/admin/realms/{realm}/clients/{client-uuid}/roles/{role-name}` | `RoleContainer.DeleteRoleAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Role deletion by name removes persisted role |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/roles/{role-name}` | `RoleContainer.GetRoleAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Role update changes persisted description |
| PUT | `/admin/realms/{realm}/clients/{client-uuid}/roles/{role-name}` | `RoleContainer.UpdateRoleAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Role update changes persisted description |
| DELETE | `/admin/realms/{realm}/clients/{client-uuid}/roles/{role-name}/composites` | `RoleContainer.DeleteCompositesAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Removing composites removes both child role relationships |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/roles/{role-name}/composites` | `RoleContainer.GetRoleCompositesAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Removing composites removes both child role relationships |
| POST | `/admin/realms/{realm}/clients/{client-uuid}/roles/{role-name}/composites` | `RoleContainer.AddCompositesAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Composite role writes and realm/client filters reflect real child relationships |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/roles/{role-name}/composites/clients/{targetClientUuid}` | `RoleContainer.GetClientRoleCompositesAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Composite role writes and realm/client filters reflect real child relationships |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/roles/{role-name}/composites/realm` | `RoleContainer.GetRealmRoleCompositesAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Composite role writes and realm/client filters reflect real child relationships |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/roles/{role-name}/groups` | `RoleContainer.GetGroupsInRoleAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Role-centric member listing reflects assigned user/group |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/roles/{role-name}/management/permissions` | `RoleContainer.GetManagementPermissionsAsync` | 政策排除 | 政策排除 | 通过 200 | 通过 200 | Disabling legacy permissions changes persisted state: clients/{client-uuid}/roles/{role-name}/management/permissions |
| PUT | `/admin/realms/{realm}/clients/{client-uuid}/roles/{role-name}/management/permissions` | `RoleContainer.SetManagementPermissionsEnabledAsync` | 政策排除 | 政策排除 | 通过 200 | 通过 200 | Disabling legacy permissions changes persisted state: clients/{client-uuid}/roles/{role-name}/management/permissions |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/roles/{role-name}/users` | `RoleContainer.GetUsersInRoleAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Role-centric member listing reflects assigned user/group |
| GET | `/admin/realms/{realm}/roles` | `RoleContainer.GetRolesGETAdminRealmsRealmRolesAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Role listing contains newly created role |
| POST | `/admin/realms/{realm}/roles` | `RoleContainer.CreateRolePOSTAdminRealmsRealmRolesAsync` | 通过 201 | 通过 201 | 通过 201 | 通过 201 | Role creation persists a unique role and ID |
| DELETE | `/admin/realms/{realm}/roles/{role-name}` | `RoleContainer.DeleteRoleDELETEAdminRealmsRealmRolesRoleNameAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Role deletion by name removes persisted role |
| GET | `/admin/realms/{realm}/roles/{role-name}` | `RoleContainer.GetRoleGETAdminRealmsRealmRolesRoleNameAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Role update changes persisted description |
| PUT | `/admin/realms/{realm}/roles/{role-name}` | `RoleContainer.UpdateRolePUTAdminRealmsRealmRolesRoleNameAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Role update changes persisted description |
| DELETE | `/admin/realms/{realm}/roles/{role-name}/composites` | `RoleContainer.DeleteCompositesDELETEAdminRealmsRealmRolesRoleNameCompositesAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Removing composites removes both child role relationships |
| GET | `/admin/realms/{realm}/roles/{role-name}/composites` | `RoleContainer.GetRoleCompositesGETAdminRealmsRealmRolesRoleNameCompositesAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | UI bulk mapping deletion removes actual direct client role for roles |
| POST | `/admin/realms/{realm}/roles/{role-name}/composites` | `RoleContainer.AddCompositesPOSTAdminRealmsRealmRolesRoleNameCompositesAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Composite role writes and realm/client filters reflect real child relationships |
| GET | `/admin/realms/{realm}/roles/{role-name}/composites/clients/{targetClientUuid}` | `RoleContainer.GetClientRoleCompositesGETAdminRealmsRealmRolesRoleNameCompositesClientsTargetClientUuidAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Composite role writes and realm/client filters reflect real child relationships |
| GET | `/admin/realms/{realm}/roles/{role-name}/composites/realm` | `RoleContainer.GetRealmRoleCompositesGETAdminRealmsRealmRolesRoleNameCompositesRealmAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Composite role writes and realm/client filters reflect real child relationships |
| GET | `/admin/realms/{realm}/roles/{role-name}/groups` | `RoleContainer.GetGroupsInRoleGETAdminRealmsRealmRolesRoleNameGroupsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Role-centric member listing reflects assigned user/group |
| GET | `/admin/realms/{realm}/roles/{role-name}/management/permissions` | `RoleContainer.GetManagementPermissionsGETAdminRealmsRealmRolesRoleNameManagementPermissionsAsync` | 政策排除 | 政策排除 | 通过 200 | 通过 200 | Disabling legacy permissions changes persisted state: roles/{role-name}/management/permissions |
| PUT | `/admin/realms/{realm}/roles/{role-name}/management/permissions` | `RoleContainer.SetManagementPermissionsEnabledPUTAdminRealmsRealmRolesRoleNameManagementPermissionsAsync` | 政策排除 | 政策排除 | 通过 200 | 通过 200 | Disabling legacy permissions changes persisted state: roles/{role-name}/management/permissions |
| GET | `/admin/realms/{realm}/roles/{role-name}/users` | `RoleContainer.GetUsersInRoleGETAdminRealmsRealmRolesRoleNameUsersAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Role-centric member listing reflects assigned user/group |

### RoleMapper（18 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GET | `/admin/realms/{realm}/groups/{group-id}/role-mappings` | `RoleMapper.GetRoleMappingsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Assigned roles and effective composite mappings persist: groups/{group-id}/role-mappings |
| DELETE | `/admin/realms/{realm}/groups/{group-id}/role-mappings/realm` | `RoleMapper.DeleteRealmRoleMappingsAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Deleting mappings removes direct role relationships: groups/{group-id}/role-mappings |
| GET | `/admin/realms/{realm}/groups/{group-id}/role-mappings/realm` | `RoleMapper.GetRealmRoleMappingsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Deleting mappings removes direct role relationships: groups/{group-id}/role-mappings |
| POST | `/admin/realms/{realm}/groups/{group-id}/role-mappings/realm` | `RoleMapper.AddRealmRoleMappingsAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Assigned roles and effective composite mappings persist: groups/{group-id}/role-mappings |
| GET | `/admin/realms/{realm}/groups/{group-id}/role-mappings/realm/available` | `RoleMapper.GetAvailableRealmRoleMappingsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Available mappings contain unassigned real realm and client roles: groups/{group-id}/role-mappings |
| GET | `/admin/realms/{realm}/groups/{group-id}/role-mappings/realm/composite` | `RoleMapper.GetCompositeRealmRoleMappingsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Assigned roles and effective composite mappings persist: groups/{group-id}/role-mappings |
| GET | `/admin/realms/{realm}/organizations/{org-id}/groups/{group-id}/role-mappings` | `RoleMapper.GetRoleMappingsGETAdminRealmsRealmOrganizationsOrgIdGroupsGroupIdRoleMappingsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Assigned roles and effective composite mappings persist: organizations/{org-id}/groups/{group-id}/role-mappings |
| DELETE | `/admin/realms/{realm}/organizations/{org-id}/groups/{group-id}/role-mappings/realm` | `RoleMapper.DeleteRealmRoleMappingsDELETEAdminRealmsRealmOrganizationsOrgIdGroupsGroupIdRoleMappingsRealmAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Deleting mappings removes direct role relationships: organizations/{org-id}/groups/{group-id}/role-mappings |
| GET | `/admin/realms/{realm}/organizations/{org-id}/groups/{group-id}/role-mappings/realm` | `RoleMapper.GetRealmRoleMappingsGETAdminRealmsRealmOrganizationsOrgIdGroupsGroupIdRoleMappingsRealmAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Deleting mappings removes direct role relationships: organizations/{org-id}/groups/{group-id}/role-mappings |
| POST | `/admin/realms/{realm}/organizations/{org-id}/groups/{group-id}/role-mappings/realm` | `RoleMapper.AddRealmRoleMappingsPOSTAdminRealmsRealmOrganizationsOrgIdGroupsGroupIdRoleMappingsRealmAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Assigned roles and effective composite mappings persist: organizations/{org-id}/groups/{group-id}/role-mappings |
| GET | `/admin/realms/{realm}/organizations/{org-id}/groups/{group-id}/role-mappings/realm/available` | `RoleMapper.GetAvailableRealmRoleMappingsGETAdminRealmsRealmOrganizationsOrgIdGroupsGroupIdRoleMappingsRealmAvailableAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Available mappings contain unassigned real realm and client roles: organizations/{org-id}/groups/{group-id}/role-mappings |
| GET | `/admin/realms/{realm}/organizations/{org-id}/groups/{group-id}/role-mappings/realm/composite` | `RoleMapper.GetCompositeRealmRoleMappingsGETAdminRealmsRealmOrganizationsOrgIdGroupsGroupIdRoleMappingsRealmCompositeAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Assigned roles and effective composite mappings persist: organizations/{org-id}/groups/{group-id}/role-mappings |
| GET | `/admin/realms/{realm}/users/{user-id}/role-mappings` | `RoleMapper.GetRoleMappingsGETAdminRealmsRealmUsersUserIdRoleMappingsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Assigned roles and effective composite mappings persist: users/{user-id}/role-mappings |
| DELETE | `/admin/realms/{realm}/users/{user-id}/role-mappings/realm` | `RoleMapper.DeleteRealmRoleMappingsDELETEAdminRealmsRealmUsersUserIdRoleMappingsRealmAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Deleting mappings removes direct role relationships: users/{user-id}/role-mappings |
| GET | `/admin/realms/{realm}/users/{user-id}/role-mappings/realm` | `RoleMapper.GetRealmRoleMappingsGETAdminRealmsRealmUsersUserIdRoleMappingsRealmAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Deleting mappings removes direct role relationships: users/{user-id}/role-mappings |
| POST | `/admin/realms/{realm}/users/{user-id}/role-mappings/realm` | `RoleMapper.AddRealmRoleMappingsPOSTAdminRealmsRealmUsersUserIdRoleMappingsRealmAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Assigned roles and effective composite mappings persist: users/{user-id}/role-mappings |
| GET | `/admin/realms/{realm}/users/{user-id}/role-mappings/realm/available` | `RoleMapper.GetAvailableRealmRoleMappingsGETAdminRealmsRealmUsersUserIdRoleMappingsRealmAvailableAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Available mappings contain unassigned real realm and client roles: users/{user-id}/role-mappings |
| GET | `/admin/realms/{realm}/users/{user-id}/role-mappings/realm/composite` | `RoleMapper.GetCompositeRealmRoleMappingsGETAdminRealmsRealmUsersUserIdRoleMappingsRealmCompositeAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Assigned roles and effective composite mappings persist: users/{user-id}/role-mappings |

### Scope（8 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/scope` | `Scope.FindAllAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Authorization scope persists and exact search returns its single model |
| POST | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/scope` | `Scope.CreateAsync` | 通过 201 | 通过 201 | 通过 201 | 通过 201 | Authorization scope persists and exact search returns its single model |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/scope/search` | `Scope.FindAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Authorization scope persists and exact search returns its single model |
| DELETE | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/scope/{scope-id}` | `Scope.DeleteAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Scope deletion persists |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/scope/{scope-id}` | `Scope.FindByIdAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Scope update persists display name |
| PUT | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/scope/{scope-id}` | `Scope.UpdateAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Scope update persists display name |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/scope/{scope-id}/permissions` | `Scope.GetPermissionsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Resource and scope permission queries reflect actual linked permissions |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/scope/{scope-id}/resources` | `Scope.GetResourcesAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Resource CRUD/search/attributes and bidirectional scope relationship persist |

### ScopeMapped（18 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GET | `/admin/realms/{realm}/client-scopes/{client-scope-id}/scope-mappings` | `ScopeMapped.GetScopeMappingsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Assigned roles and effective composite mappings persist: client-scopes/{client-scope-id}/scope-mappings |
| DELETE | `/admin/realms/{realm}/client-scopes/{client-scope-id}/scope-mappings/realm` | `ScopeMapped.DeleteRealmScopeMappingsAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Deleting mappings removes direct role relationships: client-scopes/{client-scope-id}/scope-mappings |
| GET | `/admin/realms/{realm}/client-scopes/{client-scope-id}/scope-mappings/realm` | `ScopeMapped.GetRealmScopeMappingsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Deleting mappings removes direct role relationships: client-scopes/{client-scope-id}/scope-mappings |
| POST | `/admin/realms/{realm}/client-scopes/{client-scope-id}/scope-mappings/realm` | `ScopeMapped.AddRealmScopeMappingsAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Assigned roles and effective composite mappings persist: client-scopes/{client-scope-id}/scope-mappings |
| GET | `/admin/realms/{realm}/client-scopes/{client-scope-id}/scope-mappings/realm/available` | `ScopeMapped.GetAvailableRealmScopeMappingsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Available mappings contain unassigned real realm and client roles: client-scopes/{client-scope-id}/scope-mappings |
| GET | `/admin/realms/{realm}/client-scopes/{client-scope-id}/scope-mappings/realm/composite` | `ScopeMapped.GetCompositeRealmScopeMappingsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Assigned roles and effective composite mappings persist: client-scopes/{client-scope-id}/scope-mappings |
| GET | `/admin/realms/{realm}/client-templates/{client-scope-id}/scope-mappings` | `ScopeMapped.GetScopeMappingsGETAdminRealmsRealmClientTemplatesClientScopeIdScopeMappingsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Assigned roles and effective composite mappings persist: client-templates/{client-scope-id}/scope-mappings |
| DELETE | `/admin/realms/{realm}/client-templates/{client-scope-id}/scope-mappings/realm` | `ScopeMapped.DeleteRealmScopeMappingsDELETEAdminRealmsRealmClientTemplatesClientScopeIdScopeMappingsRealmAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Deleting mappings removes direct role relationships: client-templates/{client-scope-id}/scope-mappings |
| GET | `/admin/realms/{realm}/client-templates/{client-scope-id}/scope-mappings/realm` | `ScopeMapped.GetRealmScopeMappingsGETAdminRealmsRealmClientTemplatesClientScopeIdScopeMappingsRealmAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Deleting mappings removes direct role relationships: client-templates/{client-scope-id}/scope-mappings |
| POST | `/admin/realms/{realm}/client-templates/{client-scope-id}/scope-mappings/realm` | `ScopeMapped.AddRealmScopeMappingsPOSTAdminRealmsRealmClientTemplatesClientScopeIdScopeMappingsRealmAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Assigned roles and effective composite mappings persist: client-templates/{client-scope-id}/scope-mappings |
| GET | `/admin/realms/{realm}/client-templates/{client-scope-id}/scope-mappings/realm/available` | `ScopeMapped.GetAvailableRealmScopeMappingsGETAdminRealmsRealmClientTemplatesClientScopeIdScopeMappingsRealmAvailableAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Available mappings contain unassigned real realm and client roles: client-templates/{client-scope-id}/scope-mappings |
| GET | `/admin/realms/{realm}/client-templates/{client-scope-id}/scope-mappings/realm/composite` | `ScopeMapped.GetCompositeRealmScopeMappingsGETAdminRealmsRealmClientTemplatesClientScopeIdScopeMappingsRealmCompositeAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Assigned roles and effective composite mappings persist: client-templates/{client-scope-id}/scope-mappings |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/scope-mappings` | `ScopeMapped.GetScopeMappingsGETAdminRealmsRealmClientsClientUuidScopeMappingsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Assigned roles and effective composite mappings persist: clients/{client-uuid}/scope-mappings |
| DELETE | `/admin/realms/{realm}/clients/{client-uuid}/scope-mappings/realm` | `ScopeMapped.DeleteRealmScopeMappingsDELETEAdminRealmsRealmClientsClientUuidScopeMappingsRealmAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Deleting mappings removes direct role relationships: clients/{client-uuid}/scope-mappings |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/scope-mappings/realm` | `ScopeMapped.GetRealmScopeMappingsGETAdminRealmsRealmClientsClientUuidScopeMappingsRealmAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Deleting mappings removes direct role relationships: clients/{client-uuid}/scope-mappings |
| POST | `/admin/realms/{realm}/clients/{client-uuid}/scope-mappings/realm` | `ScopeMapped.AddRealmScopeMappingsPOSTAdminRealmsRealmClientsClientUuidScopeMappingsRealmAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Assigned roles and effective composite mappings persist: clients/{client-uuid}/scope-mappings |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/scope-mappings/realm/available` | `ScopeMapped.GetAvailableRealmScopeMappingsGETAdminRealmsRealmClientsClientUuidScopeMappingsRealmAvailableAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Available mappings contain unassigned real realm and client roles: clients/{client-uuid}/scope-mappings |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/scope-mappings/realm/composite` | `ScopeMapped.GetCompositeRealmScopeMappingsGETAdminRealmsRealmClientsClientUuidScopeMappingsRealmCompositeAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Assigned roles and effective composite mappings persist: clients/{client-uuid}/scope-mappings |

### ScopeMappedClient（15 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| DELETE | `/admin/realms/{realm}/client-scopes/{client-scope-id}/scope-mappings/clients/{client}` | `ScopeMappedClient.DeleteClientScopeMappingAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Deleting mappings removes direct role relationships: client-scopes/{client-scope-id}/scope-mappings |
| GET | `/admin/realms/{realm}/client-scopes/{client-scope-id}/scope-mappings/clients/{client}` | `ScopeMappedClient.GetClientScopeMappingsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | UI bulk mapping deletion removes actual direct client role for clientScopes |
| POST | `/admin/realms/{realm}/client-scopes/{client-scope-id}/scope-mappings/clients/{client}` | `ScopeMappedClient.AddClientScopeMappingAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Assigned roles and effective composite mappings persist: client-scopes/{client-scope-id}/scope-mappings |
| GET | `/admin/realms/{realm}/client-scopes/{client-scope-id}/scope-mappings/clients/{client}/available` | `ScopeMappedClient.GetAvailableClientScopeMappingsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Available mappings contain unassigned real realm and client roles: client-scopes/{client-scope-id}/scope-mappings |
| GET | `/admin/realms/{realm}/client-scopes/{client-scope-id}/scope-mappings/clients/{client}/composite` | `ScopeMappedClient.GetCompositeClientScopeMappingsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Assigned roles and effective composite mappings persist: client-scopes/{client-scope-id}/scope-mappings |
| DELETE | `/admin/realms/{realm}/client-templates/{client-scope-id}/scope-mappings/clients/{client}` | `ScopeMappedClient.DeleteClientScopeMappingDELETEAdminRealmsRealmClientTemplatesClientScopeIdScopeMappingsClientsClientAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Deleting mappings removes direct role relationships: client-templates/{client-scope-id}/scope-mappings |
| GET | `/admin/realms/{realm}/client-templates/{client-scope-id}/scope-mappings/clients/{client}` | `ScopeMappedClient.GetClientScopeMappingsGETAdminRealmsRealmClientTemplatesClientScopeIdScopeMappingsClientsClientAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Deleting mappings removes direct role relationships: client-templates/{client-scope-id}/scope-mappings |
| POST | `/admin/realms/{realm}/client-templates/{client-scope-id}/scope-mappings/clients/{client}` | `ScopeMappedClient.AddClientScopeMappingPOSTAdminRealmsRealmClientTemplatesClientScopeIdScopeMappingsClientsClientAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Assigned roles and effective composite mappings persist: client-templates/{client-scope-id}/scope-mappings |
| GET | `/admin/realms/{realm}/client-templates/{client-scope-id}/scope-mappings/clients/{client}/available` | `ScopeMappedClient.GetAvailableClientScopeMappingsGETAdminRealmsRealmClientTemplatesClientScopeIdScopeMappingsClientsClientAvailableAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Available mappings contain unassigned real realm and client roles: client-templates/{client-scope-id}/scope-mappings |
| GET | `/admin/realms/{realm}/client-templates/{client-scope-id}/scope-mappings/clients/{client}/composite` | `ScopeMappedClient.GetCompositeClientScopeMappingsGETAdminRealmsRealmClientTemplatesClientScopeIdScopeMappingsClientsClientCompositeAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Assigned roles and effective composite mappings persist: client-templates/{client-scope-id}/scope-mappings |
| DELETE | `/admin/realms/{realm}/clients/{client-uuid}/scope-mappings/clients/{client}` | `ScopeMappedClient.DeleteClientScopeMappingDELETEAdminRealmsRealmClientsClientUuidScopeMappingsClientsClientAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Deleting mappings removes direct role relationships: clients/{client-uuid}/scope-mappings |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/scope-mappings/clients/{client}` | `ScopeMappedClient.GetClientScopeMappingsGETAdminRealmsRealmClientsClientUuidScopeMappingsClientsClientAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | UI bulk mapping deletion removes actual direct client role for clients |
| POST | `/admin/realms/{realm}/clients/{client-uuid}/scope-mappings/clients/{client}` | `ScopeMappedClient.AddClientScopeMappingPOSTAdminRealmsRealmClientsClientUuidScopeMappingsClientsClientAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Assigned roles and effective composite mappings persist: clients/{client-uuid}/scope-mappings |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/scope-mappings/clients/{client}/available` | `ScopeMappedClient.GetAvailableClientScopeMappingsGETAdminRealmsRealmClientsClientUuidScopeMappingsClientsClientAvailableAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Available mappings contain unassigned real realm and client roles: clients/{client-uuid}/scope-mappings |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/scope-mappings/clients/{client}/composite` | `ScopeMappedClient.GetCompositeClientScopeMappingsGETAdminRealmsRealmClientsClientUuidScopeMappingsClientsClientCompositeAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Assigned roles and effective composite mappings persist: clients/{client-uuid}/scope-mappings |

### Server（4 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server` | `Server.FindByIdAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | FGAP v2 uses the released admin-permissions authorization schema |
| PUT | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server` | `Server.UpdateAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Resource-server policy mode change persists |
| POST | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/import` | `Server.ImportSettingsAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Import changes persisted authorization resources |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/settings` | `Server.ExportSettingsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Portable settings export contains created resource/scope names (server strips internal IDs) |

### ServerInfoAdmin（1 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GET | `/admin/serverinfo` | `ServerInfoAdmin.GetInfoAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Authenticated serverinfo reports actual pinned server version |

### Set（9 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/resource` | `Set.FindAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Import changes persisted authorization resources |
| POST | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/resource` | `Set.CreatePostAsync` | 通过 201 | 通过 201 | 通过 201 | 通过 201 | Resource CRUD/search/attributes and bidirectional scope relationship persist |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/resource/search` | `Set.FindGETAdminRealmsRealmClientsClientUuidAuthzResourceServerResourceSearchAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Resource CRUD/search/attributes and bidirectional scope relationship persist |
| DELETE | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/resource/{resource-id}` | `Set.DeleteAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Resource deletion persists |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/resource/{resource-id}` | `Set.FindByIdAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Resource update persists display name |
| PUT | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/resource/{resource-id}` | `Set.UpdateAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Resource update persists display name |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/resource/{resource-id}/attributes` | `Set.GetAttributesAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Resource CRUD/search/attributes and bidirectional scope relationship persist |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/resource/{resource-id}/permissions` | `Set.GetPermissionsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Resource and scope permission queries reflect actual linked permissions |
| GET | `/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/resource/{resource-id}/scopes` | `Set.GetScopesAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Resource CRUD/search/attributes and bidirectional scope relationship persist |

### SsfAdmin（19 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| DELETE | `/admin/realms/{realm}/ssf/clients/{clientId}/events` | `SsfAdmin.DeleteClientEventsAsync` | 政策排除 | 政策排除 | 政策排除 | 政策排除 | SSF：26.8.1 为 EXPERIMENTAL，按要求不做真实验收 |
| POST | `/admin/realms/{realm}/ssf/clients/{clientId}/events/emit` | `SsfAdmin.EmitEventAsync` | 政策排除 | 政策排除 | 政策排除 | 政策排除 | SSF：26.8.1 为 EXPERIMENTAL，按要求不做真实验收 |
| DELETE | `/admin/realms/{realm}/ssf/clients/{clientId}/events/queued` | `SsfAdmin.DeleteClientQueuedEventsAsync` | 政策排除 | 政策排除 | 政策排除 | 政策排除 | SSF：26.8.1 为 EXPERIMENTAL，按要求不做真实验收 |
| GET | `/admin/realms/{realm}/ssf/clients/{clientId}/events/stats` | `SsfAdmin.GetClientEventStatsAsync` | 政策排除 | 政策排除 | 政策排除 | 政策排除 | SSF：26.8.1 为 EXPERIMENTAL，按要求不做真实验收 |
| GET | `/admin/realms/{realm}/ssf/clients/{clientId}/pending-events/{jti}` | `SsfAdmin.GetPendingEventAsync` | 政策排除 | 政策排除 | 政策排除 | 政策排除 | SSF：26.8.1 为 EXPERIMENTAL，按要求不做真实验收 |
| DELETE | `/admin/realms/{realm}/ssf/clients/{clientId}/stream` | `SsfAdmin.DeleteClientStreamAsync` | 政策排除 | 政策排除 | 政策排除 | 政策排除 | SSF：26.8.1 为 EXPERIMENTAL，按要求不做真实验收 |
| GET | `/admin/realms/{realm}/ssf/clients/{clientId}/stream` | `SsfAdmin.GetClientStreamAsync` | 政策排除 | 政策排除 | 政策排除 | 政策排除 | SSF：26.8.1 为 EXPERIMENTAL，按要求不做真实验收 |
| PATCH | `/admin/realms/{realm}/ssf/clients/{clientId}/stream` | `SsfAdmin.UpdateClientStreamAsync` | 政策排除 | 政策排除 | 政策排除 | 政策排除 | SSF：26.8.1 为 EXPERIMENTAL，按要求不做真实验收 |
| POST | `/admin/realms/{realm}/ssf/clients/{clientId}/stream` | `SsfAdmin.CreateClientStreamAsync` | 政策排除 | 政策排除 | 政策排除 | 政策排除 | SSF：26.8.1 为 EXPERIMENTAL，按要求不做真实验收 |
| POST | `/admin/realms/{realm}/ssf/clients/{clientId}/stream/status` | `SsfAdmin.UpdateClientStreamStatusAsync` | 政策排除 | 政策排除 | 政策排除 | 政策排除 | SSF：26.8.1 为 EXPERIMENTAL，按要求不做真实验收 |
| POST | `/admin/realms/{realm}/ssf/clients/{clientId}/stream/verify` | `SsfAdmin.VerifyClientStreamAsync` | 政策排除 | 政策排除 | 政策排除 | 政策排除 | SSF：26.8.1 为 EXPERIMENTAL，按要求不做真实验收 |
| POST | `/admin/realms/{realm}/ssf/clients/{clientId}/subjects/add` | `SsfAdmin.AddSubjectAsync` | 政策排除 | 政策排除 | 政策排除 | 政策排除 | SSF：26.8.1 为 EXPERIMENTAL，按要求不做真实验收 |
| POST | `/admin/realms/{realm}/ssf/clients/{clientId}/subjects/check` | `SsfAdmin.CheckSubjectAsync` | 政策排除 | 政策排除 | 政策排除 | 政策排除 | SSF：26.8.1 为 EXPERIMENTAL，按要求不做真实验收 |
| POST | `/admin/realms/{realm}/ssf/clients/{clientId}/subjects/ignore` | `SsfAdmin.IgnoreSubjectAsync` | 政策排除 | 政策排除 | 政策排除 | 政策排除 | SSF：26.8.1 为 EXPERIMENTAL，按要求不做真实验收 |
| POST | `/admin/realms/{realm}/ssf/clients/{clientId}/subjects/remove` | `SsfAdmin.RemoveSubjectAsync` | 政策排除 | 政策排除 | 政策排除 | 政策排除 | SSF：26.8.1 为 EXPERIMENTAL，按要求不做真实验收 |
| GET | `/admin/realms/{realm}/ssf/config` | `SsfAdmin.GetConfigAsync` | 政策排除 | 政策排除 | 政策排除 | 政策排除 | SSF：26.8.1 为 EXPERIMENTAL，按要求不做真实验收 |
| DELETE | `/admin/realms/{realm}/ssf/events` | `SsfAdmin.DeleteEventsAsync` | 政策排除 | 政策排除 | 政策排除 | 政策排除 | SSF：26.8.1 为 EXPERIMENTAL，按要求不做真实验收 |
| DELETE | `/admin/realms/{realm}/ssf/events/queued` | `SsfAdmin.DeleteQueuedEventsAsync` | 政策排除 | 政策排除 | 政策排除 | 政策排除 | SSF：26.8.1 为 EXPERIMENTAL，按要求不做真实验收 |
| GET | `/admin/realms/{realm}/ssf/events/stats` | `SsfAdmin.GetEventStatsAsync` | 政策排除 | 政策排除 | 政策排除 | 政策排除 | SSF：26.8.1 为 EXPERIMENTAL，按要求不做真实验收 |

### TestLdapConnection（1 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| POST | `/admin/realms/{realm}/testLDAPConnection` | `TestLdapConnection.TestLDAPConnectionAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Keycloak binds to actual OpenLDAP and discovers root-DSE supported capabilities |

### UiAllEffectiveRoleMapping（5 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GET | `/admin/realms/{realm}/ui-ext/effective-roles-all/clientScopes/{id}` | `UiAllEffectiveRoleMapping.ListAllEffectiveClientScopeRoleMappingsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | UI effective-role projections resolve actual composite child for clientScopes |
| GET | `/admin/realms/{realm}/ui-ext/effective-roles-all/clients/{id}` | `UiAllEffectiveRoleMapping.ListAllEffectiveClientsRoleMappingsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | UI effective-role projections resolve actual composite child for clients |
| GET | `/admin/realms/{realm}/ui-ext/effective-roles-all/groups/{id}` | `UiAllEffectiveRoleMapping.ListAllEffectiveGroupsRoleMappingsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | UI effective-role projections resolve actual composite child for groups |
| GET | `/admin/realms/{realm}/ui-ext/effective-roles-all/roles/{id}` | `UiAllEffectiveRoleMapping.ListAllEffectiveRealmRoleMappingsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | UI effective-role projections resolve actual composite child for roles (legacy endpoint uses realm default role in released source) |
| GET | `/admin/realms/{realm}/ui-ext/effective-roles-all/users/{id}` | `UiAllEffectiveRoleMapping.ListAllEffectiveUsersRoleMappingsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | UI effective-role projections resolve actual composite child for users |

### UiAuthenticationManagement（3 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GET | `/admin/realms/{realm}/ui-ext/authentication-management/flows` | `UiAuthenticationManagement.ListIdentityProvidersAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | UI authentication graph lists actual built-in browser flow |
| GET | `/admin/realms/{realm}/ui-ext/authentication-management/required-actions` | `UiAuthenticationManagement.GetRequiredActionsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | UI required actions contain configured password action |
| GET | `/admin/realms/{realm}/ui-ext/authentication-management/{type}/{id}` | `UiAuthenticationManagement.ListUsedAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | UI flow usage resolves real client binding override |

### UiAvailableEventListeners（1 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GET | `/admin/realms/{realm}/ui-ext/available-event-listeners/` | `UiAvailableEventListeners.ListAvailableEventListenersAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | UI event-listener discovery exposes installed logging listener |

### UiAvailableRoleMapping（5 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GET | `/admin/realms/{realm}/ui-ext/available-roles/clientScopes/{id}` | `UiAvailableRoleMapping.ListAvailableClientScopeRoleMappingsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | UI available-role search exposes removed client role for clientScopes |
| GET | `/admin/realms/{realm}/ui-ext/available-roles/clients/{id}` | `UiAvailableRoleMapping.ListAvailableClientRoleMappingsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | UI available-role search exposes removed client role for clients |
| GET | `/admin/realms/{realm}/ui-ext/available-roles/groups/{id}` | `UiAvailableRoleMapping.ListAvailableGroupRoleMappingsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | UI available-role search exposes removed client role for groups |
| GET | `/admin/realms/{realm}/ui-ext/available-roles/roles/{id}` | `UiAvailableRoleMapping.ListAvailableRoleMappingsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | UI available-role search exposes removed client role for roles |
| GET | `/admin/realms/{realm}/ui-ext/available-roles/users/{id}` | `UiAvailableRoleMapping.ListAvailableUserRoleMappingsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | UI available-role search exposes removed client role for users |

### UiBruteForceUsers（1 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GET | `/admin/realms/{realm}/ui-ext/brute-force-user` | `UiBruteForceUsers.SearchUserAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | UI brute-force search resolves actual failed-login user |

### UiEffectiveRoleMapping（5 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GET | `/admin/realms/{realm}/ui-ext/effective-roles/clientScopes/{id}` | `UiEffectiveRoleMapping.ListCompositeClientScopeRoleMappingsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | UI effective-role projections resolve actual composite child for clientScopes |
| GET | `/admin/realms/{realm}/ui-ext/effective-roles/clients/{id}` | `UiEffectiveRoleMapping.ListCompositeClientsRoleMappingsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | UI effective-role projections resolve actual composite child for clients |
| GET | `/admin/realms/{realm}/ui-ext/effective-roles/groups/{id}` | `UiEffectiveRoleMapping.ListCompositeGroupsRoleMappingsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | UI effective-role projections resolve actual composite child for groups |
| GET | `/admin/realms/{realm}/ui-ext/effective-roles/roles/{id}` | `UiEffectiveRoleMapping.ListCompositeRealmRoleMappingsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | UI effective-role projections resolve actual composite child for roles (legacy endpoint uses realm default role in released source) |
| GET | `/admin/realms/{realm}/ui-ext/effective-roles/users/{id}` | `UiEffectiveRoleMapping.ListCompositeUsersRoleMappingsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | UI effective-role projections resolve actual composite child for users |

### UiRoleComposite（1 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GET | `/admin/realms/{realm}/ui-ext/role-mappings/roles/{id}` | `UiRoleComposite.GetCompositeRoleMappingsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | UI composite mapping groups persisted client role under owning client |

### UiRoleMappingDelete（5 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| POST | `/admin/realms/{realm}/ui-ext/role-mapping-delete/clientScopes/{id}` | `UiRoleMappingDelete.DeleteClientScopeRoleMappingsAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | UI bulk mapping deletion removes actual direct client role for clientScopes |
| POST | `/admin/realms/{realm}/ui-ext/role-mapping-delete/clients/{id}` | `UiRoleMappingDelete.DeleteClientRoleMappingsAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | UI bulk mapping deletion removes actual direct client role for clients |
| POST | `/admin/realms/{realm}/ui-ext/role-mapping-delete/groups/{id}` | `UiRoleMappingDelete.DeleteGroupRoleMappingsAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | UI bulk mapping deletion removes actual direct client role for groups |
| POST | `/admin/realms/{realm}/ui-ext/role-mapping-delete/roles/{id}` | `UiRoleMappingDelete.DeleteCompositeRolesAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | UI bulk mapping deletion removes actual direct client role for roles |
| POST | `/admin/realms/{realm}/ui-ext/role-mapping-delete/users/{id}` | `UiRoleMappingDelete.DeleteUserRoleMappingsAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | UI bulk mapping deletion removes actual direct client role for users |

### UiSessions（2 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GET | `/admin/realms/{realm}/ui-ext/sessions` | `UiSessions.RealmSessionsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | UI session projections filter real regular/offline sessions |
| GET | `/admin/realms/{realm}/ui-ext/sessions/client` | `UiSessions.ClientSessionsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | UI session projections filter real regular/offline sessions |

### UiUIRealm（2 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| PUT | `/admin/realms/{realm}/ui-ext/` | `UiUIRealm.UpdateRealmAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | UI realm update changes actual realm display name |
| GET | `/admin/realms/{realm}/ui-ext/info` | `UiUIRealm.GetInfoAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | UI realm info reports no configured external user provider |

### UiUIRealms（1 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GET | `/admin/realms/{realm}/ui-ext/realms/names` | `UiUIRealms.GetRealmsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | UI realm names includes isolated persisted realm |

### User（28 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| DELETE | `/admin/realms/{realm}/users/{user-id}` | `User.DeleteUserAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Deleting temporary user removes persisted user |
| GET | `/admin/realms/{realm}/users/{user-id}` | `User.GetUserAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Revoking FGAP policy restores actual 403 and prevents unauthorized data change |
| PUT | `/admin/realms/{realm}/users/{user-id}` | `User.UpdateUserAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | User profile update persisted |
| GET | `/admin/realms/{realm}/users/{user-id}/configured-user-storage-credential-types` | `User.GetConfiguredUserStorageCredentialTypesAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Local user has stored password and no federated credential provider |
| GET | `/admin/realms/{realm}/users/{user-id}/consents` | `User.GetConsentsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Consent revocation removes persisted client grant |
| DELETE | `/admin/realms/{realm}/users/{user-id}/consents/{client}` | `User.RevokeConsentAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Consent revocation removes persisted client grant |
| GET | `/admin/realms/{realm}/users/{user-id}/credentials` | `User.CredentialsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | disable-credential-types delegates to storage updaters; released local OTP provider preserves local OTP (UserCredentialManager.disableCredentialType) |
| DELETE | `/admin/realms/{realm}/users/{user-id}/credentials/{credentialId}` | `User.RemoveCredentialAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Credential deletion removes selected credential only |
| POST | `/admin/realms/{realm}/users/{user-id}/credentials/{credentialId}/moveAfter/{newPreviousCredentialId}` | `User.MoveCredentialAfterAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Move-after restores persisted OTP order |
| POST | `/admin/realms/{realm}/users/{user-id}/credentials/{credentialId}/moveToFirst` | `User.MoveCredentialToFirstAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Move-to-first changes order of two stored OTP credentials |
| PUT | `/admin/realms/{realm}/users/{user-id}/credentials/{credentialId}/userLabel` | `User.SetCredentialUserLabelAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Credential user label is persisted |
| PUT | `/admin/realms/{realm}/users/{user-id}/disable-credential-types` | `User.DisableCredentialTypeAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | disable-credential-types delegates to storage updaters; released local OTP provider preserves local OTP (UserCredentialManager.disableCredentialType) |
| PUT | `/admin/realms/{realm}/users/{user-id}/execute-actions-email` | `User.ExecuteActionsEmailAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | User execute-actions-email delivers action-link email to actual persisted user's address |
| GET | `/admin/realms/{realm}/users/{user-id}/federated-identity` | `User.GetFederatedIdentityAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Federated identity removal persists |
| DELETE | `/admin/realms/{realm}/users/{user-id}/federated-identity/{provider}` | `User.RemoveFederatedIdentityAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Federated identity removal persists |
| POST | `/admin/realms/{realm}/users/{user-id}/federated-identity/{provider}` | `User.AddFederatedIdentityAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Federated identity link persists provider and external subject |
| GET | `/admin/realms/{realm}/users/{user-id}/groups` | `User.GroupMembershipAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Leaving group removes membership |
| GET | `/admin/realms/{realm}/users/{user-id}/groups/count` | `User.GetGroupMembershipCountAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Joining group updates member listing and user membership count |
| DELETE | `/admin/realms/{realm}/users/{user-id}/groups/{groupId}` | `User.RemoveMembershipAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Leaving group removes membership |
| PUT | `/admin/realms/{realm}/users/{user-id}/groups/{groupId}` | `User.JoinGroupAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Joining group updates member listing and user membership count |
| POST | `/admin/realms/{realm}/users/{user-id}/impersonation` | `User.ImpersonateAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Impersonation creates actual target-user session and realm redirect |
| POST | `/admin/realms/{realm}/users/{user-id}/logout` | `User.LogoutAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | User logout invalidates all regular sessions for that user |
| GET | `/admin/realms/{realm}/users/{user-id}/offline-sessions/{clientUuid}` | `User.GetOfflineSessionsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Offline grant persists user/client offline session and count |
| PUT | `/admin/realms/{realm}/users/{user-id}/reset-password` | `User.ResetPasswordAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Password reset allows real OIDC authentication with new password |
| PUT | `/admin/realms/{realm}/users/{user-id}/reset-password-email` | `User.ResetPasswordEmailAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | User reset-password-email delivers action-link email to actual persisted user's address |
| PUT | `/admin/realms/{realm}/users/{user-id}/send-verify-email` | `User.SendVerifyEmailAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | User send-verify-email delivers action-link email to actual persisted user's address |
| GET | `/admin/realms/{realm}/users/{user-id}/sessions` | `User.GetSessionsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Realm logout-all removes existing user sessions |
| GET | `/admin/realms/{realm}/users/{user-id}/unmanagedAttributes` | `User.GetUnmanagedAttributesAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Unmanaged attributes expose actual persisted admin attribute |

### UserProfile（3 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GET | `/admin/realms/{realm}/users/profile` | `UserProfile.GetConfigurationAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | User-profile configuration persists and metadata describes required username |
| PUT | `/admin/realms/{realm}/users/profile` | `UserProfile.UpdateAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | User-profile configuration persists and metadata describes required username |
| GET | `/admin/realms/{realm}/users/profile/metadata` | `UserProfile.GetMetadataAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | User-profile configuration persists and metadata describes required username |

### UserStorageProvider（5 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GET | `/admin/realms/{realm}/user-storage/{id}/name` | `UserStorageProvider.GetSimpleNameAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | LDAP component creation persists provider, parent and discoverable storage name |
| POST | `/admin/realms/{realm}/user-storage/{id}/remove-imported-users` | `UserStorageProvider.RemoveImportedUsersAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Remove-imported-users deletes previously imported local user |
| POST | `/admin/realms/{realm}/user-storage/{id}/sync` | `UserStorageProvider.SyncUsersAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Full LDAP sync imports actual directory user with provider link |
| POST | `/admin/realms/{realm}/user-storage/{id}/unlink-users` | `UserStorageProvider.UnlinkUsersAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Unlink-users preserves imported user while removing federation link |
| POST | `/admin/realms/{realm}/user-storage/{parentId}/mappers/{id}/sync` | `UserStorageProvider.SyncMapperDataAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | LDAP group mapper sync imports actual directory group |

### UserVerifiableCredential（7 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GET | `/admin/realms/{realm}/users/{user-id}/vc/credentials` | `UserVerifiableCredential.GetCredentialsAsync` | 政策排除 | 政策排除 | 政策排除 | 政策排除 | OID4VC：26.8.1 为 PREVIEW，按要求不做真实验收 |
| POST | `/admin/realms/{realm}/users/{user-id}/vc/credentials` | `UserVerifiableCredential.CreateCredentialAsync` | 政策排除 | 政策排除 | 政策排除 | 政策排除 | OID4VC：26.8.1 为 PREVIEW，按要求不做真实验收 |
| PUT | `/admin/realms/{realm}/users/{user-id}/vc/credentials/send-credential-offer` | `UserVerifiableCredential.SendCredentialOfferAsync` | 政策排除 | 政策排除 | 政策排除 | 政策排除 | OID4VC：26.8.1 为 PREVIEW，按要求不做真实验收 |
| DELETE | `/admin/realms/{realm}/users/{user-id}/vc/credentials/{credentialScopeName}` | `UserVerifiableCredential.RevokeCredentialAsync` | 政策排除 | 政策排除 | 政策排除 | 政策排除 | OID4VC：26.8.1 为 PREVIEW，按要求不做真实验收 |
| PUT | `/admin/realms/{realm}/users/{user-id}/vc/credentials/{credentialScopeName}` | `UserVerifiableCredential.UpdateCredentialAsync` | 政策排除 | 政策排除 | 政策排除 | 政策排除 | OID4VC：26.8.1 为 PREVIEW，按要求不做真实验收 |
| GET | `/admin/realms/{realm}/users/{user-id}/vc/issued-credentials` | `UserVerifiableCredential.GetIssuedCredentialsAsync` | 政策排除 | 政策排除 | 政策排除 | 政策排除 | OID4VC：26.8.1 为 PREVIEW，按要求不做真实验收 |
| DELETE | `/admin/realms/{realm}/users/{user-id}/vc/issued-credentials/{id}` | `UserVerifiableCredential.RevokeIssuedCredentialAsync` | 政策排除 | 政策排除 | 政策排除 | 政策排除 | OID4VC：26.8.1 为 PREVIEW，按要求不做真实验收 |

### Users（3 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GET | `/admin/realms/{realm}/users` | `Users.GetUsersAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Full LDAP sync imports actual directory user with provider link |
| POST | `/admin/realms/{realm}/users` | `Users.CreateUserAsync` | 通过 201 | 通过 201 | 通过 201 | 通过 201 | User creation persists profile |
| GET | `/admin/realms/{realm}/users/count` | `Users.GetUsersCountAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Exact user search and count select the created user |

### Workflow（5 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| DELETE | `/admin/realms/{realm}/workflows/{id}` | `Workflow.DeleteAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Workflow deletion removes persisted definition |
| GET | `/admin/realms/{realm}/workflows/{id}` | `Workflow.ToRepresentationAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Workflow representation excludes workflow/step IDs when requested |
| PUT | `/admin/realms/{realm}/workflows/{id}` | `Workflow.UpdateAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Workflow update changes persisted definition |
| POST | `/admin/realms/{realm}/workflows/{id}/activate/{type}/{resourceId}` | `Workflow.ActivateAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Activation creates a persisted future schedule for the actual user |
| POST | `/admin/realms/{realm}/workflows/{id}/deactivate/{type}/{resourceId}` | `Workflow.DeactivateAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Deactivation removes the user schedule |

### Workflows（4 项）

| 方法 | 完整路径 | SDK 方法 | v2 托管 | v2 AOT | v1 托管 | v1 AOT | 业务证明或排除原因 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GET | `/admin/realms/{realm}/workflows` | `Workflows.ListAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Workflow creation persists two real steps and is found in exact list |
| POST | `/admin/realms/{realm}/workflows` | `Workflows.CreateAsync` | 通过 201 | 通过 201 | 通过 201 | 通过 201 | Workflow creation persists two real steps and is found in exact list |
| POST | `/admin/realms/{realm}/workflows/migrate` | `Workflows.MigrateAsync` | 通过 204 | 通过 204 | 通过 204 | 通过 204 | Migration changes the resource's persisted scheduled step |
| GET | `/admin/realms/{realm}/workflows/scheduled/{resource-id}` | `Workflows.GetScheduledWorkflowsAsync` | 通过 200 | 通过 200 | 通过 200 | 通过 200 | Deactivation removes the user schedule |

## 证据与边界

- [逐接口原始业务表](full-live-acceptance.tsv)、[支持范围及原因](admin-api-support-matrix.tsv)、[接口到发布源码位置](endpoint-inventory.md)。
- [验收汇总及证据清单](full-live-acceptance.md)、[单测和覆盖率](test-coverage.md)、[声明式路线](admin-api-routing.md)。
- 本地实测证明不等于 Windows win-x64 Native AOT 或远端 CI 已通过，也不代表已覆盖所有参数、权限、配置或外部商业服务组合。

重建本清单：`dotnet run --file tools/Generate-ValidationList.cs`。
