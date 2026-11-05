# Keycloak 26.8.1 接口验证索引

由 `tools/Generate-ValidationList.cs` 从支持矩阵与真实业务表生成，共 520 个 HTTP 方法 + 路径。v2 正式范围 478 项，v1 兼容范围 492 项，两者均有托管及 Linux Native AOT 业务证明。执行时间和环境见 [验收汇总](full-live-acceptance.md)。

## 按资源入口

下表汇总各 SDK 资源；完整路径、方法、四种执行结果和业务断言保留在 [逐接口业务表](full-live-acceptance.tsv)，此处不重复展开。

| SDK 资源 | wire 操作 | v2 已验证 | v1 已验证 | 两路线均排除 |
| --- | --- | --- | --- | --- |
| AttackDetection | 3 | 3 | 3 | 0 |
| AuthenticationManagement | 39 | 39 | 39 | 0 |
| ClearCrlCache | 1 | 1 | 1 | 0 |
| ClearKeysCache | 1 | 1 | 1 | 0 |
| ClearRealmCache | 1 | 1 | 1 | 0 |
| ClearUserCache | 1 | 1 | 1 | 0 |
| Client | 26 | 24 | 26 | 0 |
| ClientAttributeCertificate | 6 | 6 | 6 | 0 |
| ClientInitialAccess | 3 | 3 | 3 | 0 |
| ClientPolicies | 2 | 2 | 2 | 0 |
| ClientProfiles | 2 | 2 | 2 | 0 |
| ClientRegistrationPolicy | 1 | 1 | 1 | 0 |
| ClientRoleMappings | 15 | 15 | 15 | 0 |
| ClientScope | 6 | 6 | 6 | 0 |
| ClientScopeEvaluate | 5 | 5 | 5 | 0 |
| ClientScopeEvaluateScopeMappings | 2 | 2 | 2 | 0 |
| ClientScopes | 4 | 4 | 4 | 0 |
| ClientTypes | 2 | 0 | 0 | 2 |
| Clients | 2 | 2 | 2 | 0 |
| Component | 6 | 6 | 6 | 0 |
| Group | 8 | 6 | 8 | 0 |
| Groups | 3 | 3 | 3 | 0 |
| IdentityProvider | 13 | 11 | 13 | 0 |
| IdentityProviders | 5 | 5 | 5 | 0 |
| Key | 1 | 1 | 1 | 0 |
| LdapServerCapabilities | 1 | 1 | 1 | 0 |
| Organization | 3 | 3 | 3 | 0 |
| OrganizationGroup | 8 | 8 | 8 | 0 |
| OrganizationGroups | 3 | 3 | 3 | 0 |
| OrganizationIdentityProviders | 6 | 6 | 6 | 0 |
| OrganizationInvitation | 4 | 4 | 4 | 0 |
| OrganizationMember | 10 | 10 | 10 | 0 |
| Organizations | 4 | 4 | 4 | 0 |
| Policy | 42 | 42 | 42 | 0 |
| PolicyEvaluation | 4 | 4 | 4 | 0 |
| ProtocolMappers | 21 | 21 | 21 | 0 |
| RealmAdmin | 30 | 28 | 30 | 0 |
| RealmLocalization | 7 | 7 | 7 | 0 |
| RealmsAdmin | 2 | 2 | 2 | 0 |
| RoleById | 10 | 8 | 10 | 0 |
| RoleContainer | 28 | 24 | 28 | 0 |
| RoleMapper | 18 | 18 | 18 | 0 |
| Scope | 8 | 8 | 8 | 0 |
| ScopeMapped | 18 | 18 | 18 | 0 |
| ScopeMappedClient | 15 | 15 | 15 | 0 |
| Server | 4 | 4 | 4 | 0 |
| ServerInfoAdmin | 1 | 1 | 1 | 0 |
| Set | 9 | 9 | 9 | 0 |
| SsfAdmin | 19 | 0 | 0 | 19 |
| TestLdapConnection | 1 | 1 | 1 | 0 |
| UiAllEffectiveRoleMapping | 5 | 5 | 5 | 0 |
| UiAuthenticationManagement | 3 | 3 | 3 | 0 |
| UiAvailableEventListeners | 1 | 1 | 1 | 0 |
| UiAvailableRoleMapping | 5 | 5 | 5 | 0 |
| UiBruteForceUsers | 1 | 1 | 1 | 0 |
| UiEffectiveRoleMapping | 5 | 5 | 5 | 0 |
| UiRoleComposite | 1 | 1 | 1 | 0 |
| UiRoleMappingDelete | 5 | 5 | 5 | 0 |
| UiSessions | 2 | 2 | 2 | 0 |
| UiUIRealm | 2 | 2 | 2 | 0 |
| UiUIRealms | 1 | 1 | 1 | 0 |
| User | 28 | 28 | 28 | 0 |
| UserProfile | 3 | 3 | 3 | 0 |
| UserStorageProvider | 5 | 5 | 5 | 0 |
| UserVerifiableCredential | 7 | 0 | 0 | 7 |
| Users | 3 | 3 | 3 | 0 |
| Workflow | 5 | 5 | 5 | 0 |
| Workflows | 4 | 4 | 4 | 0 |

## 政策排除

排除项仍保留 wire 方法和契约单测，不计为真实业务通过。逐项分类见 [支持矩阵](admin-api-support-matrix.tsv)。

| 适用范围 | 操作数 | 原因 |
| --- | --- | --- |
| 两条路线 | 2 | client-types (EXPERIMENTAL; excluded by release support policy) |
| 两条路线 | 7 | oid4vc-vci (PREVIEW; excluded by release support policy) |
| 两条路线 | 19 | ssf (EXPERIMENTAL; excluded by release support policy) |
| 仅 v2 | 14 | FGAP v1 compatibility only; select fgap-v1-compat explicitly |

## 详细证据

- [端点及发布源码位置](endpoint-inventory.md) · [独立单测映射](admin-api-test-matrix.md) · [覆盖率](test-coverage.md)。
- [路线声明与校验](admin-api-routing.md) · [发布边界](verification.md)。

重建：`dotnet run --file tools/Generate-ValidationList.cs`。
