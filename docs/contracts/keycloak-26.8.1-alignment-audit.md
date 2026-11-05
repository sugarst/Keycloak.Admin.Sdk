# Keycloak 26.8.1 REST Admin API 对齐审计

结论：本次静态对照未发现方法、路径、已比较查询参数、媒体类型及直接声明返回类型的差异。该结果不代替全量 DTO、权限、状态码与业务验收。

基线为 [发布 tag](https://github.com/keycloak/keycloak/releases/tag/26.8.1)，完整提交 `24ed1dadf3f246a555adb6d3d4a99e9b3003fb3b`。[官方 API 定义](https://www.keycloak.org/docs-api/26.8.1/rest-api/index.html) 仍标记为预览。远端 tag 和 OpenAPI 本次在线核验：**一致**；本地源码归档 SHA256 和源码文件清单校验通过。

## 数量与口径

| 检查项 | 结果 |
| --- | --- |
| 官方 OpenAPI 方法＋路径 | 415（274 个路径模板） |
| 独立源码扫描方法＋路径 | 520 |
| 源码处理分支 | 526，包含同路径的动态/媒体类型分派 |
| SDK / Markdown 清单 / 源码清单 | 520 / 520 / 520 |
| 官方接口遗漏 / 源码路径遗漏 / SDK 无来源路径 | 0 / 0 / 0 |
| 查询参数缺口 | 0 项，涉及 0 个路径 |
| 媒体类型变体缺口 | 0 个路径 |
| 可比返回类型差异 | 0 / 205 项 |

计数单位是 HTTP 方法＋路径模板；SDK 共 520 项，官方文档 415 项，发布源码补充 105 项。动态 SPI 和可选功能边界需逐版复核。

## 官方清单分组

| 官方分组 | 操作数 | SDK 路由缺失 |
| --- | --- | --- |
| Attack Detection | 3 | 0 |
| Authentication Management | 39 | 0 |
| Client Attribute Certificate | 7 | 0 |
| Client Initial Access | 3 | 0 |
| Client Registration Policy | 1 | 0 |
| Client Role Mappings | 15 | 0 |
| Client Scopes | 10 | 0 |
| Clients | 35 | 0 |
| Component | 6 | 0 |
| Groups | 11 | 0 |
| Identity Providers | 17 | 0 |
| Key | 1 | 0 |
| Organizations | 38 | 0 |
| Protocol Mappers | 21 | 0 |
| Realms Admin | 45 | 0 |
| Role Mapper | 18 | 0 |
| Roles | 28 | 0 |
| Roles (by ID) | 10 | 0 |
| Scope Mappings | 33 | 0 |
| Users | 34 | 0 |
| Workflows | 9 | 0 |
| default | 31 | 0 |

## 源码补充清单

| 源码模块 | 文档外操作数 |
| --- | --- |
| federation/ldap | 2 |
| model/storage-services | 9 |
| rest/admin-ui-ext | 31 |
| services | 44 |
| ssf/services | 19 |

services 的 44 项由授权策略动态路径 36 项、用户 VC 管理 7 项和 serverinfo 1 项构成。其余补充包括用户存储/缓存、LDAP、SSF 和 ui-ext；这些并不都属于默认启用、稳定的核心功能。

## 已审定差异与回归

[overrides.json](../../contracts/overrides.json) 记录 7 项响应/载荷修正及各自源码依据，包括列表、字典、原始载荷和 SAML @JsonValue 字符串。

动态查询、媒体类型与工作流列表的独立断言见 [六路径契约](six-path-fixes.md)。以下仅记录本地隔离场景证据：

- 本地 `managed` 六路径真实容器证据：6 / 6 通过。
- 本地 `native-aot` 六路径真实容器证据：6 / 6 通过。

## 审计边界与验证证据

独立 Java token 扫描器不复用生成器的 JavaRoutes，覆盖已知动态分派，但不是通用 Java/JAX-RS 编译器。本审计不核验 DTO 全字段、Java Response 运行时实体、全部状态码或权限组合。范围定义见 [架构说明](../architecture.md)。已知动态定位器：

- `policy provider SPI: /admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/policy/{type}/provider`
- `policy provider SPI: /admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/permission/{type}/provider`
- `dynamic SPI: /admin/realms/{realm}/{extension}`

[逐项对照](keycloak-26.8.1-alignment.tsv) 包含源码、分组、差异及早期隔离场景观测（91 条方法/路径、93 条状态记录）；该历史观测不代表当前全量业务范围。最新 [单测矩阵](admin-api-test-matrix.md)、[覆盖率](test-coverage.md) 与 [真实业务验收](full-live-acceptance.md) 分别维护证据。

## 复现

```shell
dotnet run --file tools/Audit-Contracts.cs -- --online
```

离线省略 `--online`。工具先输出报告，路由、查询、媒体类型、请求体、可比返回类型或未知定位器存在差异时返回非零。
