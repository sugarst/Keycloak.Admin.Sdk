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

计数单位是 HTTP 方法＋路径模板；仅规范化路径参数名称与末尾斜杠。520 不是官方文档的接口数量，而是 415 个文档操作加 105 个源码补充操作。三个动态 SPI 入口和可选功能仍有边界，见后文。

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

## 已处理的官方定义差异

[overrides.json](../../contracts/overrides.json) 当前记录了 7 项修正：scope/search 单对象响应、policy/permission 的原始 JSON 对象与创建实体、client-description-converter 的原始载荷、resource attributes 的字典响应，以及 scheduled workflows 的列表响应。它们说明不能把 OpenAPI 直接等同于真实 wire 契约。

源码直接声明且可与 SDK 强类型结果机械比较的返回类型共 205 项，类型差异 0 项。该检查不覆盖 Java Response 包装的运行时实体、DTO 每个字段的序列化语义或响应状态码全量行为。

## 六路径回归验证

修复方式、独立断言与真实测试场景见 [六路径修复记录](six-path-fixes.md)。生成器保留同路径的全部分派变体，合并查询参数并保留调用方的媒体类型；工作流返回值依据 Java 实现修正为列表。六组手写断言不使用生成器构造的响应，MSTest 和原生冒烟程序均执行这些断言。

- 本地 `managed` 六路径真实容器证据：6 / 6 通过。
- 本地 `native-aot` 六路径真实容器证据：6 / 6 通过。

## 全操作功能契约单元测试

全部 Admin API SDK 操作的独立用例与适用场景见 [520 项测试矩阵](admin-api-test-matrix.md)，覆盖率及强制门槛见 [门禁报告](test-coverage.md)。期望值来自独立 Java token 索引和固定发布定义，与 SDK 请求构造及原有冒烟生成逻辑分离；每个操作检查查询/载荷/响应、错误、取消和网络失败。`Verify.cs` 要求编译后目录、冻结矩阵与本次 TRX 一一对应，拒绝缺失、重复、跳过、失败或低覆盖率。该结论是 SDK 功能契约单测覆盖，不是全部服务端业务和权限场景的实测声明。

## 审计边界与验证证据

独立扫描器按 Java token 解析声明、导入、继承与资源定位器，不复用生成器的 JavaRoutes；使用已知的 PolicyService 动态分派规则并保留媒体类型变体。它不是完整 Java/JAX-RS 编译器，也不能穷举第三方 SPI 或任意递归策略类型 URI。控制台静态资源、CORS、独立 Admin API v2、Account/SCIM/OIDC 协议不纳入本表。

- `policy provider SPI: /admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/policy/{type}/provider`
- `policy provider SPI: /admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/permission/{type}/provider`
- `dynamic SPI: /admin/realms/{realm}/{extension}`

这是三个已知的动态扩展边界。内置 realm providers 已枚举；自定义 provider、feature flag、授权/FGAP 及响应模型字段的全部运行时语义仍需专门验收。现有 520 次路由冒烟、全操作功能契约单测和 91 条真实方法/路径（93 条状态观测）不能证明全部服务端业务场景对齐。原有冒烟与 SDK 共用生成逻辑，全操作矩阵、六路径手写专项和真实测试分别提供额外证据。

完整逐项对照见 [520 项清单](keycloak-26.8.1-alignment.tsv)，包含官方分组、SDK 方法、源码、已观测状态与本次缺口。后续新增分派变体或契约差异时，应同步修复生成器并增加独立断言和真实服务器测试。

## 复现

```shell
dotnet run --file tools/Audit-Contracts.cs -- --online
```

工具总是先输出报告；发现路由、参数、媒体类型或未知定位器差异时返回非零退出码。离线可省略 --online。工具仅执行静态比对和来源校验，不覆盖完整 DTO 字段/状态码、权限与业务验收。
