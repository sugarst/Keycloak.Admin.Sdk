# 验证状态与边界

验证日期：2026-11-04。构建 SDK：10.0.403；目标：net10.0；Keycloak 固定提交和镜像见 [baseline.json](../../contracts/baseline.json)。

## 已完成

- 固定源码中 520 个 HTTP 方法/路径对应 SDK 方法；每项包含 Java 文件及行号。官方预览 OpenAPI 所列端点均能关联到源码。
- 核心库 Release 构建通过，AOT 与裁剪分析零警告。全局关闭反射 JSON，内置 DTO 与响应集合使用源生成元数据。
- 520 个生成方法逐个执行无网络路由及序列化冒烟测试；另验证上下文路径、Unicode/斜杠/百分号编码、查询缺省/false/0/空值/重复数组值、Location、HTTP/JSON 错误、取消、流所有权、token 并发缓存和过期。
- 常规检查已接入 MSTest，**536 个测试方法通过**，其中全部 **520 个 Admin API SDK 操作各有一个独立功能契约矩阵测试**，另有六组源码手写专项、全部模型往返及公共组件异常分支。SDK 自有源码方法与分支覆盖率 100%，行覆盖率 99.9583%；API 包装方法行/分支和 DTO 行覆盖率 100%。完整矩阵及强制门槛见 [单测矩阵](admin-api-test-matrix.md) 和 [覆盖率报告](test-coverage.md)。测试框架包全部标记 `PrivateAssets="all"`，独立 Native AOT 程序以无包源码执行同一矩阵。
- 本机辅助入口统一为 .NET 10 文件式 C#，覆盖构建、容器生命周期、契约更新和证据汇总；CI 配置使用 `verify.yaml` 并复用相同工具。
- `linux-musl-x64` 已在 .NET SDK 10.0.403 Alpine 容器中实际 Native AOT 发布，全部 520 个功能矩阵、模型及专项断言在原生程序中执行成功。Windows 本机缺少 C++ 链接器及 Windows SDK，尚未通过 win-x64 原生发布；仓库 CI 将继续验证该目标。
- 真实集成测试程序也已发布为 `linux-musl-x64` Native AOT，并在隔离容器网络中直接执行原生 ELF，当前已实现的真实测试场景通过，覆盖 91 条方法/路径。HTTP 网络、client credentials 和资源 JSON 处理在该原生程序中实际执行。
- 使用本地 `quay.io/keycloak/keycloak:26.8.1`，先核验其 RepoDigests 与基线一致，再以本地不可变 image ID 启动。真实集成测试通过，得到 93 条方法/路径/状态码观测，覆盖 91 个不同的方法/路径。测试独立 realm 的用户、密码凭据、组、成员、客户端、角色映射、client scope、授权 scope、策略创建、组织成员、事件及认证配置读取，并验证无权限服务账号和 404；realm 与容器已清理。观测清单见 [live-endpoints.tsv](live-endpoints.tsv)。
- 本次六路径全部通过托管及 Native AOT 真实测试：策略与权限的类型分支筛选/分页和 ID 分支；身份提供方 multipart 文件解析及 JSON URL 拉取；本地化 JSON/multipart UTF-8 持久化；SMTP JSON/表单各实际投递一封邮件；工作流空列表与调度后非空列表。元数据 HTTP 服务及 SMTP 接收器均由 .NET 10 测试代码实现。工作流测试启用 `workflows`，调度资源类型使用源码定义的 `USERS`。详见 [修复记录](six-path-fixes.md)。
- 新增 [本地 Compose 服务](../../local/keycloak/README.md)，固定 Keycloak 26.8.1 + PostgreSQL 18.0 Alpine 镜像；已在该数据库后端再次通过托管及 Native AOT 真实集成测试。实际核验服务版本、管理员认证及数据库 schema，并验证 `down` / `up` 保留 PostgreSQL 集群标识和凭据。该服务用于后续扩大真实覆盖，现有真实方法/路径数量仍为 91。

## 仍需完成的稳定发布条件

独立源码对齐审计已确认：415 个官方操作和 105 个源码补充操作均有 SDK 路由，526 个源码分派变体得到保留。本次审计的路由遗漏、查询参数、媒体类型、缺失请求体及可比较的直接声明返回类型差异均为 0；可机械比较返回类型共 205 项。此前六路径缺口已修复并实测。完整分组及 520 项对照见 [审计报告](keycloak-26.8.1-alignment-audit.md)。

520 个 SDK 操作现在均有功能契约单测，但单测模拟的契约行为不能等同于 520 个端点的全部服务端业务语义已实测。真实容器已覆盖 **91/520（17.5%）** 条方法/路径，剩余 **429 条尚未完成真实容器验收**；不能声明全量 Admin API 已通过真实服务端验收。矩阵覆盖请求、响应、错误与边界，真实集成测试目前覆盖上述场景。LDAP、真实外部邮件服务及身份提供方、SSF 接收方、其他 feature flag、完整 FGAP 访问矩阵、更多策略类型和失败分支仍需专门测试环境及逐项证据。

源代码独有或动态契约暂用 `HttpContent` / `JsonElement`，保留 wire 访问能力；后续应逐项核实请求/响应模型和状态，再完善强类型方法。公开 API 命名和更新模型在预览阶段仍可调整。尚未完成旧 SDK 迁移映射，不发布稳定完整支持声明。

## 路由盘点范围

已修正的 6 项 OpenAPI 差异记录在 [overrides.json](../../contracts/overrides.json)：scope 按名称搜索实际返回单个对象；policy/permission 创建实际接收 JSON 对象并返回实体；client-description-converter 读取原始 JSON/XML/text；resource attributes 响应为多值属性字典；scheduled workflows 实际返回列表。策略创建、scope 搜索和工作流列表修正已经真实容器测试。Java 的 `RawJsonValue` 依据 `@JsonValue` 语义映射为 `JsonElement`，多值 map 保留字典与列表结构。

从 `AdminRoot` 的 realms 和 serverinfo 出发，解析资源定位器、继承和授权策略的动态分支；额外追踪内置 AdminRealmResourceProvider（用户存储、缓存、LDAP、SSF）及 ui-ext。管理端点即使依赖可选 feature flag 也保留。控制台 HTML/静态资源、CORS preflight、独立 OAuth/SCIM/Account 协议和任意第三方 SPI 扩展不属于该清单。

`unresolved-locators.txt` 中保留三处动态定位器供审计：realm 的任意 SPI extension，以及 policy/permission 的 provider。内置 realm providers 已显式枚举；固定版本的 `PolicyProviderAdminService` 是无 REST 方法的标记接口，内置 policy factories 没有实现额外 REST provider。第三方安装可扩展这些位置，SDK 可通过原始请求访问，不能在固定源码中枚举未知插件。

生成器是受固定文件 SHA256 清单约束的 Java 路由索引，不是通用 Java 编译器。升级 Keycloak 时须重新审查定位器、默认值、注解、权限和动态分派，不能仅替换 OpenAPI 或修改端点数量。当前生成状态与真实观测分开保存在清单中。
