# 验证状态与边界

验证日期：2026-11-04。构建 SDK：10.0.403；目标：net10.0；Keycloak 固定提交和镜像见 [baseline.json](../../contracts/baseline.json)。

## 已完成

- 固定源码中 520 个 HTTP 方法/路径对应 SDK 方法；每项包含 Java 文件及行号。官方预览 OpenAPI 所列端点均能关联到源码。
- 核心库 Release 构建通过，AOT 与裁剪分析零警告。全局关闭反射 JSON，内置 DTO 与响应集合使用源生成元数据。
- 520 个生成方法逐个执行无网络路由及序列化冒烟测试；另验证上下文路径、Unicode/斜杠/百分号编码、查询缺省/false/0/空值/重复数组值、Location、HTTP/JSON 错误、取消、流所有权、token 并发缓存和过期。
- MSTest **538/538** 通过，其中全部 **520 个 Admin API SDK 操作各有一个独立功能契约矩阵测试**，另有源码手写专项、全部模型往返及公共组件异常分支。SDK 自有源码方法与分支覆盖率 100%，行覆盖率 99.9583%；API 包装方法行/分支和 DTO 行覆盖率 100%。完整矩阵及门槛见 [单测矩阵](admin-api-test-matrix.md) 和 [覆盖率报告](test-coverage.md)。测试框架包全部标记 `PrivateAssets="all"`，独立 Native AOT 程序以无包源码执行同一矩阵。
- 本机辅助入口统一为 .NET 10 文件式 C#，覆盖构建、容器生命周期、契约更新和证据汇总；CI 配置使用 `verify.yaml` 并复用相同工具。
- `linux-musl-x64` 已在 .NET SDK 10.0.403 Alpine 容器中实际 Native AOT 发布，全部 520 个功能矩阵、模型及专项断言在原生程序中执行成功。Windows 本机缺少 C++ 链接器及 Windows SDK，尚未通过 win-x64 原生发布；仓库 CI 将继续验证该目标。
- 全功能真实集成程序在当前 Keycloak 26.8.1 + PostgreSQL 18.0 服务上，以托管和 `linux-musl-x64` Native AOT 两种方式分别通过：v2 正式路线 **478/478**、v1 兼容路线 **492/492**。每个支持范围内的方法/路径有业务证明，未完成项均为 0；排除项独立记录，见 [逐项结果](full-live-acceptance.md)。原有 91 路径场景和 [HTTP 观测清单](live-endpoints.tsv) 保留为历史辅助记录。
- 真实场景包含用户/组/组织生命周期、凭据顺序与密码登录、认证流/配置、OIDC 同意及普通/离线会话、邮件动作与邀请、SAML 元数据与证书/PKCS12、授权策略和实际 PERMIT/DENY、工作流调度迁移、LDAP 用户及群组同步、导入导出和 UI 扩展。测试隔离 realm 结束后删除，管理员邮箱恢复。
- FGAP 两条路线均实际验证受限管理员的 403 → 授权后读写及持久化 → 撤销后 403。v2 使用正式 `admin-permissions` schema，v1 使用旧版 management-permissions；没有启用预览或实验功能。
- 缓存验证观察实际效果：直接修改隔离 realm 的 PostgreSQL 数据，清理 realm 缓存后才读到新值；修改 LDAP 属性并清理用户缓存；轮换远端 JWKS，清理公钥缓存后新密钥认证成功；更新真实签名 CRL，清理 CRL 缓存后吊销证书被拒绝。SMTP/HTTP/LDAP/PostgreSQL 协议均真实通信。
- 本次六路径全部通过托管及 Native AOT 真实测试：策略与权限的类型分支筛选/分页和 ID 分支；身份提供方 multipart 文件解析及 JSON URL 拉取；本地化 JSON/multipart UTF-8 持久化；SMTP JSON/表单各实际投递一封邮件；工作流空列表与调度后非空列表。元数据 HTTP 服务及 SMTP 接收器均由 .NET 10 测试代码实现。工作流测试启用 `workflows`，调度资源类型使用源码定义的 `USERS`。详见 [修复记录](six-path-fixes.md)。
- [本地 Compose 服务](../../local/keycloak/README.md) 固定 Keycloak 26.8.1 + PostgreSQL 18.0 Alpine 镜像，JSON/环境变量显式声明路线，核验实际功能开关、服务器版本及数据库 schema；`down` / `up` 保留 PostgreSQL 集群和凭据。全功能入口自动增加真实 OpenLDAP 辅助服务，普通启动仍为基础配置。
- `Check-FullAcceptance.cs` 校验四份完整业务证据、当前代码指纹和实际服务版本；两条路线各验证十项门禁负向控制。CI 已改为两路线的真实 PostgreSQL 托管/AOT 矩阵，远端执行状态以 CI 为准。

## 仍需完成的稳定发布条件

独立源码对齐审计已确认：415 个官方操作和 105 个源码补充操作均有 SDK 路由，526 个源码分派变体得到保留。本次审计的路由遗漏、查询参数、媒体类型、缺失请求体及可比较的直接声明返回类型差异均为 0；可机械比较返回类型共 205 项。此前六路径缺口已修复并实测。完整分组及 520 项对照见 [审计报告](keycloak-26.8.1-alignment-audit.md)。

原先“剩余 429 条未验收”的状态已由逐接口业务矩阵替代。按最新支持政策，520 项 wire 清单中 **28 项预览/实验功能明确排除**；其余 492 项在 v1 兼容路线全部完成托管/AOT 验收。v2 正式路线另排除 14 项 v1 专用接口，其余 478 项全部完成。排除项不记成功，保留完整单测覆盖和明确原因，见 [支持矩阵](admin-api-support-matrix.tsv)。

逐接口验收不等于穷尽每个接口的所有管理员权限组合、策略提供方类型、配置组合和第三方 SPI 行为；当前业务场景及证明逐项可查。邮件和外部身份协议使用本地真实协议夹具，不代表对某个商业 SMTP/身份提供商的兼容性认证。

源代码独有或动态契约暂用 `HttpContent` / `JsonElement`，保留 wire 访问能力；后续应逐项核实请求/响应模型和状态，再完善强类型方法。公开 API 命名和更新模型在预览阶段仍可调整。尚未完成旧 SDK 迁移映射，不发布稳定完整支持声明。

## 路由盘点范围

已审定的 7 项 OpenAPI 差异记录在 [overrides.json](../../contracts/overrides.json)：原有六项加上 SAML 示例包装类的 `@JsonValue` 实际输出字符串。全量实跑还发现证书上传通过 session 读取 multipart、没有 Java body 参数；生成器现保留这类隐式 `HttpContent` 请求体，证书生成/上传/下载均实际验证。两项新增独立回归包含在 538 项测试中。Java 的 `RawJsonValue` 映射为 `JsonElement`，多值 map 保留字典与列表结构。

从 `AdminRoot` 的 realms 和 serverinfo 出发，解析资源定位器、继承和授权策略的动态分支；额外追踪内置 AdminRealmResourceProvider（用户存储、缓存、LDAP、SSF）及 ui-ext。管理端点即使依赖可选 feature flag 也保留。控制台 HTML/静态资源、CORS preflight、独立 OAuth/SCIM/Account 协议和任意第三方 SPI 扩展不属于该清单。

`unresolved-locators.txt` 中保留三处动态定位器供审计：realm 的任意 SPI extension，以及 policy/permission 的 provider。内置 realm providers 已显式枚举；固定版本的 `PolicyProviderAdminService` 是无 REST 方法的标记接口，内置 policy factories 没有实现额外 REST provider。第三方安装可扩展这些位置，SDK 可通过原始请求访问，不能在固定源码中枚举未知插件。

生成器是受固定文件 SHA256 清单约束的 Java 路由索引，不是通用 Java 编译器。升级 Keycloak 时须重新审查定位器、默认值、注解、权限和动态分派，不能仅替换 OpenAPI 或修改端点数量。当前生成状态与真实观测分开保存在清单中。
