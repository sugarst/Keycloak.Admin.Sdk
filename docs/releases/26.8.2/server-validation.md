# Keycloak 26.8.2 服务端专项验收 / Server validation

这次复核从 80 个上游功能开关中选出原先部分验证的 7 项和缺少专项证据的 21 项。使用本地 `quay.io/keycloak/keycloak:26.8.2-3`，固定 `linux/amd64` digest 为 `sha256:7e66a96e4739239070aeaf72e4c5decf0f7f682cfc725b9f7ea2b336eaba38b3`。涉及 PostgreSQL 的夹具使用新建数据。20 项通过具体本地场景，1 项通过 SPI 局部验收，2 项通过 CLI 预检，5 项缺少测试环境。SDK 栏列出可复用的接口或后续回归，表中场景按实际执行范围记录。 [基线](../../../contracts/baseline.json) · [80 项能力清单](../../contracts/platform-capability-matrix.md)

## 原先部分验证的 7 项

| 功能 | 本地观察 | SDK 回归或改造触发条件 | 剩余服务端验收 |
| --- | --- | --- | --- |
| `ACCOUNT_V3` | 浏览器修改姓名，独立 Admin REST 读取确认持久化。 | 复用 Account API，补资料更新与会话权限回归。 | 覆盖安全设置、会话页及刷新后的数据。 |
| `ADMIN_V2` | 浏览器向导创建客户端，独立 Admin REST 读取成功。 | 用现有 Admin SDK 回读控制台写入的资源。 | 覆盖客户端与用户 CRUD、委派管理员及权限提示。 |
| `LOGIN_V2` | 浏览器加载 V2 主题、完成登录并打开账户页。 | 补 ASP.NET Core OIDC 回调与本地会话回归。 | 覆盖 OTP、WebAuthn、恢复动作和本地化。 |
| `HOSTNAME_V2` | HTTP 反向代理下 discovery 的 issuer 和 token URL 保留公共地址、端口和 `/auth` 前缀。 | 补 base path、issuer 验证、回调地址和后端 discovery 回归。 | 验证 HTTPS 终止、不同前后台地址和可信代理头。 |
| `HTTP_CLIENT` | OIDC 元数据分别经匹配代理和直连导入。慢响应在约 711 ms 被截断。 | 复用 IdP 导入接口测试响应与错误映射。 | 验证连接池、重试及 TLS/mTLS。 |
| `LOGIN_FAILURES_V2` | 两次并发错误登录记录为 `2`，用同一 PostgreSQL 的替换节点读到相同值。 | 复用攻击检测读取与清除接口，补权限回归。 | 验证节点并存时的阈值、锁定、清除及数据库差异。 |
| `PERSISTENT_USER_SESSIONS` | 原节点停止后，替换节点接受原在线及离线 refresh token。在线 `sid` 和 subject 保持一致。 | 补会话枚举、续期和撤销的跨节点 SDK 回归。 | 在节点并存和切流时验证过期、注销与失效一致性。 |

## 原先缺少专项证据的 21 项

| 功能 | 本地观察 | SDK 回归或改造触发条件 | 剩余服务端验收 |
| --- | --- | --- | --- |
| `CLUSTERLESS` | 待环境。缺外置 Infinispan 和专用拓扑。 | 复用会话、缓存接口跑拓扑切换回归。 | 配置外置 Infinispan 认证与 TLS，演练节点退出和远端缓存故障恢复。 |
| `DB_TIDB` | 待环境。缺本地 TiDB 服务。 | 用 520 项 Admin 契约定位数据库专属差异，再决定模型或客户端改造。 | 新建 schema，验证初始化、事务、Unicode、并发、授权和会话。 |
| `DECLARATIVE_UI` | SPI 部分通过。镜像内 Java 21 编译并部署 `UiPage` provider，错误配置返回 `400`，有效组件持久化。 | 复用组件管理接口，在稳定新契约出现时补 SDK 类型。 | 验证浏览器挂载页面和标签、资源加载及权限。 |
| `FIPS` | 待环境。当前容器未提供合规内核和 BCFIPS 依赖。 | 用现有 TLS、OIDC、JWK 入口验证应用互操作。 | 使用受支持的 FIPS Linux/JVM 与 BCFIPS，验证所选模式和 TLS 算法。 |
| `HTTP_CLIENT_V2` | OIDC 元数据分别经匹配代理和直连导入。慢响应在约 718 ms 被截断。 | 沿用同一 SDK 导入入口核对错误和超时。 | 与 v1 对照 TLS/mTLS、连接池饱和、重试和退出。 |
| `HTTP_OPTIMIZED_SERIALIZERS` | Preview 开启时，Admin JSON 对象和数组保留 UUID、布尔值与用户标识。 | 对照多态、空值、日期、枚举和流式载荷，按契约差异更新源生成模型。 | 对开关前后的 Admin 和协议响应作快照对照及性能测量。 |
| `IPA_TUURA_FEDERATION` | 待环境。缺可用 IPA/Tuura 服务。 | 复用组件配置及用户读取，按真实 provider 的契约差异补类型。 | 验证用户导入、登录、组和属性、失联及权限。 |
| `LDAP_METRICS` | OpenLDAP 导入真实目录用户，LDAP 请求计时器计数从 `0` 变为 `2`。 | 复用 provider 配置和同步调用。 | 核对搜索、绑定、失败、结果标签及关停后的指标。 |
| `LOG_MDC` | 真实请求日志含 realm、client、session、span 和 trace 等 MDC 字段。 | 用应用遥测测试 SDK 的跟踪传播。 | 核对正常、失败与并发请求字段关联。 |
| `LOGIN_FAILURES_V1` | 旧版计数重启前为 `1`，重启后为 `0`，夹具的 realm 与用户保留。 | 复用攻击检测接口回归旧版计数读取。 | 验证阈值、锁定、清除与弃用配置组合。 |
| `LOGIN_V1` | 浏览器加载 V1 主题的独立资源并完成真实登录。 | 保持 OIDC 回调和会话回归。 | 验证必需动作、语言及主题资源。 |
| `MULTI_SITE` | 待环境。缺多站点拓扑与外置 Infinispan。 | 回归业务调用和会话恢复，按实测差异调整传输。 | 搭建遗留多站点拓扑，演练站点失联、流量切换、恢复与数据一致性。 |
| `OPENTELEMETRY` | 优化启动的 PostgreSQL 配置下，Collector 经 OTLP gRPC 收到 Keycloak trace。 | 回归 SDK 的 trace context 传播。 | 核对父子 span、采样和 Collector 短期不可用后的恢复。 |
| `OPENTELEMETRY_LOGS` | 独立 profile 与 PostgreSQL 优化启动 profile 均经 OTLP gRPC 收到 Keycloak 日志。 | 回归 SDK 客户端日志与跟踪关联。 | 原混合配置的 HTTP/protobuf 日志投递仍待验收，同时核对级别过滤和重试。 |
| `OPENTELEMETRY_METRICS` | 同一 PostgreSQL 优化启动 profile 经 OTLP gRPC 投递可辨识的 Keycloak 指标。 | 以应用调用驱动可观测事件。 | 校验登录指标、标签、采集周期和时间序列。 |
| `QUICK_THEME` | 浏览器预览并下载主题 JAR，独立节点安装后提供选定的登录主题。 | 使用 realm 主题属性补管理配置回读。 | 验证安装后的账户及管理控制台样式和资源。 |
| `ROLLING_UPDATES_V1` | 同镜像同配置 CLI 返回 `0`，变更数据库配置返回 `3`。 | 在滚动期间跑既有管理调用和会话探针。 | 逐节点替换 26.8.2 节点，持续发送业务流量并验证不中断。 |
| `ROLLING_UPDATES_V2` | 同镜像同配置 CLI 返回 `0`，变更数据库配置返回 `3`。 | 用既有 SDK 调用持续验证认证及管理操作。 | 在受支持拓扑内验证健康检查、流量切换和逐节点替换。 |
| `SCRIPTS` | 服务端部署 JAR 内 mapper，真实 access token 包含预期自定义 claim。 | 复用 mapper 表示及写入授权回归。 | 验证禁用、配置拒绝和错误处理。 |
| `STATELESS` | 节点 A 开始授权后停止。共享新建 PostgreSQL 的节点 B 完成原 PKCE 事务。 | 补跨节点续接及令牌续期的 OIDC 回归。 | 验证节点并存、流量切换和动作令牌的持续有效性。 |
| `USER_EVENT_METRICS` | 真实登录令 realm 标签下的 Prometheus 登录计数从 `2` 变为 `3`。 | 以现有认证入口驱动事件。 | 核对成功、失败与注销事件、过滤和标签。 |

## English summary

This review selected 28 flags from the 80-item upstream inventory. All seven previously partial items passed a specific local scenario. Of the 21 items previously missing targeted evidence, 13 passed a specific scenario, Declarative UI reached provider registration and persistence, two rolling-update modes passed their same-release CLI prechecks, and five need dedicated environments. PostgreSQL-backed runs used fresh data. The optimized PostgreSQL run delivered Keycloak traces, logs, and metrics to a local Collector over OTLP gRPC. The mixed configuration that sends logs over HTTP/protobuf still needs validation.

SDK follow-up centers on reusable Admin and protocol regressions for issuer and base-path handling, response serialization, and session continuity. The remaining server work includes browser rendering for Declarative UI, live rolling replacement, external-cache or multi-site topologies, TiDB, IPA/Tuura, and compliant FIPS execution. The SDK release gate and the scope of the supported interfaces are recorded separately in the candidate manifest and capability matrix. [Bilingual upgrade notes](release-notes.md) · [Platform capability matrix](../../contracts/platform-capability-matrix.md)
