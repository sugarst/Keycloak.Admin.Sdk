# Keycloak 26.8.2 服务端专项验收 / Server validation

这次复核从 80 个上游功能开关中选出原先部分验证的 7 项和缺少专项证据的 21 项。使用本地 `quay.io/keycloak/keycloak:26.8.2-3`，固定 `linux/amd64` digest 为 `sha256:7e66a96e4739239070aeaf72e4c5decf0f7f682cfc725b9f7ea2b336eaba38b3`。各次验收使用新建数据。补齐后，23 项有本地场景通过的证据，5 项缺少测试环境。SDK 栏列出可复用的接口或后续回归。 [基线](../../../contracts/baseline.json) · [80 项能力清单](../../contracts/platform-capability-matrix.md)

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
| `DECLARATIVE_UI` | 镜像内 Java 21 编译并部署 `UiPage` provider。错误配置返回 `400`。真实 Chrome 渲染侧栏、列表和动态字段，保存后重载显示新值，独立 Admin REST 回读一致。 | 复用组件管理接口，在稳定新契约出现时补 SDK 类型。 | 补 `UiTab`、委派角色可见性和其他动态字段类型。 |
| `FIPS` | 合规模式待环境。固定镜像以 BCFIPS non-strict 成功启动，生成信任库保留同一 PEM 的两张证书。 | 用现有 TLS、OIDC、JWK 入口验证应用互操作。 | 使用启用 FIPS 的 Linux 和受支持的 JVM，核验 strict 模式和 TLS 算法。 |
| `HTTP_CLIENT_V2` | OIDC 元数据分别经匹配代理和直连导入。慢响应在约 718 ms 被截断。 | 沿用同一 SDK 导入入口核对错误和超时。 | 与 v1 对照 TLS/mTLS、连接池饱和、重试和退出。 |
| `HTTP_OPTIMIZED_SERIALIZERS` | Preview 开启时，Admin JSON 对象和数组保留 UUID、布尔值与用户标识。 | 对照多态、空值、日期、枚举和流式载荷，按契约差异更新源生成模型。 | 对开关前后的 Admin 和协议响应作快照对照及性能测量。 |
| `IPA_TUURA_FEDERATION` | 待环境。缺可用 IPA/Tuura 服务。 | 复用组件配置及用户读取，按真实 provider 的契约差异补类型。 | 验证用户导入、登录、组和属性、失联及权限。 |
| `LDAP_METRICS` | OpenLDAP 导入真实目录用户，LDAP 请求计时器计数从 `0` 变为 `2`。 | 复用 provider 配置和同步调用。 | 核对搜索、绑定、失败、结果标签及关停后的指标。 |
| `LOG_MDC` | 真实请求日志含 realm、client、session、span 和 trace 等 MDC 字段。 | 用应用遥测测试 SDK 的跟踪传播。 | 核对正常、失败与并发请求字段关联。 |
| `LOGIN_FAILURES_V1` | 旧版计数重启前为 `1`，重启后为 `0`，夹具的 realm 与用户保留。 | 复用攻击检测接口回归旧版计数读取。 | 验证阈值、锁定、清除与弃用配置组合。 |
| `LOGIN_V1` | 浏览器加载 V1 主题的独立资源并完成真实登录。 | 保持 OIDC 回调和会话回归。 | 验证必需动作、语言及主题资源。 |
| `MULTI_SITE` | 待环境。缺多站点拓扑与外置 Infinispan。 | 回归业务调用和会话恢复，按实测差异调整传输。 | 搭建遗留多站点拓扑，演练站点失联、流量切换、恢复与数据一致性。 |
| `OPENTELEMETRY` | 优化启动的 PostgreSQL 混合遥测配置下，Collector 经 OTLP gRPC 解码真实 Keycloak HTTP 请求跟踪。 | 回归 SDK 的 trace context 传播。 | 核对父子 span、采样和 Collector 短期不可用后的恢复。 |
| `OPENTELEMETRY_LOGS` | PostgreSQL 优化启动时，Collector 经 HTTP/protobuf 解码 Keycloak 启动日志，同时经 gRPC 接收跟踪和指标。转发探针记录 `POST /v1/logs` 返回 `200`。 | 回归 SDK 客户端日志与跟踪关联。 | 补级别过滤、重试和 Collector 短期不可用恢复。 |
| `OPENTELEMETRY_METRICS` | 同一 PostgreSQL 优化启动 profile 经 OTLP gRPC 投递可辨识的 Keycloak 指标。 | 以应用调用驱动可观测事件。 | 校验登录指标、标签、采集周期和时间序列。 |
| `QUICK_THEME` | 浏览器预览并下载主题 JAR，独立节点安装后提供选定的登录主题。 | 使用 realm 主题属性补管理配置回读。 | 验证安装后的账户及管理控制台样式和资源。 |
| `ROLLING_UPDATES_V1` | CLI 对日志配置变更返回 `0`。先后替换两个同版节点，129 轮业务探针全部通过，会话 ID 保持一致。历史 CLI 预检中，变更数据库配置返回 `3`。 | 将既有管理和认证客户端纳入更多部署拓扑的滚动回归。 | 补实际部署负载均衡器、生产流量模型和异常节点恢复。 |
| `ROLLING_UPDATES_V2` | CLI 对相同日志配置变更返回 `0`。独立集群逐台替换两个同版节点，129 轮业务探针全部通过，会话 ID 保持一致。历史 CLI 预检中，变更数据库配置返回 `3`。 | 将既有管理和认证客户端纳入更多部署拓扑的滚动回归。 | 补实际部署负载均衡器、生产流量模型和异常节点恢复。 |
| `SCRIPTS` | 服务端部署 JAR 内 mapper，真实 access token 包含预期自定义 claim。 | 复用 mapper 表示及写入授权回归。 | 验证禁用、配置拒绝和错误处理。 |
| `STATELESS` | 节点 A 开始授权后停止。共享新建 PostgreSQL 的节点 B 完成原 PKCE 事务。 | 补跨节点续接及令牌续期的 OIDC 回归。 | 验证节点并存、流量切换和动作令牌的持续有效性。 |
| `USER_EVENT_METRICS` | 真实登录令 realm 标签下的 Prometheus 登录计数从 `2` 变为 `3`。 | 以现有认证入口驱动事件。 | 核对成功、失败与注销事件、过滤和标签。 |

## 同版本在线替换与混合遥测

两个滚动模式使用独立 Docker 网络和全新的 PostgreSQL 数据库，启动前确认没有 Keycloak schema。每组用 `rolling-updates:v1` 或 `rolling-updates:v2` 启用对应模式。变更仅给 `org.keycloak.events` 增加 DEBUG 日志，检查兼容性返回 `0` 后，逐一关闭和替换节点 A、B。接手的节点须就绪并加入两成员 Infinispan 视图。固定入口持续请求 OIDC discovery、刷新原会话、读取管理员 API 和发起新登录。两组各通过 129 轮、516 次业务请求。每轮核对原用户和会话 ID。此结果适用于采用相同 26.8.2 镜像的配置滚动。 [Keycloak 滚动更新检查](https://www.keycloak.org/server/update-compatibility)

混合遥测使用 Keycloak `build` 后 `start --optimized` 和独立的 Collector 接收管线。`KC_TELEMETRY_PROTOCOL=grpc` 和 `KC_TELEMETRY_ENDPOINT=http://otel:4317` 用于跟踪与指标。`KC_TELEMETRY_LOGS_PROTOCOL=http/protobuf` 和 `KC_TELEMETRY_LOGS_ENDPOINT=http://otel-http:4318` 用于日志。Collector 解码了带测试服务标识的 HTTP 请求跟踪、指标和 Keycloak 启动日志。线路探针记录 `POST /v1/logs`、`application/x-protobuf` 和 HTTP `200`。对照运行把 `/v1/logs` 写入配置值，实测请求变成 `/v1/logs/v1/logs` 并收到 `404`。 [Keycloak 遥测配置](https://www.keycloak.org/observability/telemetry)

[机器可读验收记录](server-validation-followup.json)

## English summary

This review selected 28 flags from the 80-item upstream inventory. Twenty-three now have evidence from specific local scenarios. Five await dedicated environments. All follow-up runs used fresh data. In headless Chrome, the installed `UiPage` provider rendered a menu item, table, and generated field. The edited value survived a reload and matched an independent Admin REST read.

Independent two-node PostgreSQL clusters ran `rolling-updates:v1` and `rolling-updates:v2`. Both passed the compatibility check for a logging change, replaced both nodes sequentially on the same 26.8.2 image, and completed 129 probe cycles each with zero failures. Probes covered discovery, refresh of the original session, a new login, and Admin REST reads. The original subject and session ID persisted.

With PostgreSQL and optimized startup, the Collector decoded traces and metrics over gRPC and logs over HTTP/protobuf. The proxy recorded a successful `POST /v1/logs`. Setting the exporter URL to include that suffix caused a duplicate path and returned `404` in the control run. Dedicated environments are still needed for external caches and multi-site, TiDB, IPA/Tuura, and FIPS compliance. The pinned image loaded both PEM certificates with BCFIPS non-strict. Browser coverage here is for the tested `UiPage` provider. [FIPS runtime evidence](release-service-specialty-evidence.json) · [Bilingual upgrade notes](release-notes.md) · [Platform capability matrix](../../contracts/platform-capability-matrix.md)
