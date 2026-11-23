# Keycloak 26.8.2 发布项验收矩阵

基线为官方 26.8.2 tag `e514445f9dcdabc5bdcf67cab56c1e49655de067`。本地镜像为 `quay.io/keycloak/keycloak:26.8.2-3`，验收环境使用新建数据。按官方公告逐项登记 **59 项**，包括安全修复 33 项、加固 5 项、增强 1 项和缺陷修复 20 项。 [官方发布公告](https://www.keycloak.org/2026/11/keycloak-2682-released) · [26.8.2 升级指南](https://www.keycloak.org/docs/26.8.2/upgrading/)

**定向通过**表示已记录该发布项的相关业务断言，具体范围见各行。**相关证据**表示已验收关联功能，行内列出仍待核验的发布行为。**待专项**表示尚缺该行为的验收证据。**上游维护**表示发布项对应上游文档、测试或 CI。SDK 支持范围和服务端功能开关分别由能力矩阵及服务端专项记录维护。 [能力矩阵](../../contracts/platform-capability-matrix.md) · [服务端专项](server-validation.md) · [兼容应用协议证据](../../contracts/application-protocol-legacy-workflows.md) · [标准协议证据](../../contracts/application-protocol-workflows.md)

矩阵共有 **13 项定向通过、31 项有相关证据、9 项待专项、6 项属于上游维护**。本次在 7 个隔离配置中重新采集了 10 个发布项的证据，其中 9 项满足所列定向场景。SAML 安装 XML 通过了 issuer 核对，Java Adapter 的运行验证仍待完成。 [机器可读专项证据](release-issue-acceptance-evidence.json)

后续协议验收的重点包括 Device 最低 ACR、CIBA 保留字段、组织自动关联与邮件验证、SAML Broker 和后通道注销、管理 token 的独立 audience 组合。Operator Helm、FIPS、多站点与外置缓存需要对应的服务端环境或制品。兼容性验收采用新建 realm、用户及数据库；同版本滚动的证据见服务端专项。

## 安全修复（33）

| 发布项 | 行为 | 归属 | 证据状态 | 已验证范围和剩余缺口 |
| --- | --- | --- | --- | --- |
| [#53061](https://github.com/keycloak/keycloak/issues/53061) | 组织取消关联与跨浏览器证明生命周期 | 服务端／身份代理 | 相关证据 | 已有同用户代理关联、取消和状态回读。待核对跨浏览器证明在关联完成后的生命周期。 |
| [#53618](https://github.com/keycloak/keycloak/issues/53618) | 设备登录最低 ACR | 协议互操作 | 相关证据 | 标准协议工作流覆盖真实设备同意与签名令牌。待验收配置最低 ACR 后的设备登录逐级认证。 |
| [#53749](https://github.com/keycloak/keycloak/issues/53749) | DCR 保留离线令牌撤销配置 | SDK／协议互操作 | 定向通过 | 读取、更新、回读保留后通道注销撤销离线令牌的设置，Managed 与 Native AOT 均通过。 |
| [#53813](https://github.com/keycloak/keycloak/issues/53813) | 登录页内容清理 | 服务端 | 相关证据 | 已有真实登录渲染与主题替换。发布项的输入清理边界待对照上游修复与回归记录。 |
| [#54333](https://github.com/keycloak/keycloak/issues/54333) | 随发行包提供的 Brotli 组件修复 | 服务端／依赖 | 待专项 | 固定镜像已确认，待制品级组件版本或厂商补丁证明。 |
| [#54687](https://github.com/keycloak/keycloak/issues/54687) | MySQL 和 MariaDB 登录失败计数 | 服务端／数据库 | 定向通过 | 两套新库在普通失败登录间隔下均按 1、2、3 递增。管理端清除后为 0，正常登录成功。 |
| [#54688](https://github.com/keycloak/keycloak/issues/54688) | 组织 identity-first 登录上下文 | 服务端／身份代理 | 相关证据 | 已有组织管理及普通代理登录的业务证据。待核对同组织新旧登录上下文隔离。 |
| [#54689](https://github.com/keycloak/keycloak/issues/54689) | 主题 gzip 缓存资源约束 | 服务端 | 待专项 | 正常主题 gzip 测试只佐证资源加载。待核对缓存资源约束及上游修复依据。 |
| [#54690](https://github.com/keycloak/keycloak/issues/54690) | SAML 端点资源保护 | 服务端 | 相关证据 | SAML 登录和 Artifact/ECP 正常工作流已通过。端点资源保护待独立核验。 |
| [#54691](https://github.com/keycloak/keycloak/issues/54691) | 浏览器注销会话归属 | 服务端／协议互操作 | 相关证据 | 已有 OIDC 正常注销和会话删除证据。官方公告对应的会话归属隔离待验证。 |
| [#54692](https://github.com/keycloak/keycloak/issues/54692) | 旧 SAML 1.1 解析器保护 | 服务端 | 待专项 | 官方升级指南记录默认关闭 SAML 1.1。待验证服务端默认配置和兼容开关。 |
| [#54693](https://github.com/keycloak/keycloak/issues/54693) | 旧 SAML 1.1 解析资源保护 | 服务端 | 待专项 | 同属旧解析器边界。待验证默认关闭和上游修复依据。 |
| [#54694](https://github.com/keycloak/keycloak/issues/54694) | DCR Mapper 的令牌声明边界 | SDK／服务端 | 相关证据 | 已验证 realm 与注册策略白名单交集。该发布项的声明边界仍需独立证据。 |
| [#54695](https://github.com/keycloak/keycloak/issues/54695) | CIBA 保留字段验证 | 协议互操作 | 相关证据 | CIBA poll、ping 和签名请求通过。发布项的保留字段校验待补证。 |
| [#54696](https://github.com/keycloak/keycloak/issues/54696) | UMA 资源类型与所有者隔离 | 协议互操作 | 相关证据 | 已有资源共享、所有者授权、撤销和拒绝。资源类型边界待补证。 |
| [#54697](https://github.com/keycloak/keycloak/issues/54697) | 无会话令牌主体及管理权限边界 | SDK／服务端 | 相关证据 | 已验证常规管理 token 和委派 Mapper 权限。无会话主体边界待补证。 |
| [#54698](https://github.com/keycloak/keycloak/issues/54698) | DCR 属性 Mapper 的保留声明检查 | SDK／服务端 | 相关证据 | 已有 DCR Mapper 白名单和保留既有 Mapper 的证据。声明级校验待补证。 |
| [#54699](https://github.com/keycloak/keycloak/issues/54699) | FGAP 委派组移动权限 | SDK／服务端 | 相关证据 | 已有组业务及 FGAP 授权生命周期。组移动的特定拒绝边界待补证。 |
| [#54700](https://github.com/keycloak/keycloak/issues/54700) | 标准交换令牌有效期限制 | 协议互操作 | 定向通过 | 正常客户端对 75 秒的原令牌执行标准交换。新客户端寿命为 300 秒，签名验证后的 access token 和 ID token 均与原令牌同时到期。 |
| [#54701](https://github.com/keycloak/keycloak/issues/54701) | Protocol Mapper 保留资源访问声明 | SDK／服务端 | 相关证据 | 已有 Mapper 委派写入约束。各令牌和协议输出的声明边界待补证。 |
| [#54702](https://github.com/keycloak/keycloak/issues/54702) | DCR 禁止修改 realm 默认角色 | SDK／协议互操作 | 定向通过 | 注册修改默认角色被拒绝，独立回读确认 realm 默认角色组合保持既有状态。 |
| [#54703](https://github.com/keycloak/keycloak/issues/54703) | 上游 Java SAML Adapter 的 issuer 校验 | 上游 Adapter | 相关证据 | 新建 SAML 客户端下载的安装 XML 使用实际 realm URL 作为 IdP entityID。Java Adapter 本身的 issuer 校验待运行验证。 |
| [#54704](https://github.com/keycloak/keycloak/issues/54704) | 管理 CLI 自定义信任库 | 服务端／CLI | 待专项 | 待验证 kcadm 和 kcreg 使用显式导入证书时的正常 TLS 互操作。 |
| [#54705](https://github.com/keycloak/keycloak/issues/54705) | DCR 默认 Mapper 策略保护保留声明 | SDK／服务端 | 相关证据 | 已有 Mapper 白名单正反向验收。默认策略的独立声明断言待补证。 |
| [#54706](https://github.com/keycloak/keycloak/issues/54706) | 认证并发与会话隔离 | 服务端 | 相关证据 | 已有普通登录及会话连续性。认证并发隔离待专项核对。 |
| [#54707](https://github.com/keycloak/keycloak/issues/54707) | 身份自动关联要求可信邮件 | 服务端／身份代理 | 相关证据 | 已有确认式代理关联。自动关联的 verified 与 Trust Email 组合待验收。 |
| [#54708](https://github.com/keycloak/keycloak/issues/54708) | 无状态令牌与身份重新绑定防护 | 服务端 | 相关证据 | 同一 PostgreSQL 上的无状态 PKCE 跨节点接续已通过。客户端生命周期边界待验收。 |
| [#54709](https://github.com/keycloak/keycloak/issues/54709) | SAML SOAP 请求体上限 | 服务端 | 相关证据 | 正常 SOAP Artifact 解析和 ECP 已通过。官方请求体上限配置及边界待核验。 |
| [#54710](https://github.com/keycloak/keycloak/issues/54710) | FGAP v2 组合角色授权边界 | SDK／服务端 | 相关证据 | 已有角色组合与委派权限工作流。组合角色的发布特定限制待补证。 |
| [#54711](https://github.com/keycloak/keycloak/issues/54711) | SAML Broker 的 bearer 确认 | 协议互操作／服务端 | 相关证据 | 普通代理登录与 SAML SP 工作流已有实测。Broker 对标准 bearer 断言的专项待补。 |
| [#54712](https://github.com/keycloak/keycloak/issues/54712) | SAML Broker 的 ProxyRestriction 处理 | 协议互操作／服务端 | 相关证据 | 普通 SAML 协议已有实测。Broker 默认策略和开关配置待独立验收。 |
| [#54713](https://github.com/keycloak/keycloak/issues/54713) | Admin REST scope 与 audience 校验 | SDK／服务端 | 相关证据 | 固定镜像中默认和可选 scope、未请求 scope、权限不足均有定向断言。独立 audience 配置组合尚未验收。 |
| [#54714](https://github.com/keycloak/keycloak/issues/54714) | SAML Redirect 签名校验 | 协议互操作／服务端 | 相关证据 | Managed 的标准 Redirect 签名及关联检查通过。Broker 的发布特定输入验证待补证。 |

## 加固（5）

| 发布项 | 行为 | 归属 | 证据状态 | 已验证范围和剩余缺口 |
| --- | --- | --- | --- | --- |
| [#50917](https://github.com/keycloak/keycloak/issues/50917) | 会话统计按客户端可见性过滤 | SDK／服务端 | 定向通过 | FGAP v2 专项确认仅有 realm 查看权限时为空，manage-only 客户端不会进入统计。 |
| [#52104](https://github.com/keycloak/keycloak/issues/52104) | OIDC 请求对象的 JWE 算法与密钥绑定 | 协议互操作 | 相关证据 | 已有签名与加密请求对象工作流。发布项的算法和密钥类型边界待补证。 |
| [#53210](https://github.com/keycloak/keycloak/issues/53210) | 授权路径规范化 | 服务端／授权 | 相关证据 | 已有真实资源策略和 UMA 许可判定。服务端路径规范化的边界待核验。 |
| [#53535](https://github.com/keycloak/keycloak/issues/53535) | SAML 后通道注销签名要求 | 协议互操作／服务端 | 相关证据 | 已验证浏览器前通道签名注销与会话删除。后通道 SessionIndex 互操作待验收。 |
| [#53815](https://github.com/keycloak/keycloak/issues/53815) | 组织按域入会要求验证邮件 | 服务端／身份代理 | 相关证据 | 已有组织管理、邀请和真实 SMTP。OIDC IdP 邮件验证与按域入会组合待验收。 |

## 增强（1）

| 发布项 | 行为 | 归属 | 证据状态 | 已验证范围和剩余缺口 |
| --- | --- | --- | --- | --- |
| [#54184](https://github.com/keycloak/keycloak/issues/54184) | Quarkus 更新到 3.40.1.1 | 服务端／依赖 | 定向通过 | 固定镜像启动日志显示 Keycloak 26.8.2 和 Quarkus 3.40.1.1。 |

## 缺陷修复（20）

| 发布项 | 行为 | 归属 | 证据状态 | 已验证范围和剩余缺口 |
| --- | --- | --- | --- | --- |
| [#44474](https://github.com/keycloak/keycloak/issues/44474) | 会话数上限与登录失败计数分开 | 服务端 | 定向通过 | 单会话上限下，第二次正确登录返回 403，只保留原会话，失败计数为 0。退出原会话后可重新登录。 |
| [#51630](https://github.com/keycloak/keycloak/issues/51630) | 保护 FGAP v2 内部 admin-permissions 客户端 | SDK／服务端 | 定向通过 | 委派更新与删除均返回 403，独立回读确认内部客户端保留。 |
| [#52870](https://github.com/keycloak/keycloak/issues/52870) | 带独立用户 JSON 的 realm 导入 | 服务端／导入 | 定向通过 | 空库启动导入新建 realm JSON 和独立用户文件。Admin API 回读及导入用户的正常登录均通过。 |
| [#52968](https://github.com/keycloak/keycloak/issues/52968) | 运行期间 UDP 套接字生命周期 | 服务端 | 待专项 | 待固定网络拓扑的长时运行与资源趋势证据。 |
| [#53238](https://github.com/keycloak/keycloak/issues/53238) | 冷 gzip 主题缓存的并发读取 | 服务端 | 定向通过 | 新容器首次并发请求真实登录主题的 gzip CSS，12 次均返回 200，解码后的内容 SHA-256 一致。 |
| [#53507](https://github.com/keycloak/keycloak/issues/53507) | 下游文档建议内容 | 上游文档 | 上游维护 | 公告登记为文档变更，归入发布文档审阅。 |
| [#53510](https://github.com/keycloak/keycloak/issues/53510) | 下游文档中的讨论链接范围 | 上游文档 | 上游维护 | 公告登记为文档变更，归入发布文档审阅。 |
| [#53612](https://github.com/keycloak/keycloak/issues/53612) | BCFIPS 加载 PEM 中的全部证书 | 服务端／FIPS | 待专项 | 需要受支持的 FIPS JVM 和 BCFIPS 依赖。 |
| [#53634](https://github.com/keycloak/keycloak/issues/53634) | 身份代理错误事件及响应处理 | 服务端／身份代理 | 相关证据 | 正常代理流程及部分拒绝场景已验证。错误事件计数和响应内容待核验。 |
| [#53760](https://github.com/keycloak/keycloak/issues/53760) | SAML XML 验证并发安全 | 服务端 | 相关证据 | 已有 SAML 业务验收。普通 XML 验证的并发行为待专项。 |
| [#53804](https://github.com/keycloak/keycloak/issues/53804) | Operator Helm 版本标签 | 上游 Operator | 待专项 | 需要实际发布 chart 的渲染结果与部署版本核对。 |
| [#53809](https://github.com/keycloak/keycloak/issues/53809) | 拓扑变更期间分布式缓存锁竞争 | 服务端／缓存 | 相关证据 | 同版滚动 v1/v2 均有双节点证据。缓存锁竞争期间的拓扑变更待单独验收。 |
| [#53819](https://github.com/keycloak/keycloak/issues/53819) | 下游 Keycloak 链接 | 上游文档 | 上游维护 | 公告登记为文档变更，归入发布文档审阅。 |
| [#53834](https://github.com/keycloak/keycloak/issues/53834) | OID4VC 控制台可见性测试稳定性 | 上游测试 | 上游维护 | 公告项调整上游 E2E 测试。SDK 侧已有钱包业务证据。 |
| [#53898](https://github.com/keycloak/keycloak/issues/53898) | 数据库锁获取失败的诊断 | 服务端／数据库 | 待专项 | 待在独立数据库中核对启动失败原因的可观察性。 |
| [#53901](https://github.com/keycloak/keycloak/issues/53901) | 启动失败后的日志过滤 | 服务端 | 定向通过 | 隔离容器连接配置的不可用数据库后退出，日志保留 JDBC 连接失败诊断，且无二次日志过滤异常。 |
| [#53930](https://github.com/keycloak/keycloak/issues/53930) | 用户存储按配置周期同步 | 服务端／LDAP | 定向通过 | 在独立新数据中分别完成四次 LDAP 全量与四次变更用户同步。每次同步均超过一秒，按配置约每 10 秒启动。 |
| [#53999](https://github.com/keycloak/keycloak/issues/53999) | Locale Cookie 只写入受支持的语言 | 服务端／登录 | 定向通过 | 普通自助注册页接受已配置的 de 并写入 Cookie，未将不受支持的 zz 持久化。 |
| [#54173](https://github.com/keycloak/keycloak/issues/54173) | 更新上游 Playwright 基础设施 | 上游测试 | 上游维护 | 公告项更新上游 JS 测试依赖，归入上游测试基础设施。 |
| [#54398](https://github.com/keycloak/keycloak/issues/54398) | 上游 FIPS CI 依赖与密钥生成 | 上游 CI／FIPS | 上游维护 | 公告项涉及上游 CI。FIPS 生产模式另在服务端专项中等待专用环境。 |
