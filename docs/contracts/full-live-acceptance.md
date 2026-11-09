# 真实容器全功能验收

固定服务：Keycloak 26.8.1 + postgres:18.0-alpine3.22；构建 SDK 10.0.403，Native AOT 目标 linux-musl-x64。

| 路线 | 执行方式 | 业务断言通过 | 未完成 | 政策排除 | 完成时间 UTC |
| --- | --- | --- | --- | --- | --- |
| `fgap-v2-stable` | managed | 478/478 | 0 | 42 | 2026-11-09T06:34:06.1706755+00:00 |
| `fgap-v2-stable` | native-aot | 478/478 | 0 | 42 | 2026-11-09T06:34:31.5539962+00:00 |
| `fgap-v1-compat` | managed | 492/492 | 0 | 28 | 2026-11-09T06:31:44.1468458+00:00 |
| `fgap-v1-compat` | native-aot | 492/492 | 0 | 28 | 2026-11-09T06:33:14.6054679+00:00 |

逐接口结果和业务断言见 [full-live-acceptance.tsv](full-live-acceptance.tsv)。排除项不计入成功。范围和排除数量以当前基线及上述实测表为准。

托管入口使用 Managed Platform 的快照模式，标识 snapshot-v1；Native AOT 入口不引用 Platform，使用主包快照门禁，标识 core-snapshot-v1。两者均在能力目录判断后检查总闸与功能开关，并验证关闭创建无数据、开启创建持久化、关闭删除保留数据和刷新后删除成功；bootstrap 标识 not-loaded-bootstrap。Managed 还使用微软引擎执行真实创建、关闭拦截、恢复删除和协议总闸检查，并验证官方 FeatureEvaluation 到达本地遥测通道，microsoftFeatureManagementBusinessGuards 必须为 true；Native AOT 该项必须为 false。此本地通道不代表 Azure 云端投递。

全部结果来自真实 SDK 请求。写操作核对持久化或协议侧效果；只读操作核对已知真实资源、关系或已安装提供方。认证、SMTP、HTTP/JWKS、LDAP、X509/CRL 和 PostgreSQL 缓存验证均实际通信。外部协议夹具由 .NET 10 实现，LDAP 使用独立真实 OpenLDAP 容器。完整 wire 契约单测仍覆盖完整发布清单，政策排除不代表漏写单测。

证据清单保留实际版本、功能开关、数据库版本、原生/托管程序 SHA256、逐项 ledger SHA256 和代码指纹。门禁拒绝缺失、重复、非成功、无业务证明、旧源码或未完成记录。该验收覆盖每个支持范围内的方法/路径的业务场景，不宣称穷尽所有配置、策略类型和管理员权限组合。

重跑两个路线的 `Service.cs -- test-full` 与 `-- test-full-native`，然后执行 `dotnet run --file tools/Check-FullAcceptance.cs -- --update-docs`。路线声明与切换见 [admin-api-routing.md](admin-api-routing.md)。
