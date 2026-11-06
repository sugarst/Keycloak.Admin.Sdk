# 真实容器全功能验收

固定服务：Keycloak 26.8.1 + postgres:18.0-alpine3.22；构建 SDK 10.0.403，Native AOT 目标 linux-musl-x64。

> 历史验收范围：本页结果对应[发布候选记录](../releases/26.8.1-preview.1/504a3c6981781b09e0f46f5f753fa9096b3c14e2104d4fd4d6fff725570f857b.json)中的 SDK 提交 `0d1213b` 和源码指纹。后续取消令牌修复尚未重跑真实容器验收，本页结果不作为当前分支源码的验收结论。

| 路线 | 执行方式 | 业务断言通过 | 未完成 | 政策排除 | 完成时间 UTC |
| --- | --- | --- | --- | --- | --- |
| `fgap-v2-stable` | managed | 478/478 | 0 | 42 | 2026-11-05T11:05:20.7118128+00:00 |
| `fgap-v2-stable` | native-aot | 478/478 | 0 | 42 | 2026-11-05T11:05:44.8816829+00:00 |
| `fgap-v1-compat` | managed | 492/492 | 0 | 28 | 2026-11-05T11:04:09.9831044+00:00 |
| `fgap-v1-compat` | native-aot | 492/492 | 0 | 28 | 2026-11-05T11:04:35.7001363+00:00 |

逐接口结果和业务断言见 [full-live-acceptance.tsv](full-live-acceptance.tsv)。排除项不计入成功。范围和排除数量以当前基线及上述实测表为准。

托管入口使用 Microsoft FeatureManagement 4.8.0，在目录判断后检查总开关及功能开关，并实际验证关闭创建无数据、开启创建持久化、关闭删除保留数据和刷新后删除成功。Native AOT 入口编译时排除托管功能开关扩展，仍使用能力策略；manifest 分别标识 microsoft-4.8.0 和 not-loaded-native-aot。Application Insights 仅做本地事件测试，未启用云端投递。

全部结果来自真实 SDK 请求。写操作核对持久化或协议侧效果；只读操作核对已知真实资源、关系或已安装提供方。认证、SMTP、HTTP/JWKS、LDAP、X509/CRL 和 PostgreSQL 缓存验证均实际通信。外部协议夹具由 .NET 10 实现，LDAP 使用独立真实 OpenLDAP 容器。完整 wire 契约单测仍覆盖完整发布清单，政策排除不代表漏写单测。

证据清单保留实际版本、功能开关、数据库版本、原生/托管程序 SHA256、逐项 ledger SHA256 和代码指纹。门禁拒绝缺失、重复、非成功、无业务证明、旧源码或未完成记录。该验收覆盖每个支持范围内的方法/路径的业务场景，不宣称穷尽所有配置、策略类型和管理员权限组合。

重跑两个路线的 `Service.cs -- test-full` 与 `-- test-full-native`，然后执行 `dotnet run --file tools/Check-FullAcceptance.cs -- --update-docs`。路线声明与切换见 [admin-api-routing.md](admin-api-routing.md)。
