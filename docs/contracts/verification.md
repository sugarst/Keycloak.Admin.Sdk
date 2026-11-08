# 验证状态与发布边界

记录日期：2026-11-05。目标、源码和镜像以 [baseline.json](../../contracts/baseline.json) 为准；以下是仓库证据，远端 CI 状态以实际运行结果为准。

| 检查 | 证据 |
| --- | --- |
| 路由及静态契约对齐 | [源码审计](keycloak-26.8.1-alignment-audit.md)、[端点清单](endpoint-inventory.md) |
| 全操作单测及覆盖率 | [测试矩阵](admin-api-test-matrix.md)、[覆盖率报告](test-coverage.md) |
| 两条路线的托管 / Linux Native AOT 业务验收 | [逐项结果与执行时间](full-live-acceptance.md)、[支持及排除原因](admin-api-support-matrix.tsv) |
| 六条特殊路径的回归契约 | [媒体类型、动态查询与列表响应](six-path-fixes.md) |

核心与能力策略已实际在 `linux-musl-x64` 发布并运行；Windows 本机缺少 C++ 链接器和 Windows SDK，尚无本机 `win-x64` 原生通过记录。平台开关面 `Keycloak.Admin.Sdk.Platform` 面向托管与 Native AOT 宿主，不依赖外部特性管理引擎，也不提供遥测；旧托管扩展的 Application Insights 本地事件验证仅属历史记录。

## 发布限制

- 当前处于开发阶段，尚未发布 NuGet 包；不承诺旧 SDK API 兼容，旧 SDK 迁移映射尚未建立，公开命名和更新模型仍可能调整。
- 动态或源码独有契约仍有 `HttpContent` / `JsonElement` 入口，后续强类型化需要独立核实模型及状态码。
- 逐接口业务验收覆盖记录的场景，未穷尽权限、配置、策略提供方及第三方 SPI。SMTP、HTTP 等本地协议夹具不构成商业服务兼容性认证。
- 验收不自动延伸至其他 Keycloak 版本；新目标必须按 [升级与发布流程](../single-target-workflow.md) 重新建立证据。

完整范围及动态定位器边界见 [架构说明](../architecture.md)。不受策略的核心客户端可通过原始请求访问自定义接口；[能力策略客户端](../capability-policy.md) 拒绝目录外接口。

## 证据维护

数值结果由报告工具维护，本页只维护结论及限制。源码/工具变化可能使已提交验收指纹过期；发布前使用 `Test-AllAdminRoutes.cs -- --update-docs` 重跑并核验，不修改旧证据冒充新结果。原有 [live-endpoints.tsv](live-endpoints.tsv) 仅为早期隔离场景的辅助观测，当前全量业务结果以 `full-live-acceptance.tsv` 为准。
