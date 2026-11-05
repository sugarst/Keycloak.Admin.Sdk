# Admin API 支持路线

部署与验收读取 [admin-api-routes.json](../../contracts/admin-api-routes.json)，精确目标见 [基线](../../contracts/baseline.json)。

| 路线 | 用途 | 显式启用 | 排除 |
| --- | --- | --- | --- |
| `fgap-v2-stable` | 默认正式路线 | `admin-fine-grained-authz:v2` | 预览/实验及 v1 专用接口 |
| `fgap-v1-compat` | FGAP v1 兼容 | `admin-fine-grained-authz:v1` | 预览/实验接口 |

选择顺序：进程 `KEYCLOAK_ADMIN_API_ROUTE` → `local/keycloak/.env` 同名项 → JSON `defaultRoute`。服务入口解析为 `KEYCLOAK_FEATURES`，写回 `.env`，并通过容器标签 `io.keycloak-admin-sdk.route` 记录；冲突的手工 feature 配置被拒绝。

修改声明后执行：

```shell
dotnet run --file local/keycloak/Service.cs -- up
```

不需要删卷或改密码。v2 不调用 `/management/permissions`、`/users-management-permissions` 等 v1 接口。SDK 保留完整生成清单；正式支持范围另由路线与能力策略约束。

## 运行时核验

启动检查实际读取受保护的 `GET /admin/serverinfo`，要求：

1. 服务器版本与基线精确一致。
2. FGAP 启用版本与声明一致，另一版本明确关闭。
3. 实际 `enabled=true` 的功能不属于 PREVIEW、PREVIEW_DISABLED_BY_DEFAULT 或 EXPERIMENTAL。

`profileInfo.previewFeatures` / `experimentalFeatures` 是功能目录，不能用其非空判断已启用。分类来自固定源码 `Profile.java` 和运行时 feature 数据。26.8.1 的 Workflows 为 DEFAULT，纳入正式验收；OID4VC_VCI 为 PREVIEW，SSF 和 CLIENT_TYPES 为 EXPERIMENTAL，均政策排除。

## 验收

使用本地服务 `test-full` / `test-full-native`，或按 [测试说明](../testing.md) 一次重跑全部路线。每次核验实际配置，输出 `artifacts/full-live/<route>-<mode>.tsv`、`-missing.tsv` 和 `-excluded.tsv`；成功响应与业务断言同时通过才计数，缺失项非空即失败。

两路线都验证委派管理员：初始 403 → 授权后读写及持久化 → 撤销后再次 403，数据未被越权修改。v2 使用正式 `admin-permissions` schema，v1 使用关联 `realm-management` 的旧管理权限；不启用预览 token 委派。数量、排除清单、环境与执行时间见 [真实验收](full-live-acceptance.md)。
