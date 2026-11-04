# Keycloak 26.8.1 Admin API 支持路线

发布基线固定为 26.8.1。路线声明在 [admin-api-routes.json](../../contracts/admin-api-routes.json)，部署与真实验收读取同一份配置，不从端口、请求是否成功或默认服务端行为猜测路线。

| 声明 ID | 用途 | 显式启用 | 预览/实验功能 |
| --- | --- | --- | --- |
| `fgap-v2-stable` | 默认正式路线 | `admin-fine-grained-authz:v2` | 不支持、不启用、不计入正式验收 |
| `fgap-v1-compat` | FGAP v1 兼容支持 | `admin-fine-grained-authz:v1` | 同样不启用；仅允许必要的 FGAP v1 兼容能力 |

选择顺序：进程环境变量 `KEYCLOAK_ADMIN_API_ROUTE` → `local/keycloak/.env` 中同名项 → JSON 的 `defaultRoute`。C# 服务入口将所选路线解析为 `KEYCLOAK_FEATURES`，把生效声明写回 `.env` 并输出路线名称；与路线冲突的手工 `KEYCLOAK_FEATURES` 会被拒绝。Compose 容器标签 `io.keycloak-admin-sdk.route` 也记录所选路线。

切换时修改 `.env` 中的 `KEYCLOAK_ADMIN_API_ROUTE`，运行：

```shell
dotnet run --file local/keycloak/Service.cs -- up
```

无需修改密码或删除数据库卷。声明 `fgap-v1-compat` 才会走旧版管理权限接口；v2 正式路线不调用 `/management/permissions`、`/users-management-permissions` 这类 v1 专用接口。SDK 保留完整 wire 接口清单，部署/验收声明决定当前支持范围；保留接口定义不等于正式功能支持声明。

## 版本与功能校验

每次启动检查都实际读取受保护的 `GET /admin/serverinfo`：

1. `systemInfo.version` 必须为 `26.8.1`。
2. 实际启用的 FGAP 版本必须与声明一致，另一版本须处于 disabled 状态。
3. `features[]` 中 `enabled=true` 的项目不能属于 PREVIEW、PREVIEW_DISABLED_BY_DEFAULT 或 EXPERIMENTAL。

`profileInfo.previewFeatures` / `experimentalFeatures` 是功能目录，包含未启用项目，不能用其非空与否判断运行状态。分类依据固定发布源码 `common/.../Profile.java` 和运行时 `FeatureRepresentation`。

26.8.1 的 `WORKFLOWS` 分类为 DEFAULT，属于正式路线验收；`OID4VC_VCI` 为 PREVIEW，`SSF`、`CLIENT_TYPES` 为 EXPERIMENTAL，明确排除。排除项有独立清单和原因，不能记作成功、跳过后通过或用 404 代替业务验收。

## 验收记录

真实业务验收入口：

```shell
dotnet run --file local/keycloak/Service.cs -- test-full
dotnet run --file local/keycloak/Service.cs -- test-full-native
```

每次执行核验实际服务器路线，记录到 `artifacts/full-live/<route>-<mode>.tsv`；未完成接口和被政策排除接口分别写入 `-missing.tsv`、`-excluded.tsv`。只有真实 SDK 调用成功且业务/数据断言通过才计入成功，未完成清单非空会返回非零。v2 正式范围 478 项，v1 兼容范围 492 项；托管和 Native AOT 的逐项结果见 [全功能验收](full-live-acceptance.md)。

两条路线分别验证实际 FGAP 权限效果：受限管理员写入初始为 403 → 在该路线的授权服务配置策略 → 读写成功且数据持久化 → 删除策略后再次 403，数据未被越权修改。v2 使用正式的 `admin-permissions` authorization schema；v1 通过旧版 management-permissions 关联 `realm-management` 授权资源。v2 不使用预览的 token 委派功能。

`Check-FullAcceptance.cs` 校验两种模式的当前代码指纹、实际功能开关、Keycloak/PostgreSQL 版本和逐项业务证明；`Test-AcceptanceGate.cs` 验证缺失、重复、失败、空证明、过期代码及缺少撤销验证等负向控制。CI 按显式路线矩阵运行全套真实托管/AOT 测试，保留独立排除清单。
