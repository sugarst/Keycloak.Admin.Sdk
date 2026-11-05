# 本地 Keycloak + PostgreSQL

从仓库根目录运行：

```shell
dotnet run --file local/keycloak/Service.cs
```

工具读取 [固定基线](../../contracts/baseline.json)，启动 Keycloak 26.8.1 + PostgreSQL 18.0，生成忽略提交的 `.env` 随机凭据，并检查 HTTP 就绪、管理员登录、服务器版本、路线及数据库 schema。

| 服务 | 默认地址 | 凭据 |
| --- | --- | --- |
| 管理控制台 | <http://127.0.0.1:18080/admin/> | 用户 admin，密码见 `.env` |
| Keycloak 管理/健康 | <http://127.0.0.1:19000/health/ready> | 就绪探针 |
| PostgreSQL | `127.0.0.1:15432` | 默认库/用户 keycloak，密码见 `.env` |

## 命令

以下参数追加到 `dotnet run --file local/keycloak/Service.cs --`，省略为 `up`：

| 参数 | 操作 |
| --- | --- |
| `up` / `check` | 启动并核验 / 仅核验运行服务 |
| `status` / `logs` | 容器状态 / 最近 100 行日志 |
| `down` | 移除本项目容器，保留数据库卷 |
| `test` / `test-native` | 早期隔离 realm 场景，托管 / Native AOT |
| `test-full` / `test-full-native` | 当前路线的全部业务验收 |
| `reset --delete-data` | 删除本项目数据库卷，以保留凭据重新初始化 |

测试自动注入 URL、用户名和密码，结束后删除测试 realm 并恢复管理员邮箱。托管程序在宿主机运行；Linux 自动叠加 `compose.linux.yaml` 提供回调地址，Docker Desktop 使用 `host.docker.internal`。原生程序共享 Keycloak 容器网络，通过 loopback 回调。

全功能测试启用 `acceptance` profile，增加固定 digest 的 OpenLDAP（本机 1389 端口，密码复用测试数据库密码），并叠加 `compose.acceptance.yaml` 配置 X509 证书头读取器。LDAP 每轮使用独立子树，PostgreSQL 夹具只修改测试 realm；普通 `up` 恢复基础配置，`down` 清理辅助容器。业务断言和结果见 [全功能验收](../../docs/contracts/full-live-acceptance.md)。

重跑两条路线、两种模式并恢复普通 v2 服务：

```shell
dotnet run --file tools/Test-AllAdminRoutes.cs -- --update-docs
```

## 配置与数据

配置项见 [.env.example](.env.example)。进程环境变量优先于 `.env`，修改端口等配置后重跑 `up`。路线通过 `KEYCLOAK_ADMIN_API_ROUTE` 声明，不直接改 `KEYCLOAK_FEATURES`，选择顺序和实际服务器校验见 [路线规则](../../docs/contracts/admin-api-routing.md)。

Compose 项目为 `keycloak-admin-sdk-local`，命名卷 `keycloak-admin-sdk-local_postgres_data` 挂载到 `/var/lib/postgresql`；PGDATA 为 `/var/lib/postgresql/18/docker`。`down` / `up` 保留数据。初始化密码只对空数据库生效，编辑 `.env` 不会修改已有角色密码；数据卷存在但凭据文件丢失时须恢复原凭据。

基线版本改变时工具停止启动，要求先选择备份/迁移或显式重置，不自动删除数据。清空数据使用：

```shell
dotnet run --file local/keycloak/Service.cs -- reset --delete-data
```

## 直接使用 Compose

首次运行生成 `.env` 后也可执行：

```shell
docker compose --project-name keycloak-admin-sdk-local --env-file local/keycloak/.env -f local/keycloak/compose.yaml up -d --wait
dotnet run --file local/keycloak/Service.cs -- check
```

Compose 仅等待数据库健康和 Keycloak 容器运行，完整 HTTP/版本核验由 `check` 完成。Linux 手动运行带宿主回调的托管测试还需叠加 `-f local/keycloak/compose.linux.yaml`。
