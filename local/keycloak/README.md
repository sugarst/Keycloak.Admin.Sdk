# 本地 Keycloak + PostgreSQL 测试服务

从仓库根目录执行一条命令：

```shell
dotnet run --file local/keycloak/Service.cs
```

该 .NET 10 文件式 C# 程序调用 Docker Compose，首次生成 `.env` 中的随机管理员/数据库密码，启动服务并等待真实就绪；随后验证管理员登录、受保护的 Admin API、Keycloak 实际版本、PostgreSQL 实际版本及 Keycloak 数据表。SDK 固定为 **10.0.403**。

## 服务与访问

| 服务 | 固定镜像 | 本机地址 |
| --- | --- | --- |
| Keycloak | `quay.io/keycloak/keycloak:26.8.1` | <http://127.0.0.1:18080/admin/> |
| Keycloak readiness | 同上，管理端口 9000 | <http://127.0.0.1:19000/health/ready> |
| PostgreSQL | `postgres:18.0-alpine3.22` | `127.0.0.1:15432` |

管理员默认用户名为 `admin`；密码查看当前目录生成的 `.env` 中 `KEYCLOAK_ADMIN_PASSWORD`。数据库默认名称/用户均为 `keycloak`，密码为 `POSTGRES_PASSWORD`。密码文件已从 Git 和 Docker 构建上下文排除，工具不打印密码。

这是用于本机测试的 `start-dev` 服务，端口只绑定 loopback。默认路线为 `fgap-v2-stable`，显式启用 FGAP v2，仅支持 26.8.1 正式功能；FGAP v1 需要声明 `fgap-v1-compat`。路线 JSON、环境变量、功能阶段和实际服务器核验规则见 [路线声明](../../docs/contracts/admin-api-routing.md)。Keycloak 的初始化管理员环境变量采用[官方容器配置](https://www.keycloak.org/server/containers)。

## 日常命令

以下命令均从仓库根目录执行；省略参数等同于 `up`。

```shell
dotnet run --file local/keycloak/Service.cs -- up          # 幂等启动并等待/核验就绪
dotnet run --file local/keycloak/Service.cs -- check       # 只检查已运行服务、登录及版本
dotnet run --file local/keycloak/Service.cs -- status      # 查看两个服务的容器状态
dotnet run --file local/keycloak/Service.cs -- logs        # 最近 100 行日志
dotnet run --file local/keycloak/Service.cs -- down        # 停止并移除本项目容器，保留数据库卷
dotnet run --file local/keycloak/Service.cs -- test        # 启动环境并运行现有托管真实集成测试
dotnet run --file local/keycloak/Service.cs -- test-native # 构建并运行 Native AOT 真实集成测试
dotnet run --file local/keycloak/Service.cs -- test-full   # 声明路线的全部真实业务验收
dotnet run --file local/keycloak/Service.cs -- test-full-native # 全部业务场景的 Native AOT 实跑
```

`test` / `test-native` 自动从 `.env` 注入 `KC_TEST_URL`、`KC_TEST_USERNAME` 和 `KC_TEST_PASSWORD`，在独立测试 realm 中操作，结束后删除该 realm；SMTP 夹具使用的管理员邮箱会恢复。原生程序共享 Keycloak 容器网络，以 loopback 访问服务和 .NET SMTP/元数据夹具。托管程序运行在宿主机；Linux 自动叠加 `compose.linux.yaml` 提供宿主机回调地址，Docker Desktop 使用内置 `host.docker.internal`。

`test` / `test-native` 保留原有 91 个方法/路径场景。全功能验收使用 `test-full` / `test-full-native`：v2 正式路线 478/478、v1 兼容路线 492/492，两种执行方式均通过，政策排除项单独列出。逐接口业务证明见 [全功能验收](../../docs/contracts/full-live-acceptance.md)。全量 SDK 单元测试及覆盖率门禁继续由 `tools/Verify.cs` 执行。

全功能测试自动启用 `acceptance` Compose profile，附加真实 OpenLDAP（固定镜像 digest），本机端口 `127.0.0.1:1389`，密码复用 `.env` 的随机测试密码；每轮创建并删除自己的目录子树。`compose.acceptance.yaml` 仅在全功能验收时叠加，配置发布版本的 X509 证书头读取器，用真实签名 CRL 验证吊销缓存。普通 `up` 恢复基础 Keycloak 配置；数据库卷保留。LDAP 辅助服务随 `down` 清理。

一次重跑两条路线、托管和 AOT 四套完整场景并更新证据：`dotnet run --file tools/Test-AllAdminRoutes.cs -- --update-docs`。入口显式注入每次的 `KEYCLOAK_ADMIN_API_ROUTE`，结束后恢复普通 `fgap-v2-stable` 服务和 `.env` 声明。

测试还会直接通过 SCRAM-SHA-256 连接真实 PostgreSQL，仅修改自己创建的隔离 realm，以验证清理 realm 缓存前后的陈旧/最新数据。LDAP 与 PostgreSQL 协议夹具均为 .NET 10 BCL 代码；不引入 SDK 运行时包或其他脚本语言。

## 配置与持久化

支持的配置列在 [.env.example](.env.example)。首次启动前可设置同名环境变量，或在后续启动前编辑 `.env`；环境变量优先于文件。默认端口为 18080、19000、15432；修改后重新运行 `up`。

Compose 项目名为 `keycloak-admin-sdk-local`。数据库命名卷为 `keycloak-admin-sdk-local_postgres_data`，挂载到 `/var/lib/postgresql`；镜像实际 PGDATA 为 `/var/lib/postgresql/18/docker`。这是 [PostgreSQL 18 官方镜像的版本化目录方式](https://docs.docker.com/guides/postgresql/)。`down` / `up` 保留数据库、realm、用户及客户端数据。

初始化密码只对空数据库生效。已有数据库时，修改 `.env` 不会自动修改数据库角色或 Keycloak 管理员的密码；保留原有凭据，或通过相应管理接口修改。数据库卷存在而 `.env` 丢失时，工具会要求恢复凭据文件，避免生成不匹配的新密码。

需要清空本地数据库并重新初始化时，显式执行：

```shell
dotnet run --file local/keycloak/Service.cs -- reset --delete-data
```

该命令删除**此 Compose 项目**的容器和数据库卷，再用保留的 `.env` 启动空数据库。其他命令不会删除数据库卷；不带 `--delete-data` 的 `reset` 会被拒绝。

## 直接使用 Docker Compose

`.env` 已经由首次启动生成后，也可以直接执行：

```shell
docker compose --project-name keycloak-admin-sdk-local --env-file local/keycloak/.env -f local/keycloak/compose.yaml up -d --wait
```

直接 Compose 命令等待 PostgreSQL 健康及 Keycloak 容器运行；完整的 Keycloak HTTP/数据库就绪和版本确认由 `Service.cs check` 完成。Keycloak 官方镜像不附带 HTTP 命令行工具，因此采用宿主机 .NET `HttpClient` 探针，不增加 shell 脚本或定制 Keycloak 镜像。

Linux 宿主机需要运行带回调的托管测试时，使用 C# 入口自动选择配置；手工启动则补充 `-f local/keycloak/compose.linux.yaml`。

## 本次验证

2026-11-04 在本机 Docker 实际启动上述两个镜像并确认：Keycloak **26.8.1**、PostgreSQL **18.0**，就绪端点返回 UP，管理员认证及 Admin API 成功，数据库已有 Keycloak `realm` 表。已验证 `down` / `up` 后 PostgreSQL 集群标识不变、原有凭据继续有效；测试 realm 结束后清理。执行日志位于 `artifacts/compose-managed.log` 和 `artifacts/compose-native.log`。
