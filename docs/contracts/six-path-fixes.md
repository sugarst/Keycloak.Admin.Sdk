# 六路径契约修复与验收

验证日期：2026-11-04。六条路径的契约缺口已全部修复，六组独立断言、托管真实容器测试及 Native AOT 真实容器测试均通过。

## 固定来源

- .NET SDK：**10.0.403**；目标框架 `net10.0`；JSON 反射序列化关闭。
- Keycloak：**26.8.1**；发布源码提交 `24ed1dadf3f246a555adb6d3d4a99e9b3003fb3b`；源码归档与 132 个索引文件的 SHA256 校验通过。
- 本地镜像：`quay.io/keycloak/keycloak:26.8.1`；核验 RepoDigests 后使用 image ID `sha256:817e41712252d6d3a2a61ac5d2a011be561d7942cee8227ee418ababa5f52b9a` 启动。
- 基线镜像 digest：`sha256:79c623a22abacf3fe6c00a5fb30f5b7843d717b234033b80995891c06116d244`；测试平台 `linux/amd64`。完整来源及哈希见 [baseline.json](../../contracts/baseline.json)。

## 修复与独立测试

以下路径均以 `/admin/realms/{realm}` 开头；授权路径中的 `{client-uuid}` 是客户端内部 ID。

| 方法及后续路径 | 按发布源码修复的契约 | 独立断言 | 托管 / 原生真实验证 |
| --- | --- | --- | --- |
| GET `/workflows/scheduled/{resource-id}` | `WorkflowsResource.getScheduledWorkflows` 返回 `List<WorkflowRepresentation>`，不采用错误的单对象 OpenAPI 注解 | `ScheduledWorkflowsAreArrays`：空数组、两元素数组及字段 | 空列表 → 创建并激活工作流 → 列表包含工作流 ID、名称和步骤；两种模式通过 |
| GET `/clients/{client-uuid}/authz/resource-server/policy/{type}` | 合并 ID 与 provider-type 分支的查询契约；保留对象/数组响应 | `PolicyProviderQueryContract`：11 个参数、false/0、Unicode 编码、缺省省略及两种响应 | 建立两个 user policy，验证筛选、分页和 ID 分支；两种模式通过 |
| GET `/clients/{client-uuid}/authz/resource-server/permission/{type}` | 合并继承的 `findAll` 与 ID 分支查询契约；保留对象/数组响应 | `PermissionProviderQueryContract`：同上，独立执行 permission 路径 | 建立两个 scope permission，验证筛选、分页和 ID 分支；两种模式通过 |
| POST `/identity-provider/import-config` | 通过 `HttpContent` 保留 JSON 与 multipart，文件分支包含 `providerId`、`file` | `IdentityProviderImportMediaContract`：MIME、boundary、字段、文件名、UTF-8 内容及 JSON 原文 | 上传 SAML 元数据并核对解析结果；JSON `fromUrl` 触发真实 HTTP 拉取；两种模式通过 |
| POST `/localization/{locale}` | 通过 `HttpContent` 保留 JSON 与 multipart `file` 分支 | `LocalizationImportMediaContract`：两种媒体类型及 UTF-8 原文 | 两种方式写入不同中文值，再 GET 核对持久化结果；两种模式通过 |
| POST `/testSMTPConnection` | 通过 `HttpContent` 保留 JSON 与已废弃但仍存在的 form `config` 分支 | `SmtpTestMediaContract`：MIME、form 单次编码及 JSON 原文 | JSON/form 各向 .NET SMTP 接收器投递一封邮件，实际收件数为 2；两种模式通过 |

源码依据：[工作流列表](https://github.com/keycloak/keycloak/blob/24ed1dadf3f246a555adb6d3d4a99e9b3003fb3b/services/src/main/java/org/keycloak/workflow/admin/resource/WorkflowsResource.java#L157)、[授权动态分派及查询](https://github.com/keycloak/keycloak/blob/24ed1dadf3f246a555adb6d3d4a99e9b3003fb3b/services/src/main/java/org/keycloak/authorization/admin/PolicyService.java#L96)、[身份提供方导入](https://github.com/keycloak/keycloak/blob/24ed1dadf3f246a555adb6d3d4a99e9b3003fb3b/services/src/main/java/org/keycloak/services/resources/admin/IdentityProvidersResource.java#L135)、[本地化文件导入](https://github.com/keycloak/keycloak/blob/24ed1dadf3f246a555adb6d3d4a99e9b3003fb3b/services/src/main/java/org/keycloak/services/resources/admin/RealmLocalizationResource.java#L110)、[SMTP 双媒体分支](https://github.com/keycloak/keycloak/blob/24ed1dadf3f246a555adb6d3d4a99e9b3003fb3b/services/src/main/java/org/keycloak/services/resources/admin/RealmAdminResource.java#L1145)。

两条授权路径原有 `fields` 之外，分别补齐 `policyId`、`name`、`type`、`resourceType`、`resource`、`scope`、`permission`、`owner`、`first`、`max`。路径参数仍名为 `type`，同名查询参数在 C# 中名为 `typeQuery`，发送的 wire key 仍是 `type`。服务端按所选 provider 分支决定过滤行为，包括覆盖部分 `type` / `permission` 条件，SDK 不改变其规则。

## 实现方式及调用变更

生成器在路由去重前保留全部 526 个处理分支，写入 [source-dispatches.json](../../contracts/source-dispatches.json)，再生成 520 个方法。相同方法和路径的查询参数取并集；多媒体分支保留调用方的 `HttpContent`。工作流响应修正写入 [overrides.json](../../contracts/overrides.json)，并生成列表的 JSON 元数据。响应修正保留原有成功及失败状态码定义。

三个媒体分支方法的请求参数现在是 `HttpContent`；JSON 调用也须显式提供内容类型。以下示例中的 `sdk` 为 `KeycloakAdminClient`：

```csharp
using System.Text;

// JSON 本地化
await sdk.RealmLocalization.CreateOrUpdateRealmLocalizationTextsFromFileAsync(
    "demo", "zh-CN",
    new StringContent("{\"greeting\":\"你好\"}", Encoding.UTF8, "application/json"));

// multipart 身份提供方元数据
var upload = new MultipartFormDataContent();
upload.Add(new StringContent("saml"), "providerId");
upload.Add(new ByteArrayContent(await File.ReadAllBytesAsync("metadata.xml")),
    "file", "metadata.xml");
var imported = await sdk.IdentityProviders.ImportFromAsync("demo", upload);

// 工作流数组，包含合法的空列表
var scheduled = await sdk.Workflows.GetScheduledWorkflowsAsync("demo", "user-id");
foreach (var workflow in scheduled.Body ?? []) Console.WriteLine(workflow.Name);
```

SMTP JSON 使用 `StringContent(json, Encoding.UTF8, "application/json")`；兼容表单使用 `new FormUrlEncodedContent(new Dictionary<string, string> { ["config"] = json })`。请求会消费并释放传入的内容，每次调用须构造新内容。

## 验证结果与复现

| 检查 | 本次结果 |
| --- | --- |
| Release 构建、AOT/裁剪分析 | 通过，零警告 |
| MSTest | 当前 **538 / 538**，含全量 520 个操作矩阵、六组手写契约及新增 SAML/隐式 multipart 回归；见 [覆盖率门禁](test-coverage.md) |
| 独立源码审计 | 官方 415、源码/SDK 520、分派变体 526；路由、查询、媒体类型、请求体缺口为 **0**；205 项可比返回类型差异 **0** |
| Native AOT 无网络冒烟 | .NET 10.0.403 / `linux-musl-x64` 实际编译并执行，520 个方法及六组独立断言通过 |
| 托管真实 Keycloak | 六路径 **6 / 6**；全部集成场景通过 |
| Native AOT 真实 Keycloak | 原生 ELF 直接执行，六路径 **6 / 6**；全部集成场景通过 |
| 真实观测总量 | 91 个不同方法/路径，93 条方法/路径/状态码记录 |
| NuGet 包检查 | 核心 SDK 运行时包依赖为 0 |

手写断言位于 [AlignmentContracts.cs](../../tests/Keycloak.Admin.Sdk.Tests/AlignmentContracts.cs)，与生成响应样本独立；通过源码链接同时进入原生冒烟程序。真实测试位于 [AlignmentLive.cs](../../tests/Keycloak.Admin.Sdk.IntegrationTests/AlignmentLive.cs)，HTTP 元数据及 SMTP 夹具位于 [CallbackFixture.cs](../../tests/Keycloak.Admin.Sdk.IntegrationTests/CallbackFixture.cs)，均使用 .NET 10 实现。工作流测试启用 `workflows`，激活时使用源码定义的 `USERS` 资源类型及未来调度时间。测试创建独立 realm，退出时清理 realm 和容器。

以下命令按顺序运行，避免文件式工具编译缓存被并发进程占用：

```shell
dotnet run --file tools/Update-Contracts.cs
dotnet run --file tools/Verify.cs -- --native-container
dotnet run --file tools/Test-Integration.cs
dotnet run --file tools/Test-Integration.cs -- --native-aot
dotnet run --file tools/Update-Verification.cs
dotnet run --file tools/Audit-Contracts.cs
```

`Audit-Contracts.cs` 默认核验固定本地来源；加 `-- --online` 可再核验远端 tag 与官方 OpenAPI。发现差异时返回非零。CI 的 `.github/workflows/verify.yaml` 自动执行常规及原生检查、托管及原生真实测试；远端状态以 CI 运行结果为准。

本地证据为 `artifacts/test-results/latest.txt` 指向目录中的 TRX/Cobertura、`artifacts/test-matrix-summary.json`、`artifacts/alignment/summary.json`、`artifacts/six-contracts-live-managed.txt`、`artifacts/six-contracts-live-native-aot.txt`；可提交的逐项记录见 [审计报告](keycloak-26.8.1-alignment-audit.md)、[520 项对照](keycloak-26.8.1-alignment.tsv) 与 [真实状态记录](live-endpoints.tsv)。本次已通过的原生目标是 Linux，Windows 本机尚缺 C++ 链接器和 Windows SDK；其余发布边界见 [验证状态](verification.md)。
