# 六条特殊路径的契约与回归

同方法/路径可以有多个 Java 分派或媒体类型分支。生成器在去重前保存 [source-dispatches.json](../../contracts/source-dispatches.json)，合并查询并保留调用方的 `HttpContent`；响应修正在 [overrides.json](../../contracts/overrides.json) 维护。

以下路径均相对于 `/admin/realms/{realm}`：

| 路径 | 契约 | 独立验证 |
| --- | --- | --- |
| GET `/workflows/scheduled/{resource-id}` | `List<WorkflowRepresentation>`，允许空数组 | 空/非空数组；实际调度后读取 |
| GET `/clients/{client-uuid}/authz/resource-server/policy/{type}` | ID/provider-type 分支查询并集，响应可为对象或数组 | 全参数、false/0、编码、筛选及分页 |
| GET `/clients/{client-uuid}/authz/resource-server/permission/{type}` | 同上，独立 permission 路径 | 同上，使用真实 scope permission |
| POST `/identity-provider/import-config` | JSON 或 multipart `providerId` + `file` | 元数据文件解析与 JSON URL 实际拉取 |
| POST `/localization/{locale}` | JSON 或 multipart `file` | UTF-8 写入后读取 |
| POST `/testSMTPConnection` | JSON 或兼容 form `config` | 两种方式分别实际投递邮件 |

授权查询包括 `fields`、`policyId`、`name`、`type`、`resourceType`、`resource`、`scope`、`permission`、`owner`、`first`、`max`。与路径参数重名的查询参数在 C# 中为 `typeQuery`，wire key 仍为 `type`；筛选效果由服务器选中的分支决定。

## 调用示例

```csharp
using System.Text;

await sdk.RealmLocalization.CreateOrUpdateRealmLocalizationTextsFromFileAsync(
    "demo", "zh-CN",
    new StringContent("{\"greeting\":\"你好\"}", Encoding.UTF8, "application/json"));

var upload = new MultipartFormDataContent();
upload.Add(new StringContent("saml"), "providerId");
upload.Add(new ByteArrayContent(await File.ReadAllBytesAsync("metadata.xml")),
    "file", "metadata.xml");
var imported = await sdk.IdentityProviders.ImportFromAsync("demo", upload);

var scheduled = await sdk.Workflows.GetScheduledWorkflowsAsync("demo", "user-id");
foreach (var workflow in scheduled.Body ?? []) Console.WriteLine(workflow.Name);
```

SMTP JSON 使用 `StringContent(json, Encoding.UTF8, "application/json")`；兼容表单使用 `new FormUrlEncodedContent(new Dictionary<string, string> { ["config"] = json })`。请求消费并释放内容，每次新建。

## 验证入口

手写 [AlignmentContracts.cs](../../tests/Keycloak.Admin.Sdk.Tests/AlignmentContracts.cs) 独立于生成样本，MSTest 与原生程序共用；另保留 SAML `@JsonValue` 字符串及隐式 multipart 证书上传断言。[AlignmentLive.cs](../../tests/Keycloak.Admin.Sdk.IntegrationTests/AlignmentLive.cs) 通过真实服务器验证，HTTP/SMTP 由 [CallbackFixture.cs](../../tests/Keycloak.Admin.Sdk.IntegrationTests/CallbackFixture.cs) 提供。工作流使用源码定义的 `USERS` 类型及未来调度时间。

运行 `tools/Test-Integration.cs`，原生加 `-- --native-aot`；六路径结果写入 `artifacts/six-contracts-live-{managed|native-aot}.txt`。该隔离测试的早期观测在 [live-endpoints.tsv](live-endpoints.tsv) 保留，当前全量支持范围和业务证明见 [真实验收](full-live-acceptance.md)。完整验证命令见 [测试说明](../testing.md)。
