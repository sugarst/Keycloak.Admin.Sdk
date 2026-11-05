# .NET 10 Keycloak Admin SDK 实施方案

> 状态：实施中；制定日期：2026-11-04。本文保留实施目标和发布门禁；当前行为以代码及 [验证记录](contracts/verification.md) 为准。尚未完成的目标不代表现有功能。

## 1. 目标与边界

在本仓库独立重实现 `Keycloak.Admin.Sdk`，以 Keycloak **26.8.1 现有 Admin REST API** 为契约基线，提供强类型、异步、可取消的 .NET 10 管理客户端。按固定版本的端点清单衡量覆盖率，不能仅凭资源模块数量宣称完整。

| 项目 | 决策 |
| --- | --- |
| 目标框架 | `net10.0`；开启 nullable 和编译器警告 |
| Native AOT | 必须支持；固定 .NET SDK `10.0.403`；JSON 禁用反射回退，公开泛型 JSON 方法接受源生成 `JsonTypeInfo<T>`；必须实际发布并运行原生测试程序 |
| 辅助工具 | 统一 .NET 10 文件式 C#，通过 `dotnet run --file tools/名称.cs` 执行；YAML 文件统一使用 `.yaml` |
| 核心依赖 | 仅 `Microsoft.NETCore.App`；无任何 `PackageReference`，不引用 ASP.NET Core 共享框架 |
| 测试和开发工具 | 常规测试使用 MSTest，允许按固定版本引入用户指定的测试包，全部设为 `PrivateAssets="all"`；包清单见 [测试说明](testing.md)。Native AOT 验证程序保持无测试框架包，Docker、Keycloak 镜像属于外部测试环境 |
| 认证 | 外部 token provider；内置 client credentials，认证 realm 与目标 realm 分开 |
| 兼容性 | 首先仅声明经过验证的 26.8.1；不承诺兼容旧 SDK 的公开 API |
| 完整性 | 仅当约定范围内的端点全部完成实现和验收，才宣称完整支持 |
| FGAP 路线 | 默认 `fgap-v2-stable`，只支持 26.8.1 正式功能；`fgap-v1-compat` 仅作兼容支持。通过 JSON 或 `KEYCLOAK_ADMIN_API_ROUTE` 环境变量声明，部署和验收必须核对服务器实际启用版本 |

路线规范位于 [admin-api-routes.json](../contracts/admin-api-routes.json)。完整 wire 契约仍保留 520 项并全部单测；v2 正式支持范围 478 项，v1 兼容范围 492 项。两条路线排除 28 项预览/实验 API，v2 另排除 14 项 v1 专用管理权限 API；Workflows 在 26.8.1 是 DEFAULT，纳入正式验收。逐项分类及真实托管/AOT 结果见 [路线说明](contracts/admin-api-routing.md) 和 [全功能验收](contracts/full-live-acceptance.md)。

本项目不实现通用 OAuth/OIDC 或 UMA 客户端、JWT 验签、ASP.NET Core 中间件、SCIM、数字凭证协议或实验性 Admin API v2。独立的 `Keycloak.Admin.Sdk.DependencyInjection` 已提供 Microsoft DI 集成，详见 [认证与错误处理](authentication-and-errors.md)。管理 API 所需 token 获取属于基础设施。FGAP 等配置的底层管理端点按清单实现；跨请求业务编排单独设计，不假设原子性。

本仓库是独立新项目，采用根目录 `LICENSE`（Apache License 2.0）。旧项目仅作为行为与迁移需求参考；不要直接复制代码。契约来源及改编声明见 [第三方说明](../THIRD_PARTY_NOTICES.md)。

## 2. 基线与证据

1. [Keycloak 26.8.1 发布及 tag](https://github.com/keycloak/keycloak/releases/tag/26.8.1)：实施阶段解析并记录 **完整 commit SHA**。
2. [26.8.1 Admin REST API](https://www.keycloak.org/docs-api/26.8.1/rest-api/index.html)：端点、模型和媒体类型盘点入口。
3. 同一 tag 的服务端资源、representation、权限逻辑和测试，如 [UsersResource](https://github.com/keycloak/keycloak/blob/26.8.1/services/src/main/java/org/keycloak/services/resources/admin/UsersResource.java)、[ClientsResource](https://github.com/keycloak/keycloak/blob/26.8.1/services/src/main/java/org/keycloak/services/resources/admin/ClientsResource.java)。
4. [26.8.0 迁移说明](https://github.com/keycloak/keycloak/blob/26.8.1/docs/documentation/upgrading/topics/changes/changes-26_8_0.adoc)和 [26.8.1 迁移说明](https://github.com/keycloak/keycloak/blob/26.8.1/docs/documentation/upgrading/topics/changes/changes-26_8_1.adoc)。
5. 固定镜像 digest 的真实服务端测试。digest 和平台由阶段 0 实际获取、记录，不能用 tag 冒充不可变 digest。

原讨论中的 [Skycloak 文章](https://skycloak.io/blog/keycloak-25-released-new-features-and-enhancements/)仅用于版本背景，不作为接口契约。文档、源码和真实响应有差异时记录证据与配置，以固定版本源码和可复现测试共同确定行为；不自动把源码中未列入文档的端点视为稳定公共 API。

## 3. 目标目录结构

以下为当前主要工程结构及尚待完成的迁移文档；契约生成器、原生验证程序和 CI 随实施一并维护。

```text
src/Keycloak.Admin.Sdk/        核心库：认证、HTTP、模型和资源客户端
src/Keycloak.Admin.Sdk.DependencyInjection/ Microsoft DI 集成
src/Keycloak.Admin.Sdk.Capabilities/ 版本与服务端能力策略
src/Keycloak.Admin.Sdk.FeatureManagement*/ 托管宿主开关及可选遥测扩展
tests/Keycloak.Admin.Sdk.Tests/ MSTest 常规测试、HTTP 契约检查与覆盖率收集
tests/Keycloak.Admin.Sdk.IntegrationTests/ 固定版本容器集成测试
tests/Keycloak.Admin.Sdk.AotSmoke/ 关闭反射后实际发布和运行的原生测试程序
tools/Keycloak.Admin.Sdk.Generator/ 从固定源码与 OpenAPI 生成路由、DTO 和 JSON 元数据
tools/*.cs                    .NET 10 文件式构建、容器测试、契约更新及证据汇总工具
.github/workflows/verify.yaml  调用同一组 .NET 工具的 CI 验证入口
docs/contracts/                端点清单、模型差异、基线和验证证据
docs/migration/                旧 SDK 能力映射（尚未建立）
```

公开入口为 `KeycloakAdminClient`，资源入口包括 `RealmsAdmin`、`RealmAdmin`、`Users`、`Groups`、`Clients`、`RoleContainer`、`ClientScopes`、`IdentityProviders` 和 `Organizations`；具体方法见 [端点清单](contracts/endpoint-inventory.md)。预览期间公开命名仍可能调整。所有网络操作接受 `CancellationToken`。内部划分请求构造、认证、响应处理、JSON 和资源模块，不暴露底层实现细节。

## 4. 契约盘点与范围冻结

阶段 0 创建 `docs/contracts/endpoint-inventory.md`（或可审计的 CSV），以 **HTTP 方法 + 原始路径模板** 为唯一键，至少包含：

| 字段 | 内容 |
| --- | --- |
| 标识 | 方法、路径、所属资源、对应 SDK 方法 |
| 请求 | 路径/查询/header 参数、必填性、默认值、媒体类型和请求模型 |
| 响应 | 成功状态、媒体类型、模型、空响应、`Location`、流或文本 |
| 约束 | 权限、feature flag、废弃状态、敏感字段 |
| 证据 | 版本化文档、源码位置、实测结果及差异 |
| 状态 | 范围内/排除/待评估，未开始/实现中/已实现/已验证，测试标识 |

从官方资源列表及模型定义提取候选项，对照固定 tag 资源类确认；拆分相同路径不同方法，记录参数和特殊响应。记录无文档但源码存在的候选项及排除理由，单独维护模型字段、可空性和差异。覆盖率计算为「范围内且已验证端点数 / 范围内端点数」，同时公开排除及待评估数；分母不得悄然改变。

阶段 0 产物还包括基线记录（完整 SHA、镜像引用与 digest、平台、feature flag、运行参数）、范围冻结和差异清单。清单未完成前不估算全量交付日期。

## 5. 核心设计

### 5.1 HTTP 与 URI

- 接收调用方提供的 `HttpClient`，由调用方释放；若未来提供内部创建方式，明确所有权和释放规则。每次请求创建独立 `HttpRequestMessage`，在请求上设置 Bearer token，不修改共享默认 Authorization header。
- 保留服务端基地址的上下文路径，如 `/auth/`；逐路径段编码路径参数，逐项编码查询参数。区分缺省、空字符串、`false` 和 `0`。验证 Unicode、斜杠、百分号和反向代理前缀。
- 按端点处理 JSON、文本、二进制和空响应；及时释放响应。大文件提供流式访问，并明确响应与流的所有权。
- 默认不自动重试或因 401 重放请求，尤其是创建、发邮件和密码重置。超时或连接中断后的写入结果可能未知，由调用方核对。当前可显式启用 401 恢复：符合条件的生成无请求体 GET/HEAD 至多重放一次，写请求符合条件时只失效 token 而不重放；原始读取需单独声明允许重放，详见 [认证与错误处理](authentication-and-errors.md)。
- realm 参数为 realm **名称**；涉及 `/clients/{client-uuid}` 的操作使用内部 ID 而非 `clientId`。便利查找方法应显式命名，不隐藏两者差异。

### 5.2 token 与并发

- 定义只提供 token 的轻量接口，允许接入宿主现有凭据管理；内置 client credentials，通过单独配置的认证 realm 获取 token。服务账号与最小权限由部署方配置。
- 按认证配置隔离缓存；依据 `expires_in` 和安全余量刷新，以单飞机制防止并发刷新风暴。失败不得缓存为成功；调用者取消不应意外取消其他调用者正在共享的刷新。
- 注入时钟以测试过期与并发；不从未经验证的 JWT 推断权限。secret、token、密码和完整认证响应不得写入日志、测试快照或仓库。

### 5.3 JSON 与模型

- 使用 `System.Text.Json`，按 wire 名称明确映射。可能省略的值类型使用可空类型；动态或扩展字段使用字典、`JsonElement` 和必要的 `JsonExtensionData`，往返时避免已知字段冲突。可扩展字符串保留未知值。
- 为需要区别「未提供 / 显式 null / 空集合」的操作设计可表达三态的请求模型或序列化机制；逐端点测试，不能统一假设 PUT 是 PATCH 或完整替换。
- 不把读取 DTO 盲目用于更新：brief representation、只读字段、掩码密钥可能造成数据损失。高风险端点使用独立创建/更新模型，依据固定版本验证密钥掩码和身份提供方更新行为。
- 每个字段依协议处理时间戳，不统一假设时间格式。未知字段是否允许回写由具体请求模型决定，避免泄露或覆盖只读数据。
- 创建结果按端点实际返回建模：对于 `201 + Location` 保留原始 Location，可提供安全解析的可选 ID；不假设所有创建请求返回实体或 ID。
- 原始单页接口暴露实际 `first`、`max` 等参数；异步分页遍历仅为便利层，不承诺总数或快照一致性，并提示并发变更可能导致重复或遗漏。

### 5.4 错误和诊断

当前 HTTP 错误保留状态码、方法、阶段、错误类别及生成接口的操作标识；异常不包含 URI、响应头或响应体，错误体也不会被读取。非 JSON 错误同样保留原始 HTTP 状态。区分 HTTP 错误、传输错误、调用方取消、超时和响应格式错误；不将 403、404 或 409 折叠成空结果。

核心客户端当前不提供内置请求日志或追踪；如后续增加诊断，可使用运行时内置 `ActivitySource`、`Meter` 或回调，并限制记录的信息。禁止记录凭据、请求体、用户属性及带敏感查询参数的完整 URI。FGAP 下的可见性与权限以服务端结果为准。

## 6. 实施任务与退出条件

| 阶段 | 主要任务与产物 | 退出条件 |
| --- | --- | --- |
| 0 契约 | 固定 SHA/digest；盘点端点、模型、特性和差异，冻结范围 | 清单完成评审，每项均有归属、范围、证据与验证计划 |
| 1 基础设施 | 初始化解决方案与零包项目；实现 URI、HTTP、token、JSON、错误、生命周期和诊断；确定公开 API | 无网络契约测试通过，打包无包依赖，API 和所有权文档完成 |
| 2 核心资源 | realm、用户、组、角色、客户端、scope、映射、凭据等，按清单逐项实现 | 纳入此阶段的每个端点有契约及真实服务端测试；允许发布标明覆盖范围的预览版 |
| 3 其他资源 | 身份提供方、认证流、组件、事件、组织、权限及清单其余项 | 所有范围内端点验证完成；feature flag、权限和差异均有证据 |
| 4 迁移与发布 | 旧能力映射、示例、兼容矩阵、包元数据、开源检查 | 迁移文档列出新方法/范围外/待支持；发布门禁全部通过 |

每个资源的工作顺序：核对清单 → 设计请求与响应模型 → 实现逐端点方法 → 添加 HTTP 契约测试 → 运行隔离集成测试 → 更新清单证据和文档。便利方法或多请求编排另列任务并描述部分成功、补偿及结果未知的语义。

## 7. 测试与发布门禁

**无网络测试：** 用自定义 `HttpMessageHandler` 捕获请求，验证方法、路径、编码、查询值、header、JSON、状态码、Location、空/文本/二进制响应、非 JSON 错误、取消及释放；覆盖 token 缓存、并发刷新、失败及认证 realm 隔离。常规检查通过 MSTest 执行并输出 TRX、覆盖率及可定位的失败信息；同一套无包检查代码由独立 Native AOT 程序复用。

**集成测试：** 使用记录 digest 的 26.8.1 镜像和隔离 realm，逐项验证清单端点的实际状态、请求响应、CRUD、分页、特殊响应和清理。以独立资源前缀隔离并清理测试数据；记录 feature flag 和账号权限。对于依赖外部邮件或身份提供方的端点，建立可复现的测试依赖或明确标记未验证，不以模拟结果代替集成证据。

**权限与安全：** 覆盖有权限、无权限和 FGAP 限制账号，跨 realm、错误凭据、token 过期、掩码密钥、身份提供方更新、组织与 feature flag；检查默认诊断不泄露敏感数据。测试取消、大响应、并发和写入失败后的未知结果。

**发布检查：**

- [ ] 干净环境还原、构建、测试、打包成功；检查项目及生成的 NuGet 包元数据，核心包无直接或传递包依赖。
- [ ] AOT/裁剪分析零警告；关闭 JSON 反射后实际 Native AOT 发布并运行测试程序，逐平台记录结果，不能仅以 `IsAotCompatible=true` 声明通过。
- [ ] 清单中每个范围内端点具有实现、契约测试、真实服务端验证和证据；公开范围外、待评估、未验证项。
- [ ] 文档说明支持版本、权限、realm 名称与客户端内部 ID、token 和 HTTP/流所有权、分页及错误语义。
- [ ] 公布实际测试通过的版本矩阵，不将 26.8.1 结果扩展为全部 26.x。
- [ ] 检查许可证、贡献版权、第三方通知、仓库历史及打包产物中的密钥；NuGet 元数据与现有 Apache-2.0 许可证一致。
- [ ] 预览包明确列出未完成范围；稳定版只有在约定完整范围达到上述条件后发布。

## 8. 首批可执行事项

1. 记录 26.8.1 tag 的完整 SHA、镜像 digest、平台及测试配置，建立基线文件。
2. 创建端点清单，先按官方资源目录完成全量候选枚举，再核对源码与 feature flag；登记差异及待评估项。
3. 评审范围、预计端点数量及分阶段优先级，冻结完整性分母。
4. 创建无包核心项目、MSTest 测试项目与独立 Native AOT 验证程序；先实现并验证 URI、HTTP、token 和错误处理。
5. 选取用户与客户端的少量端点做纵向切片，验证整个设计与真实服务端行为，再按清单扩展。

主要风险是端点规模、文档与行为差异，以及原生模式与真实服务端测试矩阵的维护成本；这些风险在阶段 0 量化后再制定排期。后续 Keycloak 版本须重新比较契约、迁移说明并运行同一测试矩阵，验证通过后才加入支持声明。
