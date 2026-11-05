# 架构与契约来源

每个构建只面向一个精确的 Keycloak 版本；源码 commit、输入哈希、镜像和 SDK 版本统一记录在 [baseline.json](../contracts/baseline.json)。升级与发布见 [单基线流程](single-target-workflow.md)。

## 项目结构

| 目录 | 职责 |
| --- | --- |
| `src/Keycloak.Admin.Sdk` | HTTP 传输、认证、响应、生成资源方法及 DTO |
| `src/Keycloak.Admin.Sdk/Authentication` | Token 获取、缓存及条件失效 |
| `src/Keycloak.Admin.Sdk/Transport` | URI、JSON 元数据入口、响应及错误类型 |
| `src/Keycloak.Admin.Sdk/Generated` | 生成的 API、DTO、端点目录及 JSON 上下文 |
| `src/Keycloak.Admin.Sdk/DependencyInjection` | Microsoft DI、Options、HttpClientFactory、显式开启的读取弹性管道 |
| `src/Keycloak.Admin.Sdk/Capabilities` | 不可变版本目录与请求支持策略 |
| `src/Keycloak.Admin.Sdk.FeatureManagement` | 托管功能开关与可选评估遥测 |
| `src/Keycloak.Admin.Sdk.FeatureManagement/ApplicationInsights` | 默认关闭的遥测注册适配器 |
| `tests/Keycloak.Admin.Sdk.Tests` | MSTest 契约矩阵及运行时行为检查 |
| `tests/Keycloak.Admin.Sdk.AotSmoke` | 源码链接共用断言的独立 Native AOT 程序 |
| `tests/Keycloak.Admin.Sdk.IntegrationTests` | 真实服务端业务及协议断言 |
| `tools/Keycloak.Admin.Sdk.Generator` | 从固定源码和 OpenAPI 生成 API、DTO、JSON 元数据 |
| `tools/*.cs`、`local/keycloak` | .NET 10 文件式工具及本地测试环境 |

## 生成与审计

生成器从 AdminRoot 的 realms/serverinfo 出发，追踪资源定位器、继承、授权动态分派、内置 realm providers 和 ui-ext。相同 HTTP 方法与路径的分支合并查询参数，并保留媒体类型选择。公开资源名沿用 Java 资源类；同名方法挂载不同路径时添加路径后缀。

输入为 [OpenAPI 快照](../contracts/openapi.json)、固定源码及 [已审定修正](../contracts/overrides.json)。源码受 [SHA256 清单](../contracts/source-files.sha256) 约束；动态或源码独有契约使用 `HttpContent` / `JsonElement`，`RawJsonValue` 映射为 `JsonElement`。生成文件标记为 `.g.cs`，应修改生成器或输入后重建。

独立的 `JavaAuditIndex` 按 Java token 扫描路由，不复用生成器的 `JavaRoutes`。冻结的 [测试矩阵](../contracts/admin-api-test-matrix.json) 使用这一独立来源和发布定义建立期望值；真实场景的前置条件、资源 ID 和业务断言由手写代码提供。静态审计、契约单测、真实验收分别记录，入口见 [测试说明](testing.md)。

## 运行时设计

- `KeycloakAdminClient` 保留服务器上下文路径，逐段编码路径及查询参数，每次请求独立设置 Bearer header。调用方管理 HTTP 客户端和 token provider。
- JSON 使用 `System.Text.Json` 源生成元数据；自定义泛型入口接受显式 `JsonTypeInfo<T>`。null 属性省略，需要显式 null 时提交原始 JSON。
- 常规响应缓冲内容；流入口转移响应所有权给调用方。HTTP 错误不读取错误体，网络、取消与 JSON 格式错误分别保留。
- client credentials 使用实例内缓存及共享获取；401 恢复可选，写入不自动重放。并发、超时和生命周期见 [认证说明](authentication-and-errors.md)。
- 请求策略在最终 URI 构造后、token 获取和 HTTP 发送前执行。支持策略、宿主功能开关依次收紧开放结果，详见 [能力策略](capability-policy.md)。

主包直接引用 Microsoft.Extensions.Http 10.0.14 和 Microsoft.Extensions.Http.Resilience 10.11.0。DI 的 `options.Resilience` 将读取弹性策略封装为一个 ResilienceHandler，按命名客户端隔离状态，默认关闭。写入、带内容请求和 Token POST 选择空管道，读熔断不会阻断这些请求；具体规则见 [认证与弹性配置](authentication-and-errors.md#http-弹性策略)。Diagnostics 与 Polly 作为 Resilience 的传递依赖还原，不重复添加旧的 Http.Polly 适配器。托管扩展依赖主包、Microsoft.FeatureManagement 及微软的 Application Insights 遥测适配器。

仅这两个库项目可生成本地 NuGet 包，测试与生成器项目不打包。项目尚未发布 NuGet 包；客户端与功能开关介绍见 [README](../README.md#客户端与功能开关)。

## 范围边界

端点以 HTTP 方法 + 路径模板计数，见 [端点清单](contracts/endpoint-inventory.md)。控制台静态资源、CORS preflight、独立 OAuth/OIDC、Account、SCIM、实验性 Admin API v2 和未知第三方 SPI 不纳入清单。管理 API 所需 token 获取属于客户端基础设施。

三处动态 SPI 定位器保留在 [unresolved-locators.txt](contracts/unresolved-locators.txt) 供审计。生成器和独立扫描器均不是通用 Java/JAX-RS 编译器，升级时需要复核定位器、注解、模型和功能阶段。当前实现及发布限制见 [验证状态](contracts/verification.md)。
