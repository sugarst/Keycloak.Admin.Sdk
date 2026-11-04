# Admin API 单元测试覆盖率门禁

所有 Admin API SDK 操作已有独立发现且通过的功能契约单元测试。此结论指 SDK 请求/响应契约及客户端行为，真实 Keycloak 的业务/权限场景覆盖另见 [验证记录](verification.md)。

| 指标 | 实测 | 门槛 |
| --- | --- | --- |
| `matrixOperationPercent` | 100.0000% | 100% |
| `sdkSourceMethodPercent` | 100.0000% | 100% |
| `sdkSourceLinePercent` | 99.9583% | 99.9% |
| `sdkSourceBranchPercent` | 100.0000% | 100% |
| `apiWrapperLinePercent` | 100.0000% | 100% |
| `apiWrapperBranchPercent` | 100.0000% | 100% |
| `modelLinePercent` | 100.0000% | 100% |
| `rawLinePercent` | 94.3657% | 94% |
| `rawBranchPercent` | 59.9232% | 59% |

MSTest 538/538 通过；矩阵 520/520，无缺失、重复、跳过或失败。SDK 自有源码覆盖 1786/1786 个可执行方法、2398/2399 行、314/314 个分支。

`sdkSource*` 保留仓库中的全部 SDK 生成 API、DTO 和手写代码，仅把 `obj/` 下 .NET SDK 生成的 JSON/正则实现另列为 raw 指标；原始 Cobertura 不删减。当前剩余一行是 token 方法 try 块的结束括号（所有路径 return/throw），PDB 将其计为零命中序列点，因此源码行门槛为 99.9%，分支及可执行方法门槛为 100%。框架生成实现的未执行分支不代表某个 Admin API 没有测试。

门禁读取本次 TRX 指向的 Cobertura，核验编译后 SDK、冻结契约矩阵和已执行测试的一一对应。任何操作缺少测试、跳过、失败或指标低于 [coverage-policy.json](../../tests/coverage-policy.json) 都返回非零。矩阵断言见 [操作清单](admin-api-test-matrix.md)；输入来自独立 Java token 索引和固定发布定义，不从 SDK 请求实现推导期望值。
