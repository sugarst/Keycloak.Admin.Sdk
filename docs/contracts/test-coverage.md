# Admin API 单元测试覆盖率门禁

由 `tools/Check-Coverage.cs` 读取本次 TRX 及其 Cobertura 附件生成，门槛来自 [coverage-policy.json](../../tests/coverage-policy.json)。

| 指标 | 实测 | 门槛 |
| --- | --- | --- |
| `matrixOperationPercent` | 100.0000% | 100% |
| `sdkSourceMethodPercent` | 100.0000% | 100% |
| `sdkSourceLinePercent` | 100.0000% | 99.9% |
| `sdkSourceBranchPercent` | 100.0000% | 100% |
| `apiWrapperLinePercent` | 100.0000% | 100% |
| `apiWrapperBranchPercent` | 100.0000% | 100% |
| `modelLinePercent` | 100.0000% | 100% |
| `rawLinePercent` | 94.5018% | 94% |
| `rawBranchPercent` | 68.1702% | 59% |
| `capabilityMethodPercent` | 100.0000% | 100% |
| `capabilityLinePercent` | 100.0000% | 100% |
| `capabilityBranchPercent` | 100.0000% | 100% |
| `featureManagementMethodPercent` | 100.0000% | 100% |
| `featureManagementLinePercent` | 100.0000% | 100% |
| `featureManagementBranchPercent` | 100.0000% | 100% |
| `featureTelemetryMethodPercent` | 100.0000% | 100% |
| `featureTelemetryLinePercent` | 100.0000% | 100% |
| `featureTelemetryBranchPercent` | 100.0000% | 100% |

MSTest 586/586 通过；矩阵 520/520，无缺失、重复、跳过或失败。SDK 自有源码覆盖 1990/1990 个可执行方法、2953/2953 行、703/703 个分支。

`sdkSource*` 包含 SDK 手写代码及生成 API/DTO；`raw*` 还包含 `obj/` 中 .NET 生成的 JSON/正则实现。原始 Cobertura 不删减。能力、开关和遥测模块分别统计；DI 通过独立生命周期及原生断言验证。

门禁核对编译目录、冻结矩阵与本次测试一一对应，拒绝缺失、重复、跳过、失败及指标不足。测试方法与依赖边界见 [测试说明](../testing.md)，映射见 [操作矩阵](admin-api-test-matrix.md)。本报告不代表真实服务器或 Azure 验收，业务证据见 [真实验收](full-live-acceptance.md)。
