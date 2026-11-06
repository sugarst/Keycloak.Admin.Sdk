# 应用协议选定工作流验收

固定 Keycloak 26.8.1；验证输入指纹 `91845857488c428a404ed28e988cc320871f4aad49b0a512414827b30882ea87`。

| 运行模式 | 业务断言 | 不可变证据 |
| --- | --- | --- |
| managed | 20/20 | [ca49200b15d1](application-protocol-evidence/ca49200b15d116cef22f651e54d8866fcd206947105cff26f6f0d38175f417ad.json) |
| native-aot | 20/20 | [ff18454a7313](application-protocol-evidence/ff18454a7313836ed25f17d4f16d2935d5a6f0fc2fb1d6aaaf9f2061e1a30aac.json) |

本报告覆盖旧版 Token Exchange v1 和 Identity Brokering v1：权限拒绝与撤销、内部访问／刷新令牌、模拟用户、内外部双向交换、外部断言验签、代理令牌存储与同意，以及宿主关闭。两个运行模式均在隔离容器网络实际调用固定服务端。标准计划的独立报告见 [标准应用工作流](application-protocol-workflows.md)；其他能力不能继承本兼容报告。

报告不自行晋升（`promoted=false`）。独立工具依据审阅计划、全部验收标准和当前输入，为明确运行模式/RID 生成支持配置。稳定与非稳定能力分别晋升。当前应用覆盖与责任边界由 [全能力矩阵](platform-capability-matrix.md) 和完整发布门禁共同确定。
