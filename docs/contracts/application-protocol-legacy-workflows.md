# 应用协议选定工作流验收

固定 Keycloak 26.8.1；验证输入指纹 `e5cd9aa0cf71e5a856b2e50c414c580610675856fb77bc9594705a3cb32de076`。

| 运行模式 | 业务断言 | 不可变证据 |
| --- | --- | --- |
| managed | 20/20 | [165e7af333c5](application-protocol-evidence/165e7af333c56f5c7ef9c4256b3717f9aa1404c65fb6d71d133f1b521a151eaf.json) |
| native-aot | 20/20 | [26eb8643928d](application-protocol-evidence/26eb8643928d768eb12f2d62c3b033a1d60cb25993715914d3a0ac933ecec946.json) |

覆盖安全登录、PAR、客户端委托、AuthZen、SCIM、账户、注册、UMA 共享与授权、Client Admin v2、管理端 OpenAPI、Docker 令牌、DPoP、身份代理和 SSF 的选定流程。两个运行模式均在隔离容器网络实际调用固定服务端；未验证能力不会继承这些结果。

报告不自行晋升（`promoted=false`）。独立工具依据审阅计划、全部验收标准和当前输入，为明确运行模式/RID 生成支持配置。稳定与非稳定能力分别晋升。当前应用覆盖与责任边界由 [全能力矩阵](platform-capability-matrix.md) 和完整发布门禁共同确定。
