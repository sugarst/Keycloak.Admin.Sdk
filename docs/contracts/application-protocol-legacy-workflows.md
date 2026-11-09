# 应用协议选定工作流验收

固定 Keycloak 26.8.1；验证输入指纹 `f9aed0cde002ff44747820141fd527290718c7151779875778c661124b4ce523`。

| 运行模式 | 业务断言 | 不可变证据 |
| --- | --- | --- |
| managed | 20/20 | [0f4a9d7e5130](application-protocol-evidence/0f4a9d7e5130482c86f0f91c282e6a497d29e57d6864c90107d3db133e70ceb0.json) |
| native-aot | 20/20 | [9ba696b0dc6b](application-protocol-evidence/9ba696b0dc6bb193f5c941f5518c629411b299d248a2b20bac0058cc53ceb761.json) |

覆盖安全登录、PAR、客户端委托、AuthZen、SCIM、账户、注册、UMA 共享与授权、Client Admin v2、管理端 OpenAPI、Docker 令牌、DPoP、身份代理和 SSF 的选定流程。两个运行模式均在隔离容器网络实际调用固定服务端；未验证能力不会继承这些结果。

报告不自行晋升（`promoted=false`）。独立工具依据审阅计划、全部验收标准和当前输入，为明确运行模式/RID 生成支持配置。稳定与非稳定能力分别晋升。当前应用覆盖与责任边界由 [全能力矩阵](platform-capability-matrix.md) 和完整发布门禁共同确定。
