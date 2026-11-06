# 应用协议选定工作流验收

固定 Keycloak 26.8.1；验证输入指纹 `91845857488c428a404ed28e988cc320871f4aad49b0a512414827b30882ea87`。

| 运行模式 | 业务断言 | 不可变证据 |
| --- | --- | --- |
| managed | 434/434 | [c40e3da85b2f](application-protocol-evidence/c40e3da85b2fc19242754abc9ff5d6792474af0b2e1bdf7aabc376a7285b9592.json) |
| native-aot | 391/391 | [0fbaddfdd3cf](application-protocol-evidence/0fbaddfdd3cf840c275a5d04ff14477557fbb0fa8c5e4b22d9a193df6acb108a.json) |

覆盖安全登录、PAR、客户端委托、AuthZen、SCIM、账户、注册、UMA 共享与授权、Client Admin v2、管理端 OpenAPI、Docker 令牌、DPoP、身份代理和 SSF 的选定流程。两个运行模式均在隔离容器网络实际调用固定服务端；未验证能力不会继承这些结果。

报告不自行晋升（`promoted=false`）。独立工具依据审阅计划、全部验收标准和当前输入，为明确运行模式/RID 生成支持配置。稳定与非稳定能力分别晋升。当前应用覆盖与责任边界由 [全能力矩阵](platform-capability-matrix.md) 和完整发布门禁共同确定。
