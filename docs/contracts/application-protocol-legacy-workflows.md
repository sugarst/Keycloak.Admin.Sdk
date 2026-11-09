# 应用协议选定工作流验收

固定 Keycloak 26.8.1；验证输入指纹 `a54351ad222e3149bc5728db6d506a3fb8dd87aeca8d006c9923ab18a3b4a65e`。

| 运行模式 | 业务断言 | 不可变证据 |
| --- | --- | --- |
| managed | 20/20 | [9e788f6c3301](application-protocol-evidence/9e788f6c33011736702e2a09c1e6a200c0b86bcfa7b4b632d365587dd04a9acd.json) |
| native-aot | 20/20 | [bc369739fe89](application-protocol-evidence/bc369739fe890074cf53c6cb233470565e37000ebd53aba83367a2b7838a722f.json) |

覆盖安全登录、PAR、客户端委托、AuthZen、SCIM、账户、注册、UMA 共享与授权、Client Admin v2、管理端 OpenAPI、Docker 令牌、DPoP、身份代理和 SSF 的选定流程。两个运行模式均在隔离容器网络实际调用固定服务端；未验证能力不会继承这些结果。

报告不自行晋升（`promoted=false`）。独立工具依据审阅计划、全部验收标准和当前输入，为明确运行模式/RID 生成支持配置。稳定与非稳定能力分别晋升。当前应用覆盖与责任边界由 [全能力矩阵](platform-capability-matrix.md) 和完整发布门禁共同确定。
