# 应用协议选定工作流验收

固定 Keycloak 26.8.1；验证输入指纹 `a54351ad222e3149bc5728db6d506a3fb8dd87aeca8d006c9923ab18a3b4a65e`。

| 运行模式 | 业务断言 | 不可变证据 |
| --- | --- | --- |
| managed | 434/434 | [edddaf89fa2c](application-protocol-evidence/edddaf89fa2cb7e920e7e8484b564e03ea616d1eaa3adda8cc2b2159a03bf4d5.json) |
| native-aot | 391/391 | [aba287bc3783](application-protocol-evidence/aba287bc3783ba46aab4be7e7f867e322b5be5ec84bd7aefe06f72800a4c1650.json) |

覆盖安全登录、PAR、客户端委托、AuthZen、SCIM、账户、注册、UMA 共享与授权、Client Admin v2、管理端 OpenAPI、Docker 令牌、DPoP、身份代理和 SSF 的选定流程。两个运行模式均在隔离容器网络实际调用固定服务端；未验证能力不会继承这些结果。

报告不自行晋升（`promoted=false`）。独立工具依据审阅计划、全部验收标准和当前输入，为明确运行模式/RID 生成支持配置。稳定与非稳定能力分别晋升。当前应用覆盖与责任边界由 [全能力矩阵](platform-capability-matrix.md) 和完整发布门禁共同确定。
