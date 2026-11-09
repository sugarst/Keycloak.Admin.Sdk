# 应用协议选定工作流验收

固定 Keycloak 26.8.1；验证输入指纹 `3283ee6badd65da034cfe7606e26c531fdc243dada8608edc6c99175591e03f6`。

| 运行模式 | 业务断言 | 不可变证据 |
| --- | --- | --- |
| managed | 434/434 | [ca690ee6bd9f](application-protocol-evidence/ca690ee6bd9fbca903c3d4090284088721b70a6b9cf4c4fb10ec18ea5c0d6cf6.json) |
| native-aot | 391/391 | [45a96ba53c4c](application-protocol-evidence/45a96ba53c4cbfded5679720e4ca7561c427e816c76ca83b0a40973e7f57a095.json) |

覆盖安全登录、PAR、客户端委托、AuthZen、SCIM、账户、注册、UMA 共享与授权、Client Admin v2、管理端 OpenAPI、Docker 令牌、DPoP、身份代理和 SSF 的选定流程。两个运行模式均在隔离容器网络实际调用固定服务端；未验证能力不会继承这些结果。

报告不自行晋升（`promoted=false`）。独立工具依据审阅计划、全部验收标准和当前输入，为明确运行模式/RID 生成支持配置。稳定与非稳定能力分别晋升。当前应用覆盖与责任边界由 [全能力矩阵](platform-capability-matrix.md) 和完整发布门禁共同确定。
