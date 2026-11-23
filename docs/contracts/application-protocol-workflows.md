# 应用协议选定工作流验收

固定 Keycloak 26.8.2，验证输入指纹 `9e8bc9f0d97051e44c0e2d286f6682875d93230c6bd6fca32a398b74b5ed82dc`。

| 运行模式 | 业务断言 | 不可变证据 |
| --- | --- | --- |
| managed | 434/434 | [2e99d7632689](application-protocol-evidence/2e99d76326897273d6e5101d0cd946b341b44ec2c0dc275733ec07bfd99f2725.json) |
| native-aot | 391/391 | [74ca2ddb3550](application-protocol-evidence/74ca2ddb3550779a9e83ef899ac084fdfb144e9292339ef49878660a3e9063ed.json) |

覆盖安全登录、PAR、客户端委托、AuthZen、SCIM、账户、注册、UMA 共享与授权、Client Admin v2、管理端 OpenAPI、Docker 令牌、DPoP、身份代理和 SSF 的选定流程。两个运行模式均在隔离容器网络实际调用固定服务端。

报告不自行晋升（`promoted=false`）。独立工具依据审阅计划、全部验收标准和当前输入，为明确运行模式/RID 生成支持配置。稳定与非稳定能力分别晋升。当前应用覆盖与责任边界由 [全能力矩阵](platform-capability-matrix.md) 和完整发布门禁共同确定。
