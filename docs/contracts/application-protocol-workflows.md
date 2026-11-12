# 应用协议选定工作流验收

固定 Keycloak 26.8.1；验证输入指纹 `71542db6700309b9789afb388bd03b7999d247bbcb7464ef9abc19bbb2e3e216`。

| 运行模式 | 业务断言 | 不可变证据 |
| --- | --- | --- |
| managed | 434/434 | [22369b5f1cc8](application-protocol-evidence/22369b5f1cc8a1eeea0665fde11b8ef4a2ad5fa44590f1fbdc77e19c398e8481.json) |
| native-aot | 391/391 | [869af2f2fe33](application-protocol-evidence/869af2f2fe3307949c9c16b4b4f85ad7702b54786656a0f051e57300f807b0a1.json) |

覆盖安全登录、PAR、客户端委托、AuthZen、SCIM、账户、注册、UMA 共享与授权、Client Admin v2、管理端 OpenAPI、Docker 令牌、DPoP、身份代理和 SSF 的选定流程。两个运行模式均在隔离容器网络实际调用固定服务端；未验证能力不会继承这些结果。

报告不自行晋升（`promoted=false`）。独立工具依据审阅计划、全部验收标准和当前输入，为明确运行模式/RID 生成支持配置。稳定与非稳定能力分别晋升。当前应用覆盖与责任边界由 [全能力矩阵](platform-capability-matrix.md) 和完整发布门禁共同确定。
