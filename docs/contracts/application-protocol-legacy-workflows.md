# 应用协议选定工作流验收

固定 Keycloak 26.8.1；验证输入指纹 `71542db6700309b9789afb388bd03b7999d247bbcb7464ef9abc19bbb2e3e216`。

| 运行模式 | 业务断言 | 不可变证据 |
| --- | --- | --- |
| managed | 20/20 | [de9dfa289c27](application-protocol-evidence/de9dfa289c274199f56018bbbed6a1e7928dcbe929742b4399b81180a763b16e.json) |
| native-aot | 20/20 | [246951c98132](application-protocol-evidence/246951c98132956cdf5d051d0e5603803927285d2426eaac7640201923f151a2.json) |

覆盖安全登录、PAR、客户端委托、AuthZen、SCIM、账户、注册、UMA 共享与授权、Client Admin v2、管理端 OpenAPI、Docker 令牌、DPoP、身份代理和 SSF 的选定流程。两个运行模式均在隔离容器网络实际调用固定服务端；未验证能力不会继承这些结果。

报告不自行晋升（`promoted=false`）。独立工具依据审阅计划、全部验收标准和当前输入，为明确运行模式/RID 生成支持配置。稳定与非稳定能力分别晋升。当前应用覆盖与责任边界由 [全能力矩阵](platform-capability-matrix.md) 和完整发布门禁共同确定。
