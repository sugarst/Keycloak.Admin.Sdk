# 应用协议选定工作流验收

固定 Keycloak 26.8.2；验证输入指纹 `7aa98cff3d7f0dc9832d4a90ee01640715134710619091e22fcb0e7a02a0cd4d`。

| 运行模式 | 业务断言 | 不可变证据 |
| --- | --- | --- |
| managed | 20/20 | [96b19d09a319](application-protocol-evidence/96b19d09a319bc58031a873195f950e5d4ec32260f5c9681c8dd1cee1c5e8cec.json) |
| native-aot | 20/20 | [a85e0a5d29fd](application-protocol-evidence/a85e0a5d29fdf939e39611da86d93405dc7537077783c32d58ad668010e855af.json) |

覆盖安全登录、PAR、客户端委托、AuthZen、SCIM、账户、注册、UMA 共享与授权、Client Admin v2、管理端 OpenAPI、Docker 令牌、DPoP、身份代理和 SSF 的选定流程。两个运行模式均在隔离容器网络实际调用固定服务端；未验证能力不会继承这些结果。

报告不自行晋升（`promoted=false`）。独立工具依据审阅计划、全部验收标准和当前输入，为明确运行模式/RID 生成支持配置。稳定与非稳定能力分别晋升。当前应用覆盖与责任边界由 [全能力矩阵](platform-capability-matrix.md) 和完整发布门禁共同确定。
