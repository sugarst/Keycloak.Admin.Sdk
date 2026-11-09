# 应用协议选定工作流验收

固定 Keycloak 26.8.1；验证输入指纹 `f9aed0cde002ff44747820141fd527290718c7151779875778c661124b4ce523`。

| 运行模式 | 业务断言 | 不可变证据 |
| --- | --- | --- |
| managed | 434/434 | [1605d6a36caa](application-protocol-evidence/1605d6a36caae2267cc1048d79a468d188898a184a79ddec12a5beb75560b1f7.json) |
| native-aot | 391/391 | [b45e8627da25](application-protocol-evidence/b45e8627da25266a0b1552b9c091422c085f6eb17c3aa02b810a0e932263bf48.json) |

覆盖安全登录、PAR、客户端委托、AuthZen、SCIM、账户、注册、UMA 共享与授权、Client Admin v2、管理端 OpenAPI、Docker 令牌、DPoP、身份代理和 SSF 的选定流程。两个运行模式均在隔离容器网络实际调用固定服务端；未验证能力不会继承这些结果。

报告不自行晋升（`promoted=false`）。独立工具依据审阅计划、全部验收标准和当前输入，为明确运行模式/RID 生成支持配置。稳定与非稳定能力分别晋升。当前应用覆盖与责任边界由 [全能力矩阵](platform-capability-matrix.md) 和完整发布门禁共同确定。
