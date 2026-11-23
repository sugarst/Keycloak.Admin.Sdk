# 兼容应用协议工作流验收

固定 Keycloak 26.8.2，验证输入指纹 `9e8bc9f0d97051e44c0e2d286f6682875d93230c6bd6fca32a398b74b5ed82dc`。

| 运行模式 | 业务断言 | 不可变证据 |
| --- | --- | --- |
| managed | 20/20 | [fa22aa514303](application-protocol-evidence/fa22aa514303225a1d4955cdb872a544df72072e3ed20816bc4f17ef98d116cd.json) |
| native-aot | 20/20 | [901061884255](application-protocol-evidence/9010618842555bc69d868cf35a5588783e6d079adfa34e8750ae4510a5e556bc.json) |

覆盖 FGAP v1 下的旧版令牌交换、授权模拟身份和旧版身份代理令牌访问。两个运行模式均在隔离容器网络实际调用固定服务端。

报告不自行晋升（`promoted=false`）。独立工具依据审阅计划、全部验收标准和当前输入，为明确运行模式/RID 生成支持配置。稳定与非稳定能力分别晋升。当前应用覆盖与责任边界由 [全能力矩阵](platform-capability-matrix.md) 和完整发布门禁共同确定。
