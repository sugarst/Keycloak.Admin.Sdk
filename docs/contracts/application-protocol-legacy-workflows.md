# 兼容应用协议工作流验收

固定 Keycloak 26.8.2，验证输入指纹 `35dfd183277fbc15688b86592597ac934979c037a1c30bfd993a3aa9162d2d70`。

| 运行模式 | 业务断言 | 不可变证据 |
| --- | --- | --- |
| managed | 20/20 | [9cdce6f346c5](application-protocol-evidence/9cdce6f346c536ad288648e2755bcc68dfa79bbdfacd5f7c1beee8fc04293387.json) |
| native-aot | 20/20 | [77b3d19870b5](application-protocol-evidence/77b3d19870b5e14d5600b08b03fb2163a38338bcaba74a39017b8579cb6d58e0.json) |

覆盖 FGAP v1 下的旧版令牌交换、授权模拟身份和旧版身份代理令牌访问。两个运行模式均在隔离容器网络实际调用固定服务端。

报告不自行晋升（`promoted=false`）。独立工具依据审阅计划、全部验收标准和当前输入，为明确运行模式/RID 生成支持配置。稳定与非稳定能力分别晋升。当前应用覆盖与责任边界由 [全能力矩阵](platform-capability-matrix.md) 和完整发布门禁共同确定。
