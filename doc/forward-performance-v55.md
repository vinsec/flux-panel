# v5.5 统计、账本编码与冷连接优化

本批在 v5.4（`5d5211a`）基础上优化 Go Agent。保留 iptables-nft、iptables-legacy、原生 nftables 和既有 GOST 路径；不修改线上服务、配置或数据库，转发验证只使用本机 Fusion 私网 namespace/veth。

## 统计与 checkpoint

原生 counter 身份只在首次出现或元数据改变时完整验证。每轮仍通过只读 GETOBJ 获取所有最新 bytes/packets，重复名字、外来/变更的身份仍拒绝；移除或回退的计数仍送入原有连续性检查，不缓存采样数值。counter 集合稳定时复用已排序名字，避免逐秒重复解码和排序。

规则 JSON 是 Manager 内部缓存。规则改变、运行时元数据改变、状态替换、恢复、续约和回滚均失效；只把 `json.Marshal` 产生的可信字节拼入新的动态 checkpoint。Rules/Page/Normalize 返回的协议策略采用独立副本，防止调用方经共享指针改变缓存对应的状态。

文件格式和 durability 顺序不变：完整 checkpoint → 临时文件 → fsync → rename → 目录 fsync → 上报。没有延迟落盘、减少落盘频率、提前 ACK 或更改 journal 校验算法，仍使用既有 state format。事务日志不走此编码缓存。

第一版 RawMessage 嵌入会重复验证/压缩整段规则，微基准反而更慢，因此已舍弃；最终只拼接失效时由 JSON 编码器产生的可信片段，字符串转义和完整状态解码一致性均有测试。

## 冷连接

保留 SYN 入队与初始序号记录，包括携带应用数据的 SYN/TFO。只对**能证明 TCP 载荷为空**的非 SYN 包留在内核：

- IPv4 使用 IHL、TCP doff、实际 skb length 三元组精确匹配 121 种合法首部长度；不使用“短包就是 ACK”的近似。
- 无扩展首部的 IPv6 使用 TCP doff/length 精确匹配；IPv6 扩展首部继续走保守识别路径。
- 携带数据的 ACK、两字节 HTTP 前缀、SYN-data 均继续入队。保持 500ms 有界重组、UNKNOWN 放行并标记、暂停/配额和原始网络层计费。

常规串行新 TCP 的入队从 SYN、空 ACK、首数据三次降至两次；已分类数据仍走 conntrack 快路径。NFQUEUE verdict 改为固定长度 scratch 编码，复用接收消息头缓冲；保留已验证的低五位 masked-XOR，不能把高位 token 放入 CTA_MARK value。

接管 v5.4 协议表时重建少量自有静态 chain，并补齐空包集合；不替换业务 counter，也不改变现有 checkpoint ABI。兼容测试覆盖旧版→新版→旧版读取→新版再次接管及累计账本。

## 验证

新增测试覆盖 counter 缓存身份变更/重复/移除、checkpoint 与完整当前 State 的语义等价、公共快照指针隔离、转义文本、SYN-data、乱序前缀及实际入队次数。既有协议识别、UNKNOWN、TCP/UDP 配额、暂停、重启、万规则增删/GC、故障恢复和最小权限 helper 一并回归。

微基准只评价编码器/处理函数，不代表端到端提升。端到端比较冻结 v5.4 **开启识别**与 v5.5 开/关识别，使用相同私网拓扑、统计间隔、CPU 绑定和收包校验。具体构建、轮数、结果、CPU 采样及边界见 [验证报告](forward-performance-v55-validation.md)。
