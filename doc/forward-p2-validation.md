# P2 第一批隔离验收

本批实现本机 OUTPUT、本机/回环目标、hairpin 基础路径及同族源地址模式；**不表示 P2 全部完成，也不进行生产部署**。剩余功能及逐项方案见 [完整清单](forward-p2-traffic.md)。

## 冻结输入与环境

最终 arm64 Agent：`b192b1bbf17990508c627ed5f015c3e6ee14bae12dab5b664ecddb75c467cd2b`；面板 JAR：`07bad10c7dcb4d2004a258052afcb314b0e9e3a9277d4bfbf9475f4c37c6830b`。

复用 VMware Fusion 25、Debian 13 arm64、4 vCPU/4 GiB 的专用测试 VM。业务测试位于独立 mount/net namespace 的私有 veth；外层没有公网默认路由。没有广州入口数据、代理节点切换或新增依赖下载。真实面板/MySQL 测试复用现有隔离 Lima；Docker Desktop 内核缺少所需 ipset 类型的尝试不计为通过。

## 功能与恢复

| 套件 | 通过项 |
|---|---:|
| p2-accepted-helper-legacy | 47 |
| p2-accepted-helper-nft | 47 |
| p2-accepted-p1-faults-legacy | 13 |
| p2-accepted-p1-faults-nft | 13 |
| p2-accepted-p1-kernel-legacy | 43 |
| p2-accepted-p1-kernel-nft | 43 |
| p2-accepted-p2-faults-legacy | 13 |
| p2-accepted-p2-faults-nft | 13 |
| p2-accepted-p2-traffic-legacy | 46 |
| p2-accepted-p2-traffic-nft | 46 |

合计 324 项；另有真实 Java/MySQL 面板 53 项端到端检查通过。Go `test -race` / `vet`、前端构建通过；JUnit 19 项、0 失败/错误、1 项既有 Spring 上下文跳过。AMD64 仅完成交叉编译，不宣称本轮做了原生 AMD64 内核矩阵。

覆盖不同本机监听/目标地址、通配 UDP 服务、IPv4 回环预配置、IPv6 网卡及纯回环、精确 UDP 字节去重、既有 TCP/UDP 暂停、单共享预算、目标不健康时不消耗预留、健康恢复、共享带宽变更失败关闭与恢复、state5 重启、维护卸载；两种后端均含九阶段崩溃恢复。P2 故障套件使用真实本机目标，验证 INPUT/POST SNAT 与本机 OUTPUT 恢复。

启动同步前先完成测试拓扑地址配置，避免把地址变更事务的预期短暂门控当成静态链路故障。正式数据路径仍保留地址变更时的门控保证。

## 性能对照

冻结 P1 参考：`51de4ee90db93f5a31c8ad1796c8ebe7b380cbf30290a9033c6698eb2611625d`。主窗口对照使用的 P2 Agent 为 `77338aad6a0f2da8ae8b442ea4316aa81fecce0b066f4506f97a0a2df68fea45`。

3/10k 规则各三轮交错顺序，统计每秒上报，端点与 Agent 固定 CPU1。每方向连续八次 1 GiB 接收确认形成窗口，避免短促峰值与一秒采样相位互相影响；另测 20 秒 150 Mbps CPU 及每次 5000 个常驻 TCP/UDP RTT。私有应用负载合计 196.192 GiB，低于单次 256 GiB 上限。CPU 包含端点、softirq 和 guest 系统开销，不是纯转发器 CPU，也不是独占物理 PMU。

| 规则数 | 指标 | P1 中位值 | P2 中位值 | 变化 |
|---:|---|---:|---:|---:|
| 3 | window_up (Gbps) | 51.160 | 51.326 | +0.3% |
| 3 | window_down (Gbps) | 58.405 | 57.549 | -1.5% |
| 3 | tcp_paced (CPU-s/GiB) | 3.677 | 3.722 | +1.2% |
| 3 | tcp_persistent (p95 us) | 241.500 | 281.375 | +16.5% |
| 3 | udp_persistent (p95 us) | 250.958 | 252.292 | +0.5% |
| 10000 | window_up (Gbps) | 47.519 | 45.791 | -3.6% |
| 10000 | window_down (Gbps) | 52.180 | 52.413 | +0.4% |
| 10000 | tcp_paced (CPU-s/GiB) | 10.342 | 9.904 | -4.2% |
| 10000 | tcp_persistent (p95 us) | 191.458 | 210.166 | +9.8% |
| 10000 | udp_persistent (p95 us) | 205.875 | 180.375 | -12.4% |

较长窗口没有复现早期单次下载峰值约 8% 的持续下降。10k 上行约 -3.6%、下行约 +0.4%、固定负载总 CPU 约 -4.2%；TCP p95 中位值增加约 19 us、UDP p95 降低，原始范围有重叠。**这些结果支持性能总体接近 P1，不证明每个指标严格零退化，也不宣称性能必然提升。** 3 条规则的 TCP p95 中位值同样偏高、跨轮波动较大，仍是后续稳态/物理环境需跟进的信号。

最后一次修改只修正 P2 通配 OUTPUT 在目标不健康时的捕获边界。最终二进制完整功能及面板复验通过；另用最终二进制在 3/10k 规则核验了实际可达转发规则图及自有集合，与性能采样版及 P1 完全一致。**没有将前一二进制的逐样本性能结果伪称为对最终二进制的再次完整采样**；最终 proof 与各版本哈希一并保留。

## 交付与边界

源码包含原生内核路径及新表单/能力协商；本机平滑整形、本机 UDP 源地址保留、外部 IPv6 回环、scoped IPv6、跨用户全局隧道带宽、原生 nft 后端、单物理节点多引擎迁移、NAT64、WireGuard/CDN 数据封装、协议屏蔽和生产灰度仍按完整清单推进。

新版本尚未冻结正式发布资产或生产镜像。旧 P1 的 Fusion 30 分钟稳态/VM hard stop 证据继续保留，本次应用崩溃及恢复不替代新版本的物理 PMU、实际宿主掉电或更长稳态验收。

原始 JSON、逐轮范围、接收确认、规则图、功能日志、面板结果和 SHA 清单位于任务输出 `outputs/p2-validation/`。
