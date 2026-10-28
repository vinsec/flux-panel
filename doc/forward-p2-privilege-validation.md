# P2 v5.2 缩权与回程诊断验证

2026-10-28，基于 `2a036af`。实现与运行契约见
[v5.2 说明](forward-p2-privilege-returnpath.md)，原始汇总与哈希见
[验证 JSON](forward-p2-privilege-validation.json)。本轮未部署生产。

## 权限与功能

Fusion Debian 13 ARM64 / Linux 6.12.113，4 vCPU / 4GiB，iproute2 6.15 /
libbpf 1.5。每套件私有 mount/net namespace，数据只经本机 veth/回环；
无外网业务路由，没有 qcloud GZ 流量。

28 个套件、832 次断言执行通过，覆盖 iptables-nft/legacy、直接模式/helper、
原 P1/P2 回归、九阶段崩溃恢复、暂停、配额、双栈、UDP 源地址与 PMTU。
新增 pin 缺失、boot/object/program ID/tag 不匹配、未提交阶段、幂等恢复和
管理员修复验证；异常时保持新限速意图并关闭，不回退为不限速。

实际 systemd 单元验证：准备进程结束后 MainPID=0；长期 helper 的
CapEff/CapPrm/CapBnd/CapAmb 均为 `0x3400`，只有原三项网络能力，
不含 SYS_ADMIN(bit21) 或 BPF(bit39)。ProtectSystem=strict、
ProtectKernelTunables=yes、bpffs/准备目录只读，仍能通过真实 typed RPC
安装本地限速 BPF 过滤器。网络进程零 capability。

准备器是短时 root 单元；它为固定嵌入对象处理模块 BTF 和 pin，允许写入
bpffs。长期进程无 ELF 加载/模块 BTF 枚举回退。没有降低主机
unprivileged_bpf_disabled 设置；检查值记录在 JSON。

回程诊断验证包括：默认不建立任何目标连接、同族多个目标不丢失、管理员确认
不等于远端验证、严格 RPF 接口不匹配、all/interface 最大值、IPv6 不套用
IPv4 RPF、无效输入拒绝、真实缺路由、显式最多两次 TCP 握手。节点探测不带
业务 connmark，转发计数不增长；不会自动改变确认或放行规则。

另一个隔离 Linux 6.1 环境运行真实 Spring Boot/MySQL，通过 62 项检查，包含
新 API/默认只读行为、显式 TCP、输入类型、10k 批量应用/清理、额度续期、
删除竞争和 GOST 兼容。Go race、Linux vet、Linux 原生 engine 单元和前端/Maven
检查通过。amd64 仅交叉构建，不冒充 x86 真机验收。

## 普通转发性能

冻结 v5.1 对照 v5.2，同 VM 三轮交错、3/10000 规则，双向 8×1GiB 接收确认，
20秒 150Mbps CPU、TCP/UDP 各 5000 次常驻 RTT。共 196.19GiB 隔离内网应用
负载，120000 次 RTT 无丢失。每次核对实际进程二进制 SHA；可达规则图和自有
集合完全一致，没有给未使用功能的规则增加 pin 查询或数据面步骤。

三轮中位数变化：

| 规则数 | 上传吞吐 | 下载吞吐 | 固定速率 CPU | TCP p95 | UDP p95 |
|---|---:|---:|---:|---:|---:|
| 3 | +4.99% | +4.86% | +5.81% | -3.9μs | +0.6μs |
| 10000 | +6.17% | -0.59% | -4.76% | +4.3μs | +9.2μs |

CPU 含端点与 guest 背景工作，轮次范围保存在 JSON。小幅分位变化不视为
逐项零差异；本次未发现实质退化，也不据这些 VM 波动宣称确定性能提升。
吞吐是虚拟内网内存路径，不等于公网/物理 NIC；没有物理独占 PMU 归因。

## 本地限速对照

两版同样启用 200Mbps 共享 HTB/fq_codel、固定负载 150Mbps，两轮反向顺序。
候选长期进程降为基础三项能力；两版 BPF 程序 tag 均为 `17e0a0dfa7d78963`。

| 配置 | 实际接收 | CPU1 占用 | TCP p95 | UDP p95 |
|---|---:|---:|---:|---:|
| v5.1 | 149.99Mbps | 8.93% | 109.2μs | 146.6μs |
| v5.2 | 149.99Mbps | 8.43% | 106.1μs | 141.4μs |

因此缩权没有引入新的逐包工作，本轮也未观察到本地限速功能/性能退化。
上述 CPU 是包含主负载端点/softirq 的观测，不把 0.5 个百分点差异视为精确归因。

候选 ARM64 Agent SHA256：
`ff1441efc744054500e96c296a87a534288864bef7328c5268500799a926a933`

验证 JAR SHA256：
`7648f8f1433bd205a01f2ef5341f3a3352aff80cd168d42b6822a0b6e9352f32`

离线包从代码提交 `02587e7931ab85abde4e00ee11fdb51c1d057bb6` 的干净源码构建，ARM64 SHA 与
测试版本一致，amd64 交叉构建成功。固定清单校验、幂等安装、真实转发、
从冻结 v5.1 升级、激活失败回滚、账本保留及卸载共 11 项断言通过。
准备单元和新 drop-in 随校验清单交付，不由默认安装器自动启用。
