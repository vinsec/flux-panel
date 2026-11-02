# P2 第二批：本地平滑限速与固定绑定 UDP 源地址

2026-10-28，分支 `feat/forward-engine-iptables`，Agent `iptables-v5.1`。
沿用 schema 4 / state format 5、业务 token、共享额度和累计账本。
本批不表示 P2 23–27 或生产上线已完成。

当前缩权与回程诊断实现已更新至 [v5.2 说明](forward-p2-privilege-returnpath.md)。
以下保留 v5.1 的实现与权限成本记录。

## 本地平滑限速

`localTrafficShaping=true`。本机 OUTPUT、本机目标和普通转发共用已有
owned IFB + HTB/fq_codel；用户、UserTunnel 授权、转发三级上限及上下行
计费方向不变。同一用户的本地/远端规则不会各获得一份带宽额度。

物理入口先由 tc ct 追踪/重组，再用 flower 的 connmark/方向和首包绑定
哈希匹配进入共享队列；物理出口继续用 fw 哈希分类。回环出口使用一个
固定、内嵌的 CO-RE BPF 程序，只读取 conntrack 并恢复入队前五元组，避免
IFB 重入丢失 NAT 连接；业务数据始终在内核。ICMP/ICMPv6 不进入数据队列。
低位 0x40 只在该能力启用时跨 mangle 保留，防止同一方向重复入队。
未开启本地限速时不加载 BPF、不安装入口追踪或回环分类器。

### 节点前置条件

此功能为显式启用能力，Agent 不自动改主机 sysctl、回环 MTU 或外部防火墙。
管理员准备：

```sh
# 示例：仅在明确启用此功能的节点上执行并按系统方式持久化。
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
mkdir -p /sys/fs/bpf/{tc,ip,xdp}/globals
ip link set lo mtu 131072
sysctl -w net.ipv4.conf.lo.accept_local=1 net.ipv4.conf.lo.rp_filter=2
```

需要内核 BTF、tc ct/flower、IFB/HTB/fq_codel、bpf_skb_ct_lookup 及匹配的
libbpf/tc。IPv4/IPv6 同用这些前置条件；不放宽物理接口的反向路径校验。
完整 UDP 报文进入回环队列后才重新执行原连接的 NAT。原始本机非首片、
IPv6 routing/AH 和 jumbogram 不在该可选队列契约内。

使用独立 helper 时，将已校验的 `flux-kernel-local-shaping.conf` 安装到
`/etc/systemd/system/flux-kernel.service.d/local-shaping.conf`，daemon-reload
并重启 helper/网络进程。该可选 drop-in 累加 CAP_BPF 和 CAP_SYS_ADMIN；默认三项权限不变，
不关闭 ProtectKernelTunables。stock tc/libbpf 读取模块 BTF 的 GET_NEXT_ID /
GET_FD_BY_ID 接口在验证内核仍要求 SYS_ADMIN。这是显式可选模式的权限成本；
不接受时保持基础模式并让本地限速失败关闭。后续可通过一次性预加载/固定
程序、helper 只取程序 FD 的方式缩减长期权限，需另做权限/升级验收。tc/ip/xdp 的 globals 目录需提前创建，
运行期间不写 /sys/fs/bpf，也不固定 map/program。运行在容器/网络命名空间时，
bpffs 需在实际 helper 的 mount namespace 内可见，不能仅检查父进程挂载。网络进程仍为零 capability。
权限/库/内核预检失败时新限速意图保留、规则 failed 且关闭，不回退为不限速。
改变程序权限或内核环境后重启 helper，再重新对账。

前置参数丢失会在运行时关闭相应规则，恢复后自动重建；自有 IFB 的创建/
删除通知按 netlink 设备名/索引过滤，不缓存新接口清单去跳过旧绑定快照。
物理接口地址、IPv6 DAD 和删除事件仍逐次对账；运行时检查自有 IFB 的存在、
UP 状态和索引，外部删除/替换会触发重建。发现外部 ingress/egress
classifier、raw NOTRACK 或非默认 CT zone 时拒绝接管，保留原资源。
此跟踪约束需在本地限速运行期间持续成立。

## UDP 保留源地址

`localUDPPreserveSource=true`。`sourceMode=preserve` 仍要求明确
`returnPathConfirmed=true`。允许本机 IPv4/IPv6 UDP 服务固定绑定**目标 IP**，
回包来自同一绑定地址；通过 DNAT-only 保留真实外部/本机来源，无静默 SNAT。
通配绑定或与目标端口共享的通配 socket 仍明确拒绝；不猜测 IP_PKTINFO
实现是否满足回包地址契约。双栈通配 socket 对 IPv4 的潜在歧义也保守拒绝。

节点缓存 /proc/net/udp{,6} 清单 100ms，并按运行时周期检查绑定契约。
丢失/改成通配时规则 failed 并关闭；精确绑定恢复后自动恢复。暂停、配额、
计数、重启及整形仍使用同一业务状态。改变探测到失败之间存在一个检查周期，
这不是对任意本机程序发送行为的强制约束；服务必须使用该绑定 socket 回包。

## 状态、资源及回退

新增局部 tc 资源使用 aux manifest v2；旧 Agent 拒绝接管，需维护结算后回退。
主状态和传输 schema 不增加字段。嵌入对象写入 statePath.bpf 私有目录，
只从编译进 Agent 的字节加载。自有 probe 有 epoch 所有权，始终为 down；
最后一个本地限速规则移除/维护卸载时清理自有过滤器、IFB 和对象，保留外部
root qdisc/classifier。默认系统单元和不用该功能的节点不增加 BPF 权限。

源码、BPF 构建说明和验证器见 `node-agent/internal/engine/bpf/README.md`、
`node-agent/tests/p2-local-shaping.py`、`p2-udp-source.py`、
`p2-local-no-bpf.py`、`p2-shaping-faults.py`。

批量对账与交互创建/更新/删除/暂停现在共用现有物理节点 GET_LOCK，覆盖
期望快照读取到交互操作最后一笔 DB 写入。恢复在取锁后开启事务，保留首笔
额度的 after-commit 语义。真实 MySQL 验证用 revision 行锁强制删除与限速
对账并发，检查删除后不会以新 revision 复活旧配置。

## 后续顺序

当前边界也计入剩余工作：21 的一次性预加载/长期 helper 缩权、原始本机
分片与额外 IPv6 回环组合；22 的通配 UDP/IP_PKTINFO 显式服务契约与自动回程
诊断。当前固定绑定支持不代表这些项目已自动完成。

1. 22 的回程/反向路径诊断：输出路由、源地址、rp_filter 和可证明/不可证明项；
   保留管理员确认。目标端配合探测是另一个明确协议，不能把本节点 route get
   当作远端返回路由已经正确的证据。
2. 27 原生 nft map 后端：复用 Spec/额度/账本与黑盒矩阵，分别实现 map/vmap
   编译、原子事务、计数恢复、互斥所有权、维护回滚，再按相同基准验证。
3. 26 单节点多引擎/在线迁移：物理节点身份、跨 Agent 端口仲裁、预备/停流提交、
   失败回退和累计水位连续性；明确跨引擎 TCP 连接断流边界。
4. 23 跨族：独立 Jool/NAT64 capability，先验证模块、地址池、ICMP/PMTU 和
   双向连接/配额，再实现安装与管理；不支持环境继续使用 GOST。
5. 24 加密中继：先 WireGuard 内层转发；WS/WSS/CDN 数据封装保留 GOST。
6. 25 应用协议屏蔽：先明确可识别范围与误判策略，再选择代理/DPI 适配；
   不承诺对 ECH、加密和混淆流量的可靠 L4 识别。

生产灰度/发布资产替换属于 10；物理 PMU、真实物理掉电和更长稳态属于 20
剩余验收，本地 VM 结果不能替代。当前运行数据仅限隔离内网，排除 GZ 入口。
