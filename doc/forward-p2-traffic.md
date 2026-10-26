# P2 第一批：本机路径与源地址模式

2026-10-27，基于 `feat/forward-engine-iptables`。本批是 21、22 的基础实现，不表示 21–27 全部完成。不执行生产部署、数据库迁移或广州入口测试。

## 配置与版本

沿用 P1 端点、DNS、双族、目标池、业务 token 与账本。只有新 `traffic` 配置使用 ForwardSpec **schema 4**；Agent `iptables-v5` 声明 protocol 1/2/3/4，以及 `trafficPolicy`、`localOutput`、`localTargets`、`preserveSource`。面板在下发前检查能力，普通 P1 规则保持 schema 3，旧 IPv4 规则保持兼容路径。含 schema 4 的状态使用 **format 5**，旧 Agent 必须拒绝读取；回退先走维护备份/结算流程，不直接覆盖二进制。

```json
{
  "schemaVersion": 4,
  "id": "1_2_3",
  "revision": 1,
  "enabled": true,
  "listen": {"host": "0.0.0.0", "port": 18000},
  "targets": [{"endpoint": {"host": "10.0.2.2", "port": 19000}, "weight": 1}],
  "traffic": {
    "localOutput": true,
    "localTargets": false,
    "sourceMode": "preserve",
    "returnPathConfirmed": true
  }
}
```

`localOutput` 默认 false，启用后本节点程序可以访问该转发入口；独立 OUTPUT 绑定哈希不影响未开启的规则。`localTargets` 默认 false，允许目标为分配在本机网卡上的地址或回环地址。来源与目标均须同族；这不提供 NAT64。`sourceMode` 默认 `masquerade`，`preserve` 仅做 DNAT，拒绝同时指定 SNAT 源地址。

`returnPathConfirmed` 是管理员对目标回程经过本节点的**明确确认**，不是 Agent 已核实远端路由的声明。节点无法仅凭本机 `ip route get` 证明目标机或同网段客户端的路由，故缺少确认时拒绝启用，不自动取消 SNAT。保留源地址时需准备目标回程、策略路由及合适的 rp_filter；错误确认会导致回程失败，不会自动降级为 MASQUERADE。默认 MASQUERADE 保留，可支持同网段 hairpin。

## 数据路径与安全边界

- 外部转发继续走 PREROUTING → FORWARD → POSTROUTING；普通数据不增加随全局规则数增长的扫描。
- 本机发起通过 OUTPUT mangle 绑定和 OUTPUT DNAT 接入；本机服务的请求在 INPUT、回包在 OUTPUT 受策略控制。每条规则有独立的本机来源/本机目标允许集合，启用另一条本机规则不会放开原本仅支持外部转发的规则。
- 网络层字节在 FORWARD 或终端 INPUT 计数；OUTPUT 仅对离开本节点的包计数。本机到本机同时经过 OUTPUT/INPUT，仍只收取一次 IP 包字节。上传/下载仍进入原转发、用户、用户隧道授权账本。
- 限额规则共享同一个原生 nft quota 对象；INPUT/OUTPUT 与 FORWARD 使用相同的额度、单调 TTL。事务在三类终端 hook 同时关闭路径，暂停已确认连接，避免修改期间绕过或消耗预算。
- 发往本机的流量不做 MASQUERADE。否则某些回环 UDP 服务会选择网卡地址回包，破坏原有 NAT 五元组。远端及 hairpin 的默认 MASQUERADE 保持。
- 不改主路由、默认路由、全局 sysctl 或物理网卡 root qdisc。外部监听转向 IPv4 回环时，目前要求事先显式配置 `net.ipv4.conf.all.route_localnet=1`；默认拒绝并建议使用网卡地址。此项并不自动配置按接口的最小权限策略，属于后续收敛项。纯本机回环不需此配置。

## 尚未完成的组合

`localTrafficShaping=false`。现有 IFB 在出口整形，终止于 INPUT 的方向无法完整覆盖，因此初次在本机路径上设置转发/用户/授权平滑带宽上限时，面板明确拒绝。若管理员后来给已有本机规则添加共享上限，对账必须把新策略送到节点，由节点关闭该规则并显示 failed；不能只拒绝更新而保留旧的不限速规则。移除冲突限速后正常恢复，账本不重置。

第 21 项的本地路径平滑整形、容器宿主组合和全部端口复用矩阵尚待补齐；本批不把它标为完整完成。IPv4 外部回环的按接口 route_localnet 检查/最小开放也待补，当前采用更保守的显式预配置要求。

## 后续逐项实施方案

| 原编号 | 剩余工作 | 实施与验收 |
|---|---|---|
| 21 | 本地路径平滑整形与完整组合 | 为终端 INPUT 建立独立可控的整形路径，不能用 nft 丢包限速冒充 HTB 平滑整形。评估 TC/BPF 的 conntrack/首包分类与 reinject 去重，仍使用现有用户→授权→转发类树；没有完整分类/去重能力的内核拒绝该组合。补本机↔容器、既有 TCP/UDP 暂停、跨族独立监听/复用、共享组聚合和 route_localnet 按接口最小开放测试。 |
| 22 | 运维预检增强 | 保留管理员回程确认；增加结构化客户源网段与节点本地 rp_filter/策略规则检查。若需自动证明远端返回路由，需有目标端探针/Agent 的明确能力与短期握手验证，单侧健康 TCP 成功不能证明真实客户端地址的回程。故障时明确诊断，不悄悄切回 SNAT。 |
| 27 | 原生 nftables map 后端 | 先提取纯数据路径编译器与计数快照接口，保留 Manager/账本/租约事务；按族生成 listener→mark、mark→DNAT map/vmap、named counter 和共享 quota。在独立表内原子更新，审计自有对象和流卸载冲突。先达到 P1 与本批完整黑盒矩阵，再测 2/1k/10k 规则、更新和采样并发，不能把 iptables-nft 称作原生后端。 |
| 26 | 单物理节点多引擎与迁移 | 新增物理节点身份及按引擎注册的 Agent 会话/能力；将现有物理主机端口锁推广为协议、地址族、地址、端口的全机仲裁。迁移分 prepare/结算+停旧/切换+核验/失败回滚，业务 ID 与累计账本连续；用户必须能看见不同引擎间的 TCP 断流边界。先实现停流迁移，再讨论 drain。 |
| 23 | 跨族转发 | 对支持 Jool 的受控 Linux 单独增加 NAT64 capability、模块/版本/地址池/前缀审计及命名空间隔离；双向转换分别测试 TCP/UDP、ICMP 翻译、PMTU、分片、暂停/额度/重启。不能安装模块的节点明确选择支持该能力的 GOST，引擎与计量口径须可见。 |
| 24 | 加密中继及 CDN 数据通道 | 先复用已有 GOST TLS/QUIC/WS/WSS 能力；内核方案分为 WireGuard 的密钥/接口/握手/MTU/路由生命周期，再在内层调用同一转发后端。密钥只在受保护配置/helper 中，不进入普通 Spec。CDN 仍通过 WS/WSS/HTTPS 协议网关，独立验证数据封装与回连，不能用控制连接的 WSS 代替数据能力验收。 |
| 25 | 应用协议屏蔽 | 先约定允许承诺的可见 HTTP/TLS/QUIC 握手范围及 unknown 处理，再增加有界代理网关/可选 DPI。用明文、加密、ECH、分片、重传、混淆和误报样本验收，无法判断时按配置处置；不以端口/字符串匹配宣称可靠识别。纯 L4 模式不引入这些代理成本。 |
| 10 | 生产灰度 | 本地验收冻结后，另选低成本受控节点与流量预算，备份并核对账本/额度，再小流量灰度和回滚演练。当前不执行生产部署，不以广州入口压测。 |

物理独占 PMU、切断实际宿主机电源等第 20 项物理范围仍不作已测声明；此前 Fusion 的 30 分钟稳态与虚拟机 hard stop 证据保留。
