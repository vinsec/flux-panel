# 原生 nftables map 后端（v5.3）

本后端仍使用 `iptables` 这个面板引擎类型及原 ForwardSpec、中央 credit、
累计账本和 helper 协议。节点配置新增 `"kernelBackend":"nftables"`；省略或
`"iptables"` 保留既有 iptables-nft/legacy 路径。`iptables-nft` 命令本身不代表
选用了这里的原生后端。实时 EngineHello/节点工具报告实际 kernelBackend 和
nativeNFTMap 能力，避免只从版本或命令名推断。

## 编译与逐包路径

独立拥有 `inet FP_NATIVE`，不翻译 xtables 文本，也不 flush ruleset。
地址族/协议/地址/端口的拼接 map 将首包映射到 conntrack token；单目标 DNAT
直接查 token→地址/端口 map，多目标由 token→verdict map 跳到有限目标池。
round 为加权轮询，random 为加权随机，hash 保持同一来源 IP 的黏性。
现存 conntrack 继续绑定原目标，DNS retiring 路径沿用相同 token。

许可集合和两个方向的 counter 对象 map 都以目标地址+token 查询。无目标、
暂停、到期或运行时前置条件失败的转发没有许可；既有连接也必须通过该检查。
普通转发的规则数量不随总转发数增长。原子事务只替换配置元素与规则引用，
命名累计 counter 不重建、不归零，历史对象由既有 ACK/conntrack/保留期 GC 回收。
只读采样使用 `list counters table`，不导出整个规则图；控制 map 缓存身份，
不用每秒重装一万条元素。

规则使用 [nftables map](https://wiki.nftables.org/wiki-nftables/index.php/Maps) 与
[命名 stateful object map](https://wiki.nftables.org/wiki-nftables/index.php/Stateful_objects)。
部署前仍需实际内核验收；这里已避开 Linux 6.12 不支持的寄存器间 bitwise 运算。

## 配额、暂停与本机路径

复用独立 `FP4_QUOTA` 的共享命名 quota 和短期限集合；同一业务的 v4/v6、
上传/下载及本机/外部来源消耗同一预算。准入计数发生在额度 gate 之后，因此
被额度丢弃的包不进入计费累计值。TLS/WSS 控制协议及面板三层账本口径不变。

事务 guard 独立于可替换配置图，覆盖 INPUT/OUTPUT/FORWARD。小批只拦截指定
token，大批整体拦截；回滚、崩溃恢复期间不提前放行。辅助路由、共享 HTB/IFB
和已经缩权的固定 BPF pin 复用原实现；两个编译器共用运行时前置条件检查。

本地原发、回环、hairpin、DNAT-only、双栈和 RELATED ICMP 保留各自路径。
本机到本机只在 OUTPUT 计数；loopback INPUT 再检查许可但不重复计费。
IPv6 ND 等无 conntrack 的控制报文保持宿主策略，不能落入业务的兜底丢弃。

## 所有权与迁移

- 系统已经启用相应 forwarding；Agent 不静默改 sysctl、全机防火墙策略或 MTU。
- 继续使用全网络命名空间单实例锁。原生表必须有精确 owner；epoch 和内核
  ledger instance 写入独立标记链，缺 checkpoint 时拒绝重新生成计费身份。
- 本模式为兼容 Linux 6.12 对受管报文保留完整 mark 字段；检测到外部 mark
  读写冲突或 flow-offload 时拒绝。既有 iptables 模式保持原分配约定。
- 不接管存活的旧 Flux xtables 规则。维护必须使用 checkpoint 对应的原后端；
  backend 不符时，在读取/修改另一后端之前拒绝。普通升级也拒绝暗中切后端。
- nft 模式的 checkpoint 使用 state format 6，阻止不认识 kernelBackend 的
  旧二进制在重启后静默改用 xtables。既有 iptables 模式仍写原来的 3/4/5。
- 明确维护停流、最终结算并备份后，用原配置清理规则，保留 epoch 与最新账本；
  全部转发暂停、计数基线清理且无未恢复 journal 后，才修改 kernelBackend 并
  启动新后端。业务恢复必须通过正常面板新版本/额度对账。跨引擎已有 TCP
  连接会断开，不声明无损迁移。
- 保留宿主已有防火墙链。其他 base chain 的 DROP/默认 DROP 仍可阻止业务；
  nft ACCEPT 不越过它们。宿主需显式放行所需转发路径，Agent 不擅自改成 ACCEPT。
- 卸载先结算/停流，删除本模式的表、配额和自有辅助资源，保留账本及外部规则。

## 剩余清单

27 的原生后端与 26 的单节点多引擎/在线迁移是两项不同工作。
27 的受控后端迁移不等于 26 的按转发选择引擎和自动两阶段迁移。

仍需分别交付：26 的统一物理身份、多连接 capability、持久化迁移状态机及
跨引擎端口/账本仲裁；23 的 Jool/NAT64 跨族能力；24 的 WireGuard 管理及
独立隧道验收；25 的明确协议识别/未知策略与可选代理。WS/WSS/CDN 和已有
GOST 协议封装保持现有 GOST 路径，不能由本原生 L4 后端冒充实现。

21 的原始本机分片/额外 IPv6 回环边界、22 的 wildcard UDP/IP_PKTINFO
显式服务契约及远端协作回程证明也仍需单独验收。生产灰度与物理 PMU/真实
宿主掉电不在隔离 VM 结果内。所有性能和功能实验继续排除 qcloud GZ。
