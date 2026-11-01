# HTTP / TLS / SOCKS 屏蔽与旧监听迁移（v5.4）

本次仅开发和隔离验证，没有更新生产面板、节点、数据库或防火墙。GOST 引擎保持原有控制路径；iptables 与原生 nftables 后端共用新的可选识别器。

## 控制与策略

面板节点的 HTTP / TLS / SOCKS 开关写入原有字段，生成 schema 5 的 `protocolFilter`，通过现有带修订号的规则对账下发。交互应用与批量对账使用同一个工厂；节点全局屏蔽与规则单独屏蔽取并集。开关改变会改变意图摘要，重新应用并清除受影响连接的 conntrack，已有 TCP 连接需要重连。没有 `protocolBlocking` 能力的旧 Agent 会被明确拒绝。

```json
{"schemaVersion":5,"protocolFilter":{"http":true,"tls":true,"socks":true,"unknown":"allow"}}
```

`unknown` 只接受 `allow`。schema 5 使用 checkpoint format 7，防止旧二进制忽略屏蔽字段后启动。不要直接用 v5.3 或更旧的二进制读取该 checkpoint；回退前需要结算并安排受控状态迁移。

## 数据路径与边界

- 只对尚未判定的原方向 TCP 进行 NFQUEUE 识别，不接管整个 TCP 字节流。HTTP 常见请求方法 / HTTP2 明文前言、TLS ClientHello 记录前缀、SOCKS4/5 握手可独立屏蔽。SOCKS5 沿用仓库 GOST 的认证方法判据（方法列表包含 0x00 或 0x02）；只有其他/私有方法时归 UNKNOWN，避免扩大对不透明数据的误判范围。
- 最多重组前 4096 字节、暂存 16 个包、等待约 500ms；支持 TCP 序号重排与一致重传。大 GSO 包只取前缀，不会因正文很大而跳过已能识别的协议。
- 不认识、前缀不足超时、冲突重叠、超出识别边界或用户态暂存/缓存上限时，归为 UNKNOWN 并放行。UNKNOWN 会记录原因；不存储或记录业务载荷。
- UDP 直接由内核标为 UNKNOWN 并放行，按新 UDP conntrack 的首包判定计数（若后续 hook 丢弃未确认连接，重试可能再次计数），不送用户态识别。QUIC、HTTP3、DTLS 等不会因 TLS/HTTP 开关而自动屏蔽。
- 判定缓存在 conntrack 低五位（mask `0x1f`），保留高 24 位转发 token 和其他低位。NFQUEUE verdict 的 CTA_MARK 只包含掩码内的判定位，不能把完整 token 填入 masked-XOR 的 value；单测验证幂等，真实 TCP 验证 token 保持及有限配额不可绕过。已放行的连接直接走内核快路径；TCP 识别缓存最多 32768 项，暂存前缀最多 4096 项，全局最多持有 2048 个包。
- `inet FP_PROTOCOL` 只在有生效策略时安装，表级 comment 必须精确匹配 `flux-protocol:v1`。INPUT / OUTPUT / FORWARD hook 优先级 -6：事务栅栏优先，协议丢弃先于配额和业务字节计数。暂停、有限配额、原有网络层双向计费继续生效。
- 固定队列 41600，只绑定自己的队列，不执行全局 PF_UNBIND；不使用 queue bypass。队列不可用时，受屏蔽规则报告失败并停止转发；无策略规则继续独立工作。运行 helper 保持原有 `NET_ADMIN / NET_RAW / NET_BIND_SERVICE`，不增加长期 SYS_ADMIN 权限。

这是有界前缀识别。故意分段并拖延超过识别时限、协议伪装和加密内部协议可以成为 UNKNOWN；按用户指定策略放行。它不能充当不可绕过的 L7 安全网关。

## 观测与性能实现

`GetForwardStatus.protocolInspection` 包含 `ready/error`、运行 epoch、HTTP/TLS/SOCKS/UNKNOWN/blocked 决策次数、UNKNOWN 原因，以及独立的 `counterError`。这些是诊断计数，不替代持久化流量账本。TCP 诊断计数随进程重启重置；UDP 内核诊断计数在进程首次接管时重置，暂停/移除对应规则时回收其 UDP 诊断对象，恢复时重新计数，避免 token 复用继承旧业务的 UNKNOWN 次数。对账、暂停和恢复不重置 TCP 诊断计数。界面标明当前进程周期，跨 epoch 不应相减。

UDP 诊断对象使用只读 NETLINK_NETFILTER GETOBJ，按秒缓存整张表的结果；状态页不会为每条规则启动一个 nft 子进程。失效流检查最多每 50ms 执行一次，避免每个新包扫描所有缓存。完整首包能直接判定时不分配 8KiB 重组缓冲，只为分片或缺口分配。已判定允许的连接先检查 connmark 后返回，省去协议过滤集合查询。未启用过识别的进程不创建队列或协议 hook；完全停用后删除协议表，已打开的队列工作线程保持空闲至进程退出。

仍可研究的新连接优化是减少纯握手包的用户态往返、分片重组分配和按到期时间回收缓存。但须验证无载荷 ACK、TCP Fast Open、乱序与资源上限，不能直接跳过首个携带数据的包。提高并行度应通过按连接分片 NFQUEUE 完成，保留同一连接的判定顺序；需另做多核负载证据。不得启用 flowtable/offload 绕过暂停、配额和统计。

## qcloud 旧监听适配

旧 GOST 的 `[::]` 可能同时接受 IPv4。内核 NAT 不会通过 IPv6 wildcard 自动获得 IPv4 接入。生成 iptables 规则时，只有旧存储值**精确为 `[::]`，且该规则的目标全部是数值 IPv4**时，才将默认监听规范为 `0.0.0.0`；修复方括号重复拼接。不修改原隧道对象或数据库，不把云公网 NAT 地址作为本机地址绑定。

GOST、显式 `::`、自定义监听和真正的 IPv6 规则保留既有语义。域名或混合地址目标不会被静默推断成 IPv4，需要显式配置监听族。云 NAT 验证只使用文档地址 `203.0.113.77` 在隔离 namespace 中模拟，转换到测试节点实际私网地址；没有访问真实 qcloud / GZ 入口。

## 可重复验证入口

- Go：`GOSUMDB=sum.golang.org go test -race ./...`、`go vet ./...`。
- 内核真实套接字：`node-agent/tests/protocol-blocking.py`，由已有私网 namespace fixture 运行，分别选择 `FLUX_KERNEL_BACKEND=nftables`、iptables-nft、iptables-legacy；`FLUX_DPI_HELPER=1` 验证最小权限 helper。
- 三组性能：`node-agent/tests/benchmark/protocol-window.py`，冻结 v5.3、候选关闭识别、候选开启全部识别；相同原生 nft 后端，3/10000 条规则、轮换顺序、双向 8GiB 窗口、150Mbps、持久和新建连接延迟。每个 case 使用独立客户端源 IP。
- Java：离线 Maven 单测包含旧监听迁移、交互/对账一致性、节点策略变化、能力拒绝和 UNKNOWN 契约。前端执行 TypeScript/Vite 构建。

实际结果、二进制 SHA256 和性能的可证明范围见配套验证报告。
