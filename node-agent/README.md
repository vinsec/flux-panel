# 独立内核 Agent（v5.3）

当前实现包含域名、双栈、多目标、出口路由、共享平滑限速、本地路径、源地址保留、
缩权 helper，以及可选的[原生 nftables map 后端](../doc/forward-native-nft.md)。
节点配置 `kernelBackend` 省略或为 `iptables` 时保持既有模式；显式为 `nftables`
才选择新后端。模式切换须先用原配置维护结算/停流，不能直接覆盖活动节点配置。
nft checkpoint 为 format 6；保留的 iptables 模式仍按功能写 3/4/5。

完整能力和验收边界以 [实施清单](../doc/forward-engine-roadmap.md) 与各批验证报告为准。
以下 v3 章节保留历史基础方案，不能据其中的历史“未支持”描述判断当前版本。

本模块不依赖或启动 GOST。管理通信使用面板的 WSS 协议，业务数据在 Linux 内核完成 IPv4 TCP/UDP DNAT/SNAT。

## 当前范围

- 隧道和节点选择 `iptables`；旧记录迁移后默认为 `gost`。
- 单目标数字 IPv4 地址、TCP/UDP 同端口，新增/更新/暂停/恢复/删除。
- 原始网络层双向计数、持久化累计值、面板事务去重与三层账本。
- 本地保存配置和计数基线；Agent 重启不清空现有账本；到期时可在失联期间阻断转发。
- 不支持 IPv6、域名、多目标、指定出口网卡、应用协议屏蔽、GOST relay 中继和平滑带宽限速；这些请求明确拒绝。

## 安装前置条件

仅在隔离验证通过并检查目标机防火墙后部署。面板必须先显式执行 `springboot-backend/migrations/001-forward-engines.sql` 和 `002-engine-foundation.sql`；脚本可重复执行，不在启动时自动迁移生产数据库。

Linux 主机需要 `iptables`/匹配的 restore/save 工具、`ipset`、`conntrack` 命令以及网络管理权限，且所处网络命名空间的 `net.ipv4.ip_forward=1` 已由管理员配置。Agent 不自动修改主机 sysctl、外部链或默认策略。v3 使用 `FP_*` 专属链、`FPV2_*` 分类/计数集合与 `FPV3_*` 配额/账本集合，在 `0xf1` 高 8 位命名空间内以高 24 位存储持久化转发 token，掩码为 `0xffffff00`，保留低 8 位；发现链名、集合或标记冲突时拒绝接管。内核需支持 `hash:ip,port` 的 skbinfo/SET map-mark，以及 `hash:ip,mark` 的逐项计数。

编译：

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o flux-agent ./cmd/flux-agent
```

参考 `config.example.json`，真实配置权限设为 `600`。正式控制地址使用 `wss://` 或 `https://`；`allowInsecure` 仅用于隔离测试。`apply=true` 显式允许管理专属规则。

`packaging/flux-agent.service` 提供可选 systemd 单元。配置和状态路径固定后保持一个实例；不要用不同状态目录启动多个 Agent 接管同一套链。停止管理进程会保留规则，不等于停止业务转发。退回 GOST 时，先从面板暂停/删除对应转发，再关闭 Agent；两种引擎使用独立节点身份和不重叠端口；同机节点填写相同的 `serverIp`，面板据此进行保守的跨引擎端口预留。

## 独立验证

本地需要 Go 和 Docker。执行：

```sh
tests/run-local.sh nft
tests/run-local.sh legacy
go test -race ./...
```

验证器只允许本机 Unix socket Docker，使用一次性 MySQL、Java 面板、具备 NET_ADMIN/SYS_ADMIN 权限的测试容器内的 client/router/target 三个网络命名空间；Docker 网络为 `--internal`，数据流量只经过 `10.203.0.0/16` 的虚拟网线，不连接 qcloud 广州或任何外部转发入口。

另有 `tests/kernel-guards.py`，在相同权限但 `--network none` 的一次性容器验证外部集合、旧版链、标记冲突和零计数 NAT 状态丢失时的拒绝行为。

测试包含真实 TCP/UDP 往返、既有连接暂停、规则与账本恢复、目标变化、重复上报去重、三层账本、配额暂停和旧 GOST 二进制回归。退出时只删除本轮命名的测试容器和网络，证据默认保存到 `.test-work/`。旧 GOST 回归需要仓库中与 Docker 架构匹配的既有二进制。

可用 `FLUX_TEST_GOST=/absolute/path/to/verified/gost` 显式指定回归二进制，测试器复制到独立 build 目录，不覆盖仓库资产或生产服务。本批 ARM 验收使用发布包内经 WS/WSS 和初始上报验证的 GOST，不能沿用已知不兼容的旧 ARM 资产。测试主机也须具备实际内核扩展；本轮本机 Docker Desktop 缺少 `hash:ip,mark`，故改用原生 ARM Linux 测试 VM，未跳过预检。

## 统计与更新语义

计数来自 FORWARD 的网络层包字节，包含包头和重传，与 GOST 用户态读写字节不相同。面板继续应用原有倍率和单双向系数。只对入口记账；上报序号及累计水位保存在数据库，重发不会重复入账。

状态文件丢失而内核仍有本项目规则或计数时，Agent 拒绝重置账本并启动；需要先恢复原状态文件，避免把历史计数按新 epoch 再次入账。

删除前通过命令回执结算最后采样的数据。v3 用带校验和的事务日志与数据屏障协调跨表、集合和状态文件；提交前故障回到旧代，提交后完成新代，无法验证时保持关闭。新面板/Agent 协商严格额度策略后，通过中央事务预留、短期累计 credit 和内核双向共享预算限制离线/跨节点额度；不能与同用户的活动旧 GOST/旧 Agent 静默混用。异常掉电前未持久化的原始流量仍有明确丢失窗口，不能保证逐字节无损恢复。

v2 用 `FPV2_BIND` 哈希分类、connmark 恢复标记、固定深度 NAT 树分发首包；`FPV2_ALLOW` 判断放行，`FPV2_UP/DOWN` 做逐项网络层计数。暂停删除放行项并由 FORWARD DROP 覆盖本项目的既有连接；删除或变更目标时仅清理撤销转发的 conntrack 映射，大批处理用精确 token 前缀合并删除。未启用 flow offload。暂停/到期更新不重建 NAT/计数集合；旧目标与删除记录的计数保留以供最终结算。系统 CPU、内存、网卡速率监控尚未实现，页面显示为未提供，不将心跳占位值当作性能数据。


## v3 升级与回收边界

检测到 live `flux-owner:v1` 链时拒绝直接接管。使用已校验离线包与 `--maintenance` 执行最终结算、备份、停流、迁移和回滚；不能直接覆盖生产二进制。v3 维护模式兼容历史 v1/v2 状态，保持累计账本和 epoch；回滚后业务仍暂停，显式恢复后再放行。离线迁移保持关闭，直到面板确认结算与暂停。

单个 netns 最多 65,535 个转发 token。已删除条目须同时满足面板累计/计数 ACK、无 conntrack 引用、经过保留期，才可回收 token 与历史计数；迟到版本不能复活已删除记录。自动保留期 5 分钟，管理员回收至少 1 分钟。回收通过批量导出和恢复处理，只调整已删除计数的基线，不阻断其他活动流量。

内核计数的两个方向仍非同一瞬间快照。节点重启/内核账本变化保守隔离旧额度；运行中计数回退或丢失会关闭数据并持久化错误状态。详细语义见 [v3 说明](../doc/forward-foundation-v3.md)。

本轮优化、同拓扑 GOST/v1/v2 对照见 [v2 性能报告](../doc/forward-performance-v2.md)；域名、IPv6 与完整待办方案见 [实施路线](../doc/forward-engine-roadmap.md)。


第一批基础能力与升级/计费/安装语义见 [v3 说明](../doc/forward-foundation-v3.md)。发布包须固定校验和；生产启用仍需独立部署计划。
