# qcloud 统一 Agent 迁移验收

后续已更新 Agent 和面板以修复诊断并精简界面，当前二进制及验证见 [诊断修复记录](diagnostics-repair-20261102.md)。

后续状态：qhix 也已完成迁移并实际使用原生 nftables，见 [qhix 上线记录](qhix-agent-migration-20261102.md)。本文及配套 JSON 保留 qcloud 迁移当时的观测，涉及“qhix 未迁移”的描述仅指当时。

**最新状态：qcloud（逻辑节点 ID 2）已切到统一 Agent / 原生 nftables，实际 `forwardingMode=kernel`。** 最初先迁入受管 GOST，随后按用户明确要求完成原生模式切换。qhix 没有迁移、没有对其执行 SSH 或服务配置变更，仍以旧 GOST 在线；需用户确认 qcloud 后再处理。

## 业务与状态

- 原 IP、50050/50051/50052 的 TCP/UDP 入口、原目标及业务规则 ID 36/37/39 保留。
- 成功轮次入口暂停约 **36.0 秒**，恢复时间为 2026-11-02 14:41:57 +0800。这是入口保护规则的时间，不是所有客户端完成重连的时间。
- 三条规则均已启用，受管 GOST 有六个转发服务。自然业务在 50050/50051 恢复双向字节增长；被动观察同时出现 TCP 和已有回复的 UDP conntrack 记录。没有生成 GZ 测速、压测或业务探测流量；闲置端口不冒充已做业务回声验证。
- `flux-agent.service` 和 `flux-kernel.service` 已启用，检查时 PID 分别为 83772 / 83771，成功启动后均无重启。
- 网络 Agent 零 capabilities；helper 保持 NET_ADMIN/NET_RAW/NET_BIND_SERVICE，没有长期 SYS_ADMIN 或 SETUID。
- 原 `gost.service` 已停止并禁用；原二进制、配置和 device.id 未改写，备份保留。
- 历史账本没有重置，也没有导入旧快照覆盖新计数。新流量使用新 Agent 的网络字节口径；Agent 新 epoch 从零记录新增量，未把历史总量重新上报计费。

## 兼容问题与实际回滚

qcloud 的 nft 1.0.6 在 JSON 中省略表级 comment，原生文本仍保留。主分支 `4e3cfe3` 增加严格的表级归属标记恢复：只补齐项目表缺失的 comment，不覆盖明确的 JSON 标记，也不把链或规则里的 comment 当成表归属。Agent race 测试通过，实际 qcloud 内核的独立网络命名空间复验 **18/18** 通过；业务老 GOST 在该隔离测试期间保持原 PID。

第一次正式切换因操作脚本受 umask 影响，将公开程序目录建成 0700，普通用户无法读取 GOST，按预案约 70 秒内回滚。该轮没有生成有效新 Agent 状态，历史账本未回退。已将程序目录修正为 root 所有、0755；密钥配置保持 0600，并在真实 systemd 缩权配置下确认普通用户能启动空服务的受管 GOST，随后第二次切换成功。没有通过放宽服务 capabilities 或关闭保护设置解决问题。

## 控制面与保护措施

Oracle 配套更新面板前后端为 `cfabd1f` 构建，并显式应用增量 007；保留同一数据库、JWT、节点密钥和访问入口。先以只读临时实例验证 2 个节点、20 条转发，再仅替换面板两个服务。其余 6 个 Oracle 服务的进程 PID 均保持不变；qhix 节点的关键配置前后相同，恢复为在线状态。

切换时只保护三个业务入口，临时阻止新流量在空窗期生成旧 conntrack 映射，定向清理这些服务的旧映射；未清空主机整个连接表。临时入口保护表和临时本地端口保留设置均已撤除/恢复。独立超时回滚定时器在成功提交后取消。

root 私有备份：qcloud `/root/flux-agent-migration-20261102/`；Oracle `/app/flux-agent-qcloud-migration/20261102/`。包括旧 GOST、配置、原 Compose、数据库备份及操作记录。提交后的私有回滚脚本会拒绝自动回退；后续若需回滚，必须先核对有没有新增规则或策略，保留最新账本，不能直接恢复整库旧快照。

[机器记录](qcloud-agent-migration-20261102.json)。其中 conntrack 条目数不等同于活跃应用连接数。所有密钥、完整数据库和私有运行配置均不写入本报告。

## 后续原生 nftables 切换

2026-11-02T15:00:39.726000+08:00，通过面板模式切换 API 将 qcloud 从 `gost` 切到 `kernel`，任务成功。面板、Agent 实时状态和持久化 checkpoint 三处一致。原 `kernelBackend=nftables` 只是共用内核规则后端，不等于业务执行模式；此次才实际启用原生转发。

- 原三条规则全部启用，epoch 未变，累计流量不倒退。
- 受管 GOST 的业务服务列表已清空，进程仅待命；内核 DNAT map 直接指向原远端三组目标，不再转到本机 GOST 后端端口。
- 被动观察到新的原生标记 TCP/UDP 连接，UDP 有 ASSURED 记录；50050/50051 的双向字节持续增长。50052 仍闲置，没有声称对它生成业务探测。
- 未重启节点服务、未改变 IP/入口/目标，未生成 GZ 测速或压测流量。qhix 保持旧 GOST 在线，未执行迁移。
