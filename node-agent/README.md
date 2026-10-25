# 独立 iptables Agent（实验版 v1）

本模块不依赖或启动 GOST。管理通信使用面板的 WSS 协议，业务数据在 Linux 内核完成 IPv4 TCP/UDP DNAT/SNAT。

## 首版范围

- 隧道和节点选择 `iptables`；旧记录迁移后默认为 `gost`。
- 单目标数字 IPv4 地址、TCP/UDP 同端口，新增/更新/暂停/恢复/删除。
- 原始网络层双向计数、持久化累计值、面板事务去重与三层账本。
- 本地保存配置和计数基线；Agent 重启不清空现有账本；到期时可在失联期间阻断转发。
- 不支持 IPv6、域名、多目标、指定出口网卡、应用协议屏蔽、GOST relay 中继和平滑带宽限速；这些请求明确拒绝。

## 安装前置条件

仅在隔离验证通过并检查目标机防火墙后部署。面板必须先显式执行 `springboot-backend/migrations/001-forward-engines.sql`；脚本可重复执行，不在启动时自动迁移生产数据库。

Linux 主机需要 `iptables`/匹配的 restore/save 工具、`conntrack` 命令以及网络管理权限，且所处网络命名空间的 `net.ipv4.ip_forward=1` 已由管理员配置。Agent 不自动修改主机 sysctl、外部链或默认策略。首版使用 `FP_*` 专属链和连接标记命名空间 `0xf1000000/0xff000000`；发现链名或标记冲突时拒绝接管。

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

测试包含真实 TCP/UDP 往返、既有连接暂停、规则与账本恢复、目标变化、重复上报去重、三层账本、配额暂停和旧 GOST 二进制回归。退出时只删除本轮命名的测试容器和网络，证据默认保存到 `.test-work/`。旧 GOST 回归需要仓库中与 Docker 架构匹配的既有二进制。

## 统计与更新语义

计数来自 FORWARD 的网络层包字节，包含包头和重传，与 GOST 用户态读写字节不相同。面板继续应用原有倍率和单双向系数。只对入口记账；上报序号及累计水位保存在数据库，重发不会重复入账。

状态文件丢失而内核仍有本项目规则或计数时，Agent 拒绝重置账本并启动；需要先恢复原状态文件，避免把历史计数按新 epoch 再次入账。

删除前通过命令回执结算最后采样的数据。跨表规则更新并非全局原子，按专属规则快照回退；规则替换期间的计数采样窗口和异常断电前未落盘区间不能保证逐字节零误差。共享用户额度依赖面板采样后下发暂停，失联期间不提供跨节点的精确硬配额。

暂停使用 FORWARD DROP，能覆盖本项目的既有连接；删除或变更目标时仅清理该转发原始元组的 conntrack 映射。首版未启用 flow offload。系统 CPU、内存、网卡速率监控尚未实现，页面显示为未提供，不将心跳占位值当作性能数据。
