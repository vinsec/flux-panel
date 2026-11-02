# 统一节点 Agent（v7，原生 nftables / 受管 GOST）

统一 Agent 支持同一节点在原生 nftables 和受管 GOST 之间切换，允许短暂中断；旧独立 GOST 节点继续兼容。
控制协议值保持 `kernel`，执行方式使用 `forwardingMode=kernel|gost`，不提供 iptables 后端或自动回退。
使用步骤、支持范围和格式 8 回滚边界见 [统一 Agent 切换说明](../doc/unified-agent-switching.md)。

当前支持域名、双栈、多目标、出口路由、共享平滑限速、本地路径、源地址保留、缩权 helper，
以及有界 HTTP/TLS/SOCKS 识别。未知流量放行并标记 UNKNOWN。
暂停、配额和网络层计数仍由内核规则执行；控制通信保留 WSS、累计上报、中央 credit、事务日志与恢复语义。

完整移除范围、迁移、回滚和测试见 [原生后端收敛说明](../doc/native-only.md)。
先前两种后端的性能报告是历史对照，不是当前可选模式列表。

## 安装与兼容边界

- 面板升级前显式应用尚未执行的 `database/migrations/001` 至 `007` 迁移；不自动修改线上数据库。
- Linux 需要 `nftables`、`conntrack`、`iproute2` 及相应内核能力。原生模式不依赖 iptables/ipset 可执行文件。
- 主机转发开关、回程和外部防火墙需要事先配置；Agent 不修改宿主 sysctl 或全局防火墙默认策略。
- `kernelBackend` 可省略或为 `nftables`。`iptables` 后端和旧 `iptables` 二进制选项明确拒绝。
- 已有原生 nftables 的 format 6/7 状态继续使用同一 epoch、计数身份和账本；不原地把旧 iptables 状态改成原生。
- 旧 iptables 状态/备份须由以前的发布版结算和导出，再按独立迁移方案处理。新二进制拒绝接管它们。
- 只读审计会检查机器上已安装的外部 xtables 工具；工具不存在不阻止原生模式启动。外部规则不会被本项目删除。
- 一套网络命名空间只允许一个内核 Agent；保留跨版本互斥锁的历史名称，不能同时启动新旧版本。

编译：

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o flux-agent ./cmd/flux-agent
```

参考 `config.example.json`；真实配置权限应为 600。正式面板地址使用 WSS/HTTPS；
`allowInsecure` 仅用于隔离测试。离线安装器使用 `--engine kernel` 或 `--engine gost`，并固定校验发布包。
安装、升级、维护和卸载可能暂停业务，需另行安排发布窗口；qcloud 已按单独批准的窗口完成统一 Agent 灰度并切到原生 nftables，qhix 未迁移，见 [上线记录](../doc/qcloud-agent-migration-20261102.md)。

## 验证

```sh
go test -race ./...
go vet ./...
tests/run-local.sh native
```

完整端到端脚本 `tests/integration.py` 可在本地 Docker 或 Fusion Linux 运行。Linux 必须有实际 IFB/BPF 等能力，
不能把 Docker Desktop 缺少驱动的结果当作功能通过。Fusion 的 `FLUX_TEST_DB_HOST` / `FLUX_TEST_DB_PORT`
只指向一次性测试 MySQL，业务数据保持在私有 veth 内；不能指向生产。

`tests/native-no-xtables.py` 用不包含任何 iptables/ipset 的 PATH 验证转发、暂停、恢复、重启和结算卸载。
`tests/install-package.py` 验证固定哈希、离线安装、幂等及激活失败回滚，使用私有 /run 和假 systemctl。
`tests/benchmark/native-only-regression.py` 用相同协议屏蔽比较冻结原生 v5.5 与当前版本，记录实际进程哈希、CPU、延迟及收包回执。

历史设计与边界参见 [原生 map 后端](../doc/forward-native-nft.md)、
[协议识别](../doc/forward-protocol-blocking.md)、[先前 v5.5 验证](../doc/forward-performance-v55-validation.md)。
