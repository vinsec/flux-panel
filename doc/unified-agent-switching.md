# 同一节点切换转发模式

main 上实现。2026-11-02 已完成 qcloud 的受管 GOST 灰度，qhix 尚未迁移；见 [上线记录](qcloud-agent-migration-20261102.md)。未执行 GZ 业务测速或压测。初版实现基线标签为 `baseline/pre-unified-agent-20261102`（ccec0d5）。

## 使用方式与边界

管理员在节点卡片选择“切换转发模式”，选择原生 nftables 或受管 GOST，再点击“暂停并切换”。新建统一 Agent 节点也可以指定初始模式，默认原生 nftables；隧道和转发规则继承节点模式，不各自启动独立引擎。

这是整个节点的执行模式切换。切换会中断现有 TCP/UDP 会话，客户端需要重连；不做连接排空，不承诺无损或固定毫秒数的停机时间。不能同时向两套引擎发流量。节点 ID、secret、业务规则 ID、账本 epoch、累计流量、配额授权不因切换而重建。

旧独立 GOST 节点仍然可管理，但需要先按单独的迁移步骤升级成统一 Agent，才能使用这个按钮。普通模式切换不会自动改写旧节点 engine；qcloud 的一次性旧节点转换已在单独批准的灰度中完成。原有 GOST TCP/TLS/WSS 隧道兼容路径保留；这不表示这些旧隧道已经能够在统一节点上原地转换。

## 进程和数据路径

- 对面板只有一个 Go Agent 控制身份，数据库 `engine=kernel` 表示统一 Agent 协议；`forwarding_mode=kernel|gost` 表示当前业务执行方式。
- 网络 Agent 用普通用户运行，托管一个经过 SHA256 固定的 GOST 子进程。子进程只有本地 Unix API，不自行注册面板、不发旧式增量账单，也不自动加载旧 GOST 配置。
- 内核 helper 保持 NET_ADMIN、NET_RAW、NET_BIND_SERVICE；网络 Agent 和 GOST 均不需要 capabilities，不新增 SYS_ADMIN 或 SETUID。
- 原生模式沿用原生 nftables map 数据路径。GOST 模式将业务入口送到 GOST 的本地后端服务，再代理到原始目标。业务定义仍保留原始目标。
- 两种模式共用 nftables 的客户端侧网络字节计数、暂停、配额和限速。GOST 内部统计不参与账单，不会再叠加一次。它与旧独立 GOST 的应用字节口径不同。
- 后端地址/协议/端口由独立 nft 集合保护，不接受无业务 conntrack 标记的直接访问；不会将后端端口开放成免计费入口。

原生模式下也保留一个空服务、仅 Unix 管理接口的就绪 worker，会增加少量常驻内存；它不接业务、不独立记账。

GOST 是受 Agent 管理的独立子进程，并非把整个 GOST 库静态链接进同一个进程；它的启动、退出、健康检查、配置和恢复已经统一管理。子进程退出后会自动重启并重建服务，在恢复之前业务保持关闭。

## 切换事务

1. 校验目标能力、已有规则策略、后端端口和 worker 健康；不兼容时在停流前拒绝。
2. 面板保存任务 ID，节点保存 queued 状态；规则变更与节点切换使用同一个节点锁串行化。
3. 关闭转发入口，收集并持久化最终计数，清理旧业务连接跟踪。
4. 应用目标引擎，将原有配额状态映射到新的执行图，保存成功状态，之后才恢复入口。
5. 激活失败时恢复原模式并保留最新账本；恢复也失败则保持阻断并显示 blocked。

关闭弹窗不取消任务。通信超时后查询同一个任务，不凭超时判断成功。节点在提交前两个阶段崩溃会恢复原模式；成功状态持久化以后崩溃则恢复目标模式。节点保留最近一个任务回执；面板禁止未确认任务被后续任务覆盖。

**面板回滚也有版本边界**：旧 Go/Java 只识别到 kernel-v6 的 credit 预留协议，不能直接接管 v7 节点。快速回退应保留新面板/Agent，在同一节点切回先前验证的转发模式；旧栈回退需单独结算、迁移方案。

首次切换或首次以 GOST 模式启动后，账本使用格式 8。仅安装受管组件、仍未切换的原生节点继续保持格式 6/7。**切回原生模式并不将格式 8 降为旧格式**：模式回滚由本版本 Agent 完成；不能把已经切换的账本直接交给旧 Agent，不能手工降版本号。

## 当前受管 GOST 支持范围

支持普通 IPv4 旧格式规则，以及结构化 TCP/UDP、域名解析、IPv6、独立监听、多目标、暂停、配额、流量统计和公共协议过滤。HTTP/TLS/SOCKS 由统一分类器实现，未知流量放行并标记 UNKNOWN。

带平滑限速的 GOST 规则需要事先启用已有的本机限速准备配置：短时 BPF 准备服务、loopback MTU 和相应 lo 参数。长期 helper 仍不持有 SYS_ADMIN；没有这些条件时，在停流前拒绝切换，保留原模式，也拒绝在 GOST 模式新增此类限速规则。安装器不会擅自修改宿主 sysctl/MTU；运行环境准备属于单独的节点安装步骤。

以下策略在切到 GOST 前明确拒绝：原始源地址保留、内核指定出口/源地址/网关，以及主动目标健康检查。跨地址族、带 scope 的 IPv6 等原生层已经不支持的情况仍然不支持。不能把“可切换”理解成所有高级策略都能无差别映射到 GOST。

## 安装及回滚

必须先显式执行 `database/migrations/007-managed-agent.sql`，再升级面板和统一 Agent 包。迁移是增量操作，不修改旧节点的 engine 或历史账单。发布包新增 `gost-managed-linux-amd64/arm64`，安装器验证固定清单和二进制校验和；继续支持选配经过 WS/WSS 证明的旧独立 GOST 安装包。

生产配置由安装器写入 `/usr/local/lib/flux-agent/gost-managed` 和 `/run/flux-agent-gost/control.sock`。GOST 运行目录由普通用户服务拥有，目录 0750、Unix socket 0660，服务配置仅用户可读。GOST 以自己的运行目录作为工作目录，不依赖 helper 的 root 工作目录。

升级前保存原 Agent、受管 GOST、配置、systemd unit 和账本备份；安装失败恢复经过校验的旧文件。卸载只清理明确属于本节点的内核对象，拒绝删除同名但不具有本项目所有权标记的后端保护表。安装维护有意暂停规则，恢复业务应经过显式面板操作。

初版隔离验收验证了安装和模拟激活失败回滚；随后 qcloud 已完成实际 systemd 灰度、回滚和重试验证。其他节点仍须单独授权并准备备份后再迁移。

## 可重复验证入口

Go Agent：`cd node-agent && GOSUMDB=sum.golang.org go test -race ./... && go vet ./...`。
面板：使用专用可清空的 `FLUX_TEST_DSN`（测试库名），设置 `FLUX_TEST_SCHEMA_ROOT` 为仓库根目录，执行 `go test -race -count=1 ./...`；不要连接生产数据库。前端 `npm run build`。

Linux 测试在 Debian 13 ARM64 Fusion 虚拟机执行，只有 host-only 管理链路。每个案例分别创建私有 mount/net namespace，把测试脚本、实际二进制和证据目录只绑定到 `/tests`、`/build`、`/evidence`；`/tmp` 和 `/run` 使用私有 tmpfs。转发目标全部是私有 veth 地址，router 无外部默认路由。

- `node-agent/tests/managed-switch.py`：`/build/flux-agent` 和 `/build/gost`，切换、逐字节计数、暂停、有限配额、三个崩溃阶段、同进程失败回滚和不兼容策略拒绝。
- `managed-switch-unprivileged.py`：同一配置，真实拆分 helper/普通用户控制进程，验证两者 capability、worker 强杀恢复及切换。UID/GID 12345 仅用于这个一次性隔离测试。
- `managed-protocol.py`：GOST 初始模式，协议识别、未知标记、分片、IPv6、云 NAT 模拟、本机 OUTPUT、配额和维护清理。
- `managed-shaping.py`：缺少本机限速准备时切换前拒绝，准备后验证 GOST 单规则/共享用户的实际平滑限速和低权限 helper。
- `install-package.py`：固定清单安装、重复安装、卸载、旧格式账本升级和激活失败回滚；使用假的 systemctl，绝不控制宿主服务。
- `integration.py`：真实 Go 面板、专用 MySQL、Agent、旧 GOST；设置 `FLUX_TEST_MANAGED_GOST` 启用模式往返检查。扩展组包括 10k 规则协调、限速和旧 TCP/TLS/WSS 隧道。

结果和性能解释见 `unified-agent-validation.md` / `.json`。性能实验是虚拟机内的局部回归，不能证明公网性能，也不证明所有负载下绝无退化。

平滑限速在切换前检查本机准备条件；激活后若编译器将任何启用规则标记为不可用，切换会回滚。共享用户/隧道归属变化使用新的 HTB 叶类身份，避免对在用叶类直接改父级；仅修改速率则保留类身份。
