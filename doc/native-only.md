# 内核转发收敛为原生 nftables（v6）

本次只在本地实现与隔离验证，未部署、同步或修改线上机器，也未使用 GZ 入口。
保留的历史基线标签是 `baseline/dual-kernel-20261101`（`3c3681f`）。
GOST 继续保留；内核转发只保留原生 nftables，不再有 iptables 后端或运行时回退。

## 实际删除和保留的内容

删除了基础与高级 xtables 规则编译/restore、NAT 分发树、ipset 初始化/更新/采样、旧 credit 集合、
旧控制链及旧后端维护清理路径。原 `IPTables` 封装改为 `NativeKernel`，只调用原生 nft map、
命名 counter、共享 quota 和现有辅助路由/整形逻辑。`Render` 只编码业务规格，不再生成 xtables 文本。

现有 nftables 的命名计数、NETLINK 采样、mark/token 分配、暂停与额度、WSS、累计上报、
事务日志、DNS/IPv6/多目标、路由、本地转发、源地址保留、平滑限速和缩权 helper 均保留。
HTTP/TLS/SOCKS 有界识别及 UNKNOWN 放行策略不变。未修改专用 GOST 的源码或二进制。

剩余的 `iptables` 字符串有明确用途，不构成一个可运行的旧转发后端：

- 识别并拒绝旧后端配置、checkpoint 和备份。
- 接受旧版**原生 nftables Agent** 的 `engine=iptables` 控制协议别名，并归一为 `kernel`。
- 跨版本命名空间锁、持久化 counter 身份保留历史名称，避免破坏账本或让新旧进程同时接管。
- 只读审计已安装的外部 xtables 防火墙，检测 mark、NOTRACK、旧 Flux 规则等冲突；工具缺失时仍可运行原生模式。
- 历史迁移、测试对照和文档。系统已有防火墙仍由原工具管理，本次不卸载系统软件或清理外部规则。

## 面板和安装合同

面板现在只提供 **GOST / 内核转发**。新节点默认内核转发，使用原生 nftables；
删除管理员表单的后端下拉框，隧道继承入口节点。规则页面和 API 判断同步使用 `engine=kernel`。
`KernelForwardingEngine` 替代原 Java 适配器类名，协调、额度、统计等数据库查询也同步更改。

新建内核节点 `kernelBackend` 省略或为 `nftables`；传入 `iptables` 会报错。
旧 `engine=iptables` 请求仅为协议别名，不允许通过它选回旧实现。
数据库保留 `kernel_backend` 作为已部署后端身份，核对 Agent 真实声明；它不再是用户可选模式。
旧 iptables 节点在列表标记需迁移，编辑、安装、建立新会话和规则接管均拒绝，不通过改字段冒充原生节点。

Agent 控制身份与能力版本为 `kernel-v6.0`，旧原生 v5.x 的报文合同保持兼容。
安装器只接受 `--engine kernel` / `--engine gost`。发布清单仅列出 `kernelBackends=[nftables]`，
安装依赖中不再安装 iptables/ipset；仍需要 nftables、conntrack、iproute2 和常规系统工具。

一个新配置可省略 `kernelBackend`，但任何已存在的旧状态都要明确标识为 nftables。
旧状态/备份拒绝路径在内核修改前检查；不会因为省略字段就把旧 iptables 账本接到新规则上。
已有原生 format 6/7、epoch 和计数身份不变，不强制生成新 epoch。

## 数据库升级

这是未来发布步骤，本次未对线上执行：

1. 保存旧面板和 Agent 原生产物、配置、数据库备份，停止旧控制面的写入与任务。
2. 显式执行此前未执行的 001–004，再执行 `springboot-backend/migrations/005-native-only.sql`。
3. 005 将节点/隧道的历史引擎名 `iptables` 改为 `kernel`，**保留原后端身份**；
   不改账本、累计水位、revision、credit、用户额度或 Agent 本地状态。
4. 启动相匹配的新版面板/Agent，核对原生能力、身份、账本水位和实际业务后再开放管理变更。

旧 iptables 节点仍需用原发布版先结算、停流和导出，再按独立方案迁往新建原生节点。
不自动迁移活动连接、不删除历史流量；用户允许按时点镜像的迁移策略仍需另行安排。
宿主机必须满足实际内核能力、转发开关和回程/防火墙条件，不能据 VM 测试推定所有生产机器都满足。

## 代码回滚

回到双后端基线时，要在控制面停止写入期间显式执行 `005-native-only-rollback.sql`，恢复旧引擎名；
它保留最新账本和实际后端身份。然后恢复配套的旧 Java/原生 Agent 与原生配置，核对会话和水位。
不拿旧数据库备份覆盖新账单，不把“回滚版本”理解为把原生状态切到 iptables。
原生格式继续是 6/7；需要处理真正旧 iptables 状态时使用其对应旧发布版。

离线安装验证使用真实冻结原生 v5.5、假 systemctl 和私有 `/run`，检查激活失败时恢复原二进制、
保留 epoch/新增累计值、保持业务暂停，以及再次升级。该沙箱不会调用宿主或 guest 的真实服务管理器。

## 隔离验证方法

真实 Java 21 面板和 Agent 在 Fusion Debian 13 ARM64 / Linux 6.12.113 的私有网络命名空间运行。
一次性 MySQL 位于 Docker `--internal` 网络；仅通过绑定 host-only 地址且限制测试 VM 来源的临时中转访问。
测试 VM 没有公网默认路由，所有业务负载只经过私有 veth/回环。
Java/Python 运行依赖从已有本机缓存镜像复制，没有经代理下载依赖或镜像。

Docker Desktop 缺少 IFB，未在该内核上跳过整形用例冒充完整通过；完整端到端改在上述 Linux VM 验证。
这不是物理 PMU、物理磁盘掉电或公网/真实 NIC 吞吐验收。

验证入口：

- `go test -race ./...`、`go vet ./...`；实际 Linux 单元测试另在 VM 运行。
- Maven 离线 test/package，并设置 `FLUX_TEST_DB=1` 对一次性数据库跑完整 Spring 上下文测试。
- 前端 TypeScript/Vite 构建。
- `tests/node_backend_integration.py`：正反迁移、非零账本、新旧原生身份、拒绝旧后端、安装配置及隧道继承。
- `tests/integration.py`：真实 Java/MySQL/Agent/GOST，包含 1 万规则协调、三层账本、跨节点共享额度和离线恢复。
- 原生 map 生命周期/GC、协议识别、P1/P2、维护故障恢复及权限隔离矩阵。
- `tests/native-no-xtables.py`：没有任何 iptables/ipset 工具的 PATH 中运行原生生命周期。
- `tests/install-package.py`：固定哈希离线安装、幂等、实际转发、卸载与激活失败回滚。
- `tests/benchmark/native-only-regression.py`：冻结原生 v5.5 与候选版同开协议屏蔽、3/10000 规则、三轮交错性能对照。

最终计数、构建标识、性能和证据见 [验证报告](native-only-validation.md)。
