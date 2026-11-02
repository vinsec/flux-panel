# Fusion 独立 Linux 验证

这些脚本仅用于用户明确创建的可丢弃 VMware Fusion Linux VM。硬停止只允许指定的 `FLUX_FUSION_VMX`，禁止把生产或其他用户的 VM 路径传入。

环境为 Apple Silicon、Fusion 25、官方 Debian 13 generic arm64。通用镜像的内核驱动比 genericcloud 完整，使用官方 SHA512SUMS 校验下载。仅分配 host-only 管理网络；**guest 无公网默认路由**。包安装可通过宿主机绑定物理接口的 Debian 白名单中转，测试中不使用 Shadowrocket/GZ 入口。中转不是业务数据路径。

## 管理及输入

`guestops.py` 使用 Fusion 官方 vmrun 的认证 Guest Operations，不依赖宿主到 VM 的 SSH。设置 `FLUX_FUSION_WORK` 和 `FLUX_FUSION_VMX`；工作目录的 `vm-definition.json` 必须显式声明 `disposable: true` 且路径相同，否则拒绝执行。工作目录的 `keys/guestops-password` 必须为仅本机用户可读的临时测试账号密码，不得提交到仓库。所有根操作只在此可丢弃 guest 内执行。

VM 输入放 `/opt/flux-p1/{build,tests,packaging,guest}`。`/tests`、`/build`、`/code` 分别指向输入测试、二进制和 benchmark 目录。`guest/run-isolated.sh` 为每次测试创建独立 mount/net namespace，私有 `/tmp` 和 `/run/netns`，把证据目录绑定到 `/evidence`；每次显式选择 nft/legacy，避免裸 guest 的 update-alternatives 跨套件残留。

## 故障与观测

- `host-panel.cjs WORK/host-controller` 是位于宿主机的测试协调器，持久化累计水位和额度预留，VM 硬停不会重置它。只绑定 host-only 地址；管理 API 仅允许宿主源地址。它不是产品后端。
- `guest/install-power-case.sh` 安装实际打包的低权限网络进程/root helper 服务，使用私有 p1client/p1target veth；仅对本次管理目录和测试服务有效。
- `power-host.py` 先验证时钟回拨不延长内核额度，然后 `vmrun stop ... hard`、重新启动 guest。检查 boot ID 改变、epoch/最后外部确认累计值保留、旧预留不被新 boot 重新获得、限额业务保持关闭及无限额业务恢复。串口每次启动使用新文件，避免覆盖日志的 GUI 提示。
- `guest/fusion-perf.py` 采集 10k 规则、150 Mbps 的 `cpu-clock` 软件事件。`perf stat` 即使退出码为 0，也可能输出 `<not supported>`；必须核查实际 cycles/instructions 计数，不能据返回码宣称硬件 PMU 可用。
- 完成 power case 后应先停用测试服务并维护卸载，才运行其他测试。保留根 VM 的管理链路；业务数据仅在新建的私有 namespace 内。

此验证是**虚拟机硬断电模拟**，不等于切断宿主机或物理磁盘供电。软件 perf 不等于物理独占 PMU 归因。结果要保留虚拟化、CPU 分配、真实采样间隔、主机负载与未落盘损失边界。

## 稳态参数

30 分钟验证使用 `FLUX_P1_SOAK_SECONDS=1800 FLUX_P1_SOAK_BUDGET_BYTES=2147483648`，上限是双向应用字节，不是外网流量额度；原默认仍是 600 秒/1 GiB。所有数据目标保持私有，不允许为了压测添加公网默认路由。

## P2 复用

`run-isolated.sh` 也接受 `p2-traffic`、`p2-faults`、`p2-regression`。前者设置 `FLUX_P2_HELPER=1` 可改用专用 UID 的无 capability 网络进程和受限 root helper；helper 也在持久状态恢复检查中重新启动。不同后端顺序运行，禁止同时更改同一 guest 的 alternatives。

性能输入除当前 `/build/flux-agent` 外，还需冻结 P1 的 `/build/flux-agent-p1`、当前 `/build/flux-agent-v2` 和 `/build/bench-peer`。`p2-regression` 使用 3/10k 规则、三轮交错顺序，1 GiB 严格接收确认的双向传输，以及默认 20 秒的 150 Mbps CPU 采样和 TCP/UDP 延迟。统计每秒上报，私有应用负载总上限 32 GiB。CPU 含端点和 guest 系统开销，不能当作独占物理 PMU 归因。镜像、依赖和编译器均可复用，不需额外下载。

针对吞吐/RTT 信号，可另跑 `p2-confirmation`：每个版本每种规模五轮交错，单轮三次 1 GiB 严格下载，常驻 TCP/UDP 各 5000 个 RTT 样本，统计周期一秒。单次确认的私有应用字节上限 64 GiB；与主测试分开保存，不混用不同窗口的结果。

若短促峰值与一秒采样周期相互影响，可使用 `p2-window`：每方向连续八次 1 GiB 接收确认组成窗口，覆盖采样工作；每版本每规模三轮交错，并采集 20 秒固定速率 CPU、5000 个常驻 TCP/UDP RTT。上限 256 GiB 私有应用负载，记录可达转发规则图与自有集合，固定二进制哈希。此模式不走公网；不要把单次峰值或共享 VM 的波动当作已经证明的改进。

## P2 本地整形与固定绑定 UDP

`p2-local-shaping`、`p2-udp-source`、`p2-shaping-faults` 和
`p2-local-no-bpf` 使用相同私有四网段；最后一项须设 `FLUX_P2_HELPER=1`。
前两项也可设该变量验证可选 helper 权限配置。新本地整形测试先在实际
Agent/helper 的 mount namespace 准备 bpffs tc/ip/xdp globals，并用只读 bind
mount 模拟受保护 /sys；网络进程零 capability，基础 helper 缺少权限时验证
新增限速意图失败关闭。只在明确可丢弃 VM 执行准备步骤。

`benchmark/p2-next-window.py` 对照冻结 v5 和当前 v5.1，分别放在
`/build/flux-agent-v5`、`/build/flux-agent-v51`；每次启动检查 /proc/PID/exe SHA。
3/10k、三轮交错、双向 8×1GiB 接收确认、20 秒 150Mbps 与 TCP/UDP 各 5000
常驻 RTT 均与第一批窗口一致，私有应用字节上限 256GiB。
`p2-local-profile.py` 另测本地到本地：旧 v5、不限速的新版本、200Mbps 共享
限速的新版本，在固定 150Mbps 负载下对照接收率、CPU1 与 2000 次 TCP/UDP
RTT；两轮反向顺序，应用字节上限 4GiB。此负载用于量化新队列的成本，不能
与“不启用能力的基线零额外规则”混成一个性能结论。

小规模 CPU 信号可用 `benchmark/p2-next-cpu-confirmation.py` 单独确认：3 条规则，
三轮交错、40秒 150Mbps、每轮清除 TCP metrics。与主窗口分开保存，实际运行
二进制仍逐次校验。`p2-local-combinations.py` 额外验证出口/源地址、本地整形、
UDP 连续流和双栈真实 PMTU。
