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
