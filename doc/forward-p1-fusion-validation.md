# Fusion 本地 Linux 补充验收

用户选择本地 VMware Fusion 作为第 20 项的后续验证环境。本文补充先前的隔离验收，不把虚拟机硬停止等同于拔掉物理宿主机电源。

## 镜像、网络和资源

- VMware Fusion 25.0.0，Apple Silicon / arm64；新建 `Flux P1 · Debian 13 Minimal`，4 vCPU、4096 MiB、32 GiB 稀疏磁盘，初始系统实际使用约 1.1 GiB。既有 Windows VM 未恢复或修改。
- Debian 官方 generic arm64 云镜像，固定 `20261021-2638`；下载 300023540 字节（286 MiB），与官方 HTTPS SHA512SUMS 匹配。generic 使用标准内核；本次为 `6.12.113+deb13-arm64`。
- 新增 ipset/conntrack/nftables/iperf3/open-vm-tools/linux-perf/sysstat/binutils 及依赖实际下载 **22752340 字节（21.7 MiB）**。最终改为二进制仓库索引；早期默认镜像的 Sources 索引请求已移除。不安装桌面、Java 或 Docker。
- 镜像和包下载的宿主出站 socket 均绑定物理 `en9`，真实 DNS 和 TLS 校验保持；未使用或切换 Shadowrocket/US/GZ 节点。镜像直连有重试，额外流量属于本地宽带，非代理额度。
- VM 只接 host-only 管理网，路由只有管理子网和宿主地址，**没有公网默认路由**。临时 Debian 白名单下载中转在依赖装完后停止。业务测试在独立 net/mount namespace 的私有 veth 中。
- 宿主到 guest 的 SSH 返回 EHOSTUNREACH，未为此修改全局网络权限；使用 Fusion 官方认证 Guest Operations 管理。临时测试账号凭据只在工作目录的 0600 文件，不进源码/报告。

## 已完成检查

- Debian 13/Fusion 下 nft、legacy 各 43 项独立黑盒检查通过（不含该脚本可选的 3 项 helper-UID 专项）；涵盖双族 TCP/UDP、共享预算、DNS、PTB/分片、健康、权重、地址变更和共享限速。
- 九阶段应用进程崩溃及恢复套件 13 项通过。真实低权限网络进程/root helper 的系统服务另用于整机恢复检查。
- 宿主机上的独立测试协调器保存累计水位和额度预留，随后对指定测试 VM 执行 Fusion **hard stop**。guest 的客户端、目标、内核 conntrack/规则和服务一起消失，宿主协调器不重置。
- 恢复后 boot ID 改变而账本 epoch 保留；累计流量不小于最后外部确认的持久水位；旧 64 KiB 预留不向新 boot 重新发放；限额 TCP/UDP 仍关闭，无限额业务通过实际 systemd/helper 恢复。恢复信息明确标记潜在未落盘损失。
- 将 guest 墙钟回拨一小时，15 秒单调内核 credit 按原期限耗尽，未被墙钟调整延长。

## perf 采样与边界

10k 规则、150 Mbps、20 秒的实际接收速率约 149.965 Mbps，收齐 374996992 字节。使用 25 秒、99 Hz 的 `cpu-clock` 软件事件采集完整 guest 调用链；采样无丢失。完整数据含空闲线程与内核上下文；筛选 iperf3/flux-agent 的摘要只代表这些 comm，不能替代全 guest 内核成本。

`perf stat -e cycles,instructions -- true` **退出码为 0，但实际输出均是 `<not supported>`**。因此本环境没有可用的这些硬件 PMU 计数；不得只检查返回码便宣称可做物理 PMU 归因。软件事件可用于热点定位，物理专机 PMU/真正宿主掉电仍不在本报告的已测范围。

## 30 分钟稳态结果

同一冻结 Agent `51de4ee90db93f5a31c8ad1796c8ebe7b380cbf30290a9033c6698eb2611625d`，10k 高级规则、128 常驻连接，持续 1800.03 秒，86652 次内容校验交换、17331 次新连接，错误 0。期间 171 次配置变更、1583 次有效累计报告；配置统计周期 1 秒，实际报告频率受处理耗时影响。

Agent RSS 中位 149.4 MiB，峰值 221.9 MiB，暖窗口中位漂移 7.17 MiB；满足本次 384 MiB/32 MiB 的既定预算。测试后热业务暂停 1.37 秒，恢复成功，带 10k 状态温重启 4.19 秒，实际 TCP/UDP 继续可用。累计双向应用负载 1.067 GiB，低于 2 GiB 私有链路预算。

此长稳态的私有 `/tmp` 状态在 tmpfs 中，主要证明资源、并发和计数/配置行为；虚拟磁盘持久性由前面的实际服务硬断电案例在 ext4/VMDK 上单独验证，不能把 tmpfs 稳态等同于长期磁盘 fsync 压测。Mac 宿主仍可运行其他程序，本报告不是物理独占机器的基准。


## 重现材料

`node-agent/tests/fusion/` 包含受可丢弃 VM 定义保护的 Guest Operations 包装、宿主协调器、硬停止检查、命名空间运行器和软件 perf 脚本。稳态使用 `FLUX_P1_SOAK_SECONDS=1800 FLUX_P1_SOAK_BUDGET_BYTES=2147483648`；应用字节预算 2 GiB 完全在私有测试链路，不是外网流量额度。

官方来源：[Debian 镜像](https://cdimage.debian.org/images/cloud/trixie/20261021-2638/)、[Debian generic 与 genericcloud 内核区别](https://wiki.debian.org/Cloud/)、[Fusion Apple Silicon 兼容性](https://knowledge.broadcom.com/external/article/315602/compatibility-considerations-for-arm-gue.html)。
