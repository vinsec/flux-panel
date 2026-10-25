# 隔离内网性能对照工具

比较当前 GOST 二进制与 iptables Agent，不修改引擎代码。使用同一 Linux 容器内 client/router/target 三个 netns、MTU 1500、相同端点和 CPU 资源限制。容器必须为 `--network none`，root/controller 和 router 都断言没有外部默认路由；不得把公开节点或 qcloud 广州入口设为测试目标。

## 设备与前置条件

在有至少两个逻辑 CPU 的隔离 Linux Docker 测试机上操作。控制器绑 CPU 0，流量端点和转发器绑 CPU 1；整个容器限制 0.75 核、512 MiB、低 CPU 权重和 nice 19。测试机若与生产服务共享 CPU，结果需注明后台噪声，不能当作独占机器容量。

准备 `$FLUX_BENCH_ROOT/build/` 中的 `flux-agent`、`gost`、`bench-peer` 三个 Linux 本机架构二进制。前两个必须记录版本/哈希。辅助端点编译：

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bench-peer ./tests/benchmark/peer.go
```

将 `benchmark.py` 和 `run.sh` 放在 `$FLUX_BENCH_ROOT/code/`。构建测试镜像：

```sh
docker build --build-arg BASE=flux-iptables-test:local -t flux-forward-benchmark:local tests/benchmark
```

`BASE` 需要已有功能验证镜像提供 iproute2、iptables、conntrack、Python 等工具；性能镜像另装 iperf3 和 ethtool。启动不需要生产面板、数据库或真实密钥。控制端只在虚拟网络里接收统计和维持 WebSocket，GOST/Agent 的业务流量统计均开启，周期 5 秒。

## 可信 TCP 主测试

```sh
FLUX_BENCH_ROOT=/root/flux-forward-benchmark-20261025 \
FLUX_BENCH_EVIDENCE=/root/flux-forward-benchmark-20261025/strict \
FLUX_BENCH_STRICT=1 code/run.sh
```

运行路径以实际保存的 `run.sh` 为准。`FLUX_BENCH_STRICT=1` 使用 `peer.go` 的定长传输协议：所有上游连接就绪后开始计时，接收端收齐指定字节并返回回执，下载方向还校验客户端收齐回执。TCP 结果只在严格收发字节一致后有效，默认每轮 64 MiB；含单流上传、单流下载、四流上传。

基础组有两条 TCP/UDP 转发，规模组为 100/1000 条。热服务默认按 service ID 排序位于末端；`FLUX_BENCH_HOT_FIRST=1` 可以前置，用于诊断链扫描成本。

基础组按三种顺序交错运行，避免总让某个引擎先跑。规模组补齐三轮可使用 `FLUX_BENCH_SCALE_ONLY=1`（补 round 2/3），同时设置 `FLUX_BENCH_STRICT=1`。前置诊断可使用 `FLUX_BENCH_FIRST_ONLY=1`、`FLUX_BENCH_HOT_FIRST=1` 和较小的 `FLUX_BENCH_STRICT_BYTES`，该诊断结果不与 64 MiB 三轮主表混算。

## UDP、延迟与计数校准

不设置 STRICT/EXTRA/SCALE_ONLY/FIRST_ONLY 时运行原始探索矩阵：iperf3 TCP、两档固定速率 UDP，以及三轮应用回声延迟。延迟分别测长连接 TCP、新连接首个应用响应和 UDP；不把 GOST 的第一跳 TCP 握手当作端到端应用延迟。

2026-10-25 的短流探索中，iperf3 固定字节 TCP 的发送与接收最终统计最多差约 17%，所以该部分不用于最终吞吐主表；UDP 和独立回声延迟按其各自定义分析。正式 TCP 主表改用接收端回执工具。

`FLUX_BENCH_EXTRA=1` 运行热服务前置诊断和两轮 150 Mbps 同速率 TCP 对照；这些是辅助证据。64 MiB 主测试只能称为短传输吞吐，不能宣称长时持续公网速率。

## CPU 与预算解释

同时记录：

- 转发器进程 CPU、RSS：不包括全部内核成本，不能据此把 iptables 说成 0 CPU。
- cgroup CPU 核秒/GiB：包含本轮端点与控制器等测试进程，是整组固定工作的成本，不是转发器独占成本。
- CPU 1 的 user/nice/system/irq/softirq 与 steal：能观察 cgroup 外内核工作，也混入同机其他负载，附每轮空闲窗口供判断噪声。
- cgroup throttling：说明资源限额对结果的影响。

GOST 含原版本系统监控，新 Agent 未提供同样的系统监控，CPU 比较包含现有管理实现差异。需要专门归因时应增加独占环境和 perf 采样。

每个子测试有超时，单轮脚本有总时长上限，默认累计应用负载预算 3 GiB。多阶段时把已发送总量传给 `FLUX_BENCH_PRIOR_BYTES`；校准后可显式设置 `FLUX_BENCH_BYTE_LIMIT`，不要无记录地重置累计预算。2026-10-25 完整校准累计约 4.982 GiB，显式预算 5 GiB，全部经 veth，无公网路由。

输出包含逐轮原始 JSON、延迟样本、二进制哈希与元数据；只清理本次命名的临时容器。不要为了改进数字而临时关闭统计、暂停控制，或修改被测引擎代码。
