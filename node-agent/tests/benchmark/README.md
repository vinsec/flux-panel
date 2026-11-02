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


## v2 三方对照

新增优化 Agent 后，在 `build/` 中保留原 `flux-agent`（v1），另放 `flux-agent-v2`。测试镜像需包含 ipset。运行：

```sh
FLUX_BENCH_ROOT=/root/flux-forward-benchmark-v2-20261025 \
FLUX_BENCH_IMAGE=flux-ipset-v2-verifier:local \
FLUX_BENCH_V2=1 FLUX_BENCH_STRICT=1 \
FLUX_BENCH_BYTE_LIMIT=5368709120 code/run.sh
```

v2 矩阵：2/100/1000 条转发，GOST/v1/v2 按三种顺序交错，各三轮；TCP 使用 64 MiB 接收端回执。两条转发组另测下载和四流。延迟覆盖长连接；基础组另测新连接和 UDP。UDP iperf 与 TCP 定长端点在分开的配置阶段运行，避免协议混用。UDP 为 2/1000 条规则、50 Mbps×1200B 及 5 Mbps×64B。

`collection.json` 用每组十次原始导出测内核计数读取成本和输出量，v1 是一次 filter save，v2 是两次 ipset save；**不包含 Go 解析、fsync、HTTP 或数据库开销**，不能说成完整统计链路成本。也记录真实内核中的 mangle/filter/nat 规则数。

单独固定 150 Mbps、5 秒 TCP CPU 对照：`FLUX_BENCH_V2=1 FLUX_BENCH_PACED_ONLY=1`，不设 STRICT；2/1000 条规则各三轮。把前阶段 `metadata.json` 的 sent_payload_bytes 传给 PRIOR_BYTES，继续使用同一 5 GiB 总预算。吞吐主表与固定速率 CPU 表分开。5 秒传输覆盖至少一次正常 5 秒采样，保留其解析/持久化开销。

主矩阵总时长上限 900 秒，容器清理上限 960 秒，单案例 15 秒（定长传输 20 秒）。失败校准目录单独保留，已知发出负载计入后续预算；失败案例不混入有效三轮统计。
