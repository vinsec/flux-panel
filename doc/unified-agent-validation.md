# 统一 Agent 切换验收（2026-11-02）

仅本地 main；未发布、未部署，未连接 Oracle/qcloud/qhix，未使用 GZ 入口。基线为 `baseline/pre-unified-agent-20261102`（ccec0d5）。最终 Agent、面板、GOST 的 SHA256、原始证据位置和逐项结果见 [JSON](unified-agent-validation.json)。

## 功能结果

| 组别 | 通过 | 内容 |
|---|---:|---|
| managed-switch | 20/20 | TCP/UDP 往返、共享账本/配额、151 字节精确计数、三处崩溃、失败回滚、不兼容策略提前拒绝 |
| managed-switch-unprivileged | 18/18 | 真实 helper/普通用户拆分、零 capabilities 的网络进程和 GOST、worker 强杀恢复、GOST 模式 helper 先启动 |
| managed-protocol | 29/29 | HTTP/TLS/SOCKS、UNKNOWN 放行标记、分片、IPv6、模拟云 NAT、本机路径、配额、精确所有权清理 |
| install-package | 12/12 | 固定清单/伴随 GOST 校验、重复安装、卸载、升级、模拟服务激活失败与旧格式账本回滚 |
| managed-shaping | 8/8 | 缺少准备时拒绝切换/新增限速，准备后单规则 8 Mbps、改为共享用户上限、两规则共享、切回原生 |
| Go 面板/MySQL/节点端到端 | 88/88 | 实际按钮对应 API、节点身份、累计账单、旧 GOST TCP/TLS/WSS 隧道、共享余额、DNS、IPv6、限速、10k 协调、断网额度过期 |
| 新 GOST 独立兼容 | WS/WSS 均通过 | 当前 ARM64 二进制的 WebSocket 注册和初始配置上报，测试 CA/loopback |
| 构建后的浏览器界面 | 两次往返通过 | 中断提示、同一任务轮询、成功后再打开切回；API 在浏览器测试中模拟，真实 API 另由上一组覆盖 |

Agent race/vet、Go 面板的真实专用 MySQL race/vet、前端 TypeScript/Vite 构建通过。Linux ARM64 实际运行；AMD64 为编译验证。安装组使用假的 systemctl，没有部署或控制真实生产服务。

## 限速实测

```json
[
  {
    "profile": "gost-single-8Mbps",
    "seconds": 1.2037083340001118
  },
  {
    "profile": "gost-shared-user-8Mbps",
    "seconds": 2.4429649180001434,
    "individualSeconds": [
      2.1446804590000283,
      2.424995501000012
    ]
  }
]
```

切换会使既有 TCP/UDP 连接中断，不是无损迁移。缺少本机限速准备时不会报告假成功；不支持的源地址保留/出口路由/主动健康检查提前拒绝。开启本机平滑限速需要独立准备环境，长期 helper 仍不持有 SYS_ADMIN。

## 原生模式性能回归

最终同一 Agent 二进制，3/10000 规则分别执行 baseline → candidate → candidate → baseline，HTTP/TLS/SOCKS 屏蔽、统计与正常控制周期均开启。控制器、Agent、目标、客户端分别绑定 VM CPU0/1/2/3。每轮 5 秒预热、20 秒固定 150 Mbps、长连接/新连接/UDP 延迟、20,000 次串行新连接回声；所有回声样本无丢失。

| 规则 | 版本 | 接收 Mbps | Agent CPU% | 串行新连接/秒 | 无间隔新连接 p95 μs | 1ms 间隔新连接 p95 μs |
|---:|---|---:|---:|---:|---:|---:|
| 3 | 改动前 | 150.01 | 0.82 | 4976 | 234.9 | 3086.3 |
| 3 | 统一 Agent 原生模式 | 150.00 | 0.77 | 5034 | 233.1 | 2500.5 |
| 10000 | 改动前 | 150.01 | 12.87 | 4593 | 243.4 | 1925.5 |
| 10000 | 统一 Agent 原生模式 | 150.01 | 12.49 | 4585 | 244.1 | 1842.5 |

两组每轮的原生 nftables 规则程序哈希一致。性能组使用没有有限配额的种子规则，统计采样/控制轮询开启；额度租约和数据库/跨节点预留负载在功能组另行覆盖。工具沿用 `flux-agent-v55-baseline` 文件名，实际内容是由 ccec0d5 标签归档源码构建的基准，按 SHA256 校验。此表是小样本局部回归，固定速率不是最大吞吐，串行 CPS 包含端点和虚拟机调度开销。Agent 进程 CPU 不包含全部内核开销，也不包含 GOST 子进程；原始记录还保留测试核和 cgroup 的混合 CPU 观察，不能当作转发器独占 CPU。延迟存在 VM 调度波动，不作所有负载下无退化或公网性能提升的承诺。

早期共享 CPU、修复管理监听前的中间产物实验保留在本地证据目录，没有混入上表。最终源代码增加了限速前置检查、共享 HTB 叶类迁移和 helper/worker 启动顺序保护后，以上功能与性能组均重新执行。

## 上线边界

现有独立 GOST 节点仍须单独升级为统一 Agent；没有自动转换线上节点。先显式应用 007 迁移，再安排升级灰度。旧 Go/Java 面板不认识 kernel-v7 的 credit 预留版本，已经切换的格式 8 账本也不能交给旧 Agent：快速回退使用本版本面板/Agent 切回先前已验证的模式，旧栈回退需另行结算迁移。详见 [实现与操作边界](unified-agent-switching.md)。
