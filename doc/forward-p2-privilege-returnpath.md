# P2 第三批：缩短特权生命周期与回程诊断

2026-10-28，Agent `iptables-v5.2`，沿用 schema 4 / state 5 / aux manifest 2。
此批只更新实现和隔离验证，不启用生产配置，不走 qcloud GZ 入口。

## 准备与长期运行分离

新增 `flux-agent --prepare-local-shaping`，在连接面板、读取 config 或启动 helper
之前独立执行。只从 Agent 内嵌的固定 BPF ELF 加载，不接受远程代码或路径。
stock tc/libbpf 的模块 BTF 枚举/程序加载仅发生在此短时步骤。

准备过程验证 bpffs、创建无地址/down 的自有加载设备，加载后取程序 FD、固定
程序并记录身份，最后清理加载设备并退出。记录位于 root:0700 的
`/run/flux-agent-bpf`，0600 记录绑定内嵌对象 SHA256、内核 boot ID、程序 ID/tag
及 prepared/ready 提交阶段。固定位置为 bpffs 私有目录，文件名由对象哈希生成。
已有正确程序可幂等复用；prepared 阶段只由准备器完成提交，helper 不接受未提交
记录。缺失、过期、身份不符和不安全的所有权/权限都失败关闭。

长期 helper 仅执行 BPF_OBJ_GET 和前缀程序信息读取，再通过 tc pinned 挂载；
不再枚举模块 BTF、按 ID 获取任意程序或加载 ELF。基础三项权限
CAP_NET_ADMIN / CAP_NET_RAW / CAP_NET_BIND_SERVICE 足够；SYS_ADMIN、BPF 均不保留。
网络进程继续保持零 capability。BPF 数据面字节码、共享 HTB/fq_codel、暂停、
配额及计数语义不变；没有为普通 P1 规则增加程序加载或 pin 查询。

## 可选 systemd 配置

仅在明确启用本地限速的节点操作。先按原说明准备并持久化主机 bpffs 挂载、
回环 MTU 与 sysctl；准备器不自动改变主机路由、MTU、sysctl 或外部策略。

1. 安装校验过的 `flux-local-shaping-prepare.service`。其 Type=oneshot，执行完毕
   MainPID=0；RemainAfterExit 仅保留单元状态，不保留特权进程。它的能力限于
   NET_ADMIN / BPF / SYS_ADMIN。短时单元允许写 bpffs；长期 helper 仍启用
   ProtectKernelTunables、ProtectSystem=strict 和准备目录只读保护。
2. **覆盖**旧 `flux-kernel.service.d/local-shaping.conf`。新文件显式清空并重设
   Bounding/Ambient 为基础三项权限，且 Requires/After 准备单元；不能把新内容
   简单追加到旧的 SYS_ADMIN 配置后保留旧赋权。
3. daemon-reload，重启准备单元和 helper/网络进程。检查真实 MainPID 的
   CapEff/CapPrm/CapBnd/CapAmb 不含 bit 21/39，不能只看 systemctl 的文本声明。
   Type=simple 刚 fork 时可能尚处 systemd 设置沙箱的阶段，应等 helper socket
   就绪、进程完成 exec 后再检查能力。
4. 准备单元每次主机启动重建易失 pin；升级到对象哈希不同的版本须重新运行
   准备单元后重启 helper。挂载命名空间中必须看到相同 pin/记录；挂载替换后需
   重启 helper 继承新挂载。缺失准备记录时本地限速关闭，不回退为不限速。

准备缓存按对象在物理机共享，不由某个逻辑节点的维护卸载自动删除；仍有节点
使用时不得取消固定。管理员先维护暂停/结算节点、确认没有活动过滤器使用后，可停止准备单元并
清理相应 pin/记录。运行中的 helper 会在下一次运行时检查发现缓存缺失并关闭
依赖规则；仅停止进程或取消固定本身不会撤销内核已持有的程序引用。旧 v5.1 的私有 ELF 缓存只按原所有权规则清理。

## 回程诊断契约

面板 `/forward/diagnose` 增加可选 `clientIP`、`ingressInterface`、`probe`。
内核引擎默认 `probe=false`，纯读取本机路由与 sysctl，不连接目标。
Agent `DiagnoseForward` 对应相同字段；新选项必须协商 returnPathDiagnostics。
旧节点仍可使用原有不带样本字段的诊断；GOST 诊断路径保持兼容。

- 最多列出 8 个不同目标，不再每个地址族只保留第一个。记录目标路由、配置的
  源地址/mark；给出客户端与入口后，另查带 from/iif 的转发路由线索。
- 提供 IPv4 rp_filter 的 all、接口、有效最大值，以及 src_valid_mark；查询到
  客户端的本机反向目的路由，提示严格模式接口不匹配或路由不可达风险。
  IPv6 明确标记不适用 IPv4 rp_filter；读不到的数据保留 unknown/null。
- 明确区分管理员 returnPathConfirmed、本机 FIB 证据、节点 TCP 握手和远端
  目标的真实返回路由。remoteReturnVerified 始终 false；不会自动修改确认或规则。
  本机 route get 不能证明远端回程，也未完整模拟 VRF/ECMP/全部策略条件。
- 用户显式选择 probe 时最多 2 次、单次 500ms TCP 握手，不发送业务载荷。
  只绑定配置接口/源地址，不携带业务 connmark，避免诊断消耗用户配额/计数；
  因此不把它称作指定 mark 网关或原客户端路径的连接验证。
- 整体约 4 秒预算、并发最多 2 个，容量满直接报 busy；不拿业务状态锁等待网络。
  UDP 不发猜测的探测包，仍需要明确请求/响应契约。

前端展示“路由已读取”与“TCP 连接”两种结果，显示采样入口的 rp_filter 风险、
未验证的远端回程及证据局限，不把只读检查渲染成连接成功。

验证入口包括 p2-local-preparation、p2-return-diagnostics、原双后端/helper矩阵、
实际 systemd 沙箱，以及与冻结 v5.1 的同机吞吐/CPU/延迟对照。结果见 [本批验证报告](forward-p2-privilege-validation.md)。

## 后续顺序

21 的长期 SYS_ADMIN 已移除；原始本机分片和额外 IPv6 回环组合仍不承诺。
22 的只读回程诊断已补齐；远端协作验证及通配 UDP/IP_PKTINFO 契约仍待实现。
接下来依次推进 27 原生 nft map 后端、26 单节点多引擎、23 跨族、24 加密中继、
25 协议屏蔽，沿用原清单的独立能力与验收方案。生产迁移/发布仍归第 10 项。
