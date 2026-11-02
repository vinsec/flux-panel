# 管理员选择节点内核后端

> 历史版本说明：当前内核已收敛为原生 nftables，入口、依赖及迁移以 [native-only.md](native-only.md) 为准。
2026-11-01，限本地实现和隔离验证，未部署线上。

管理员新建节点默认选择「内核转发 / 原生 nftables」，也可选择「iptables（兼容模式）」或 GOST。
内核节点使用历史协议值 `engine=iptables`，具体后端由节点的 `kernelBackend` 决定。
隧道只保存入口节点引用，不保存可覆盖节点的后端；表单显示入口节点所配置的后端。
节点引擎和内核后端创建后固定，编辑不能直接切换。

`POST /api/v1/node/create` 的内核节点请求示例：

```json
{
  "name": "isolated-native",
  "engine": "iptables",
  "kernelBackend": "nftables",
  "ip": "10.203.1.1",
  "serverIp": "10.203.2.1",
  "portSta": 18000,
  "portEnd": 18100
}
```

新建内核节点省略 `kernelBackend` 时 API 默认 nftables；旧客户端省略 `engine` 仍按 GOST 处理。
GOST 请求不应携带 `kernelBackend`。数据库中 GOST 的兼容默认值不控制 GOST 安装或行为。
编辑请求省略 `kernelBackend` 保留数据库原值。非法值及不同后端的原地更新均拒绝。

升级面板前须**显式**应用 `database/migrations/004-node-kernel-backend.sql`，
以及此前尚未应用的 001–003；不在启动时自动执行。004 只增加列，可重复执行，
已有节点默认保留 iptables，不改用户、规则、账本或 Agent 配置。
如某个旧测试节点早已手工部署 native Agent，需核实后显式登记其实际后端，不能依赖旧行默认值推断。

安装命令将节点选择写入经过固定哈希校验的安装配置；安装包仍需重新构建和固定发布，不能复用旧安装器哈希冒充新包。
没有经过固定发布配置的面板继续拒绝生成浮动下载命令。
Agent 省略后端时的历史默认仍为 iptables，未改动 Agent、GOST 或内核数据路径。
原生后端不满足运行条件时拒绝启动，不自动退回 iptables。

交互创建/更新、暂停/恢复/删除和批量协调会核对 Agent 声明的实际后端；不匹配时拒绝下发，
不会按面板文字静默更换活动规则。旧 Agent 未声明后端时只兼容 iptables。
这些检查在管理操作中执行，不添加逐包检查。

验证：

- `npm run build`：TypeScript 和 Vite 构建通过，保留既有动态/静态 import 提示。
- 缓存 Java 21/Maven 容器、`--network none`、`mvn -o -q test package`：27 项：26 通过、0 失败/错误，1 项原有 Spring 上下文测试跳过；另有真实进程启动验证覆盖启动。
- `node-agent/tests/node_backend_integration.py`：真实 Spring Boot + 一次性 MySQL，17 项通过。
  验证重复迁移、旧数据与用户账本、新建默认/显式后端、编辑兼容、非法组合、禁止切换、
  列表脱敏、两种安装配置被现有 Go Agent `--check-config` 接受、隧道无独立覆盖及 GOST 安装兼容。
- 单元测试另验证两种错配方向在交互与批量操作中均先拒绝，不递增 revision 或修改额度/账本。
- API 验证容器使用 Docker `--internal` 网络，没有发布宿主机端口；隧道 CRUD 用在线状态夹具，
  不把该检查声称为真实内核转发测试。本次未重跑吞吐/延迟压测，未改动数据路径。
- 未连接或修改 oracle/qcloud/qhix/qcloud-sg，未经过 GZ 入口，未下载额外镜像/依赖。

机器可读结果见 [验证结果](node-kernel-backend-validation.json)。
完整本地日志位于 `/Users/vinsec/Documents/Codex/2026-10-23/ssh/work/node-backend-20261101/evidence/`。
回滚代码可保留新增列，不通过删列回滚；该操作不迁移或重启任何线上 Agent。
