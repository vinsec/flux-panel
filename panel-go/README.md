# Go 面板

以 `a08e3d8` 的 Java 面板为功能对照。保留现有 React 前端、MySQL、GOST 和原生 nftables Agent。
规范引擎值为 `gost` / `kernel`；历史 `iptables` 只作为旧原生 Agent 的协议名称兼容，不能选择或接管 iptables 后端。
实现状态及实测结果以 [本地验收报告](../doc/go-panel-validation.md) 为准，不能把本文件的功能清单当成测试通过声明。

## 运行和数据库

使用 Go 1.26.10 或经验证的兼容工具链。已有缓存可离线构建，不自动下载 Agent、GOST、镜像或依赖。
首次数据库使用仓库 `gost.sql`，已有数据库保留原数据。由操作者显式应用尚未执行的 001–006 迁移，面板不自动执行 DDL。
006 只增加任务完成记录和待完成批次表；现有账本、额度、累计水位、epoch 和实际后端身份不变，Java 回滚版忽略新增表。

```sh
GOTOOLCHAIN=local GOPROXY=off go build -o flux-panel ./cmd/panel
DB_HOST=127.0.0.1:3306 DB_NAME=flux DB_USER=flux DB_PASSWORD='设置自己的数据库密码' \
JWT_SECRET='沿用现有面板的 JWT 密钥' PANEL_LISTEN=127.0.0.1:6365 TZ=Asia/Shanghai ./flux-panel
```

默认只监听回环地址。前端反向代理和现有 TLS 终止方式继续保留；容器间访问时显式设置 `PANEL_LISTEN=0.0.0.0:6365`。
保持原 JWT 密钥可验证既有令牌；保留 Java 的现有密码记录格式，不要求用户统一重置密码。
日志输出到标准错误，便于服务管理器收集；审计记录写入数据库。敏感内容不写入请求体日志。

| 环境变量 | 行为 |
| --- | --- |
| `DB_HOST` / `DB_NAME` / `DB_USER` / `DB_PASSWORD` | MySQL 地址、库和账号；地址可带端口 |
| `JWT_SECRET` | 必填；与旧面板一致才能保持令牌兼容 |
| `PANEL_LISTEN` | 默认 `127.0.0.1:6365` |
| `TZ` | 统计/每日重置所用时区；应与 Java 部署保持一致 |
| `PANEL_READ_ONLY=true` | 拒绝写接口、Agent 连接及后台任务，供独立快照验证 |
| `ENGINE_AUTH_ALLOW_LEGACY_QUERY=false` | 禁止旧 URL 密钥鉴权；仅在旧 GOST/客户端迁移完成后启用 |
| `ENGINE_AUTH_SESSION_MILLIS` | 默认 900000，实际范围 60000–3600000 |
| `ENGINE_LEASE_MAX_BYTES` | 默认 4294967296，允许 128–4294967296 |
| `ENGINE_LEASE_DURATION_MILLIS` | 默认 30000，允许 1000–60000 |
| `NODE_RELEASE_BASE_URL` | 固定 HTTPS 节点发布地址 |
| `NODE_RELEASE_MANIFEST_SHA256` / `NODE_RELEASE_INSTALLER_SHA256` | 固定节点发布哈希；缺少时拒绝生成浮动安装命令 |

`GET /healthz` 检查数据库连接。Go 写实例以持有的专用 MySQL 连接取得单实例执行权，连接丢失后拒绝继续变更并停止任务。
这个锁只约束 Go 实例，不能代替停用旧 Java；两者不能同时管理同一套业务。
SIGTERM/SIGINT 时停止接收请求、等待在途 HTTP 操作、关闭 Agent 连接、停止任务并释放执行权。

## 测试与功能对照

`contracts/java-baseline.json` 包含 Java 的 64 个 HTTP 映射和 DTO 约束；`tests/inventory.py` 可从基线源码重新生成。
测试既检查成功路径，也检查权限、计数去重、额度预留、并发、崩溃/事务回滚、WSS、会话轮换和任务重复执行。
四类验证码保留原 TAC 的请求、响应和交互格式。图像和字体来自原项目资源，答案只留在进程内存。
浏览器测试的答案文件由 `_test.go` 专用装饰器写入临时目录，产品二进制不含该入口或文件导出功能。

```sh
GOTOOLCHAIN=local GOPROXY=off go test -race ./...
GOTOOLCHAIN=local GOPROXY=off go vet ./...
```

实际数据库测试要求 `FLUX_TEST_DSN` 指向名称以 `flux_go_test` 开头的可丢弃数据库；它会清空该库，禁止用于生产库。
设置 `FLUX_TEST_SCHEMA_ROOT` 指向仓库根目录。仅单元测试通过不等于完成验证，必须另跑真实数据库和 Agent 套件。
原 `node-agent/tests/node_backend_integration.py`、`integration.py` 默认仍测试 Java；设置 `FLUX_TEST_PANEL=go` 后测试 `/build/flux-panel`。
后一套件需要支持 IFB 的可丢弃 Linux 环境；使用现有 Fusion 私网，不能以 Docker 缺能力为理由跳过必要检查。

原前端浏览器工作流使用固定构建，外部浏览器请求全部禁止。设置 `FLUX_TEST_BROWSER_SCRIPT` 为 `tests/browser-flows.cjs`，
并提供本地 `PLAYWRIGHT_MODULE`、前端回环端口和临时测试数据库；不要让开发热更新器监视测试输出目录。
Linux 的实际 GOST/WSS 测试使用 `FLUX_TEST_GOST_BIN` 指向经过哈希核对的原二进制。

## 本地产物与未来回滚

`FLUX_GO_BIN=/已缓存的/go packaging/build.sh /本地输出目录` 构建 Linux ARM64/AMD64 静态二进制、哈希清单和迁移文件。
ARM64 是本次实际 Linux 验证平台；其他架构的编译成功不能冒充运行测试。
运行时 Dockerfile 从已构建的 `flux-panel` 创建无 Java 的最小镜像，不联网安装软件。
前端、Agent 和 GOST 保持独立发布；面板安装配置继续要求节点发布清单和安装器的固定哈希。

本次不发布线上。将来切换时先阻止管理变更、排空事务并停用 Java 的自动重启和任务，再启动 Go、重连 Agent 并核对累计水位。
失败时停止 Go，以 `a08e3d8` 配套 Java 接管同一份最新数据库，新增 006 表可以保留。
不恢复旧数据库快照覆盖新账单；回退到更早双后端版本属于另一项迁移，不能混同为 Java/Go 代码回滚。
GOST→nftables 节点迁移继续单独处理，现有 TCP 连接不能跨引擎无损迁移。
