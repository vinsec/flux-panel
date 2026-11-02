# Go 面板部署与交接

面板服务为 Go 单进程，配套 MySQL 与独立前端。Compose 的 backend 固定从 `panel-go/Dockerfile` 构建；没有 Java 镜像回退。
`docker-compose.yml` 和 `-v4.yml` 使用 IPv4 网络，`-v6.yml` 增加 Docker IPv6；主机监听地址用 `PANEL_BIND` 显式指定。
不修改 Docker daemon、不重启主机其他服务。机器专用 override 已改为显式示例，不会自动加载。

## 全新安装

从本分支完整 checkout 执行 `./panel_install.sh install`。可提前填写 `.env`；否则生成随机数据库/JWT 密钥。
脚本只在显式 install 时对空数据库执行 `flux-panel migrate --init`。非空库会拒绝，不能借 install 重置用户或账本。
外部数据库部署请手动组合 `docker-compose.yml` 与 `deploy/compose.external-db.example.yml`，配置 DB_HOST/DATABASE_NETWORK，并显式迁移；内置 mysql 不会启动。

健康检查直接调用静态二进制 `flux-panel healthcheck`，检查 `/healthz` 的数据库可用性，scratch 镜像无需 shell/wget。
后端以 uid/gid 65532、只读根文件系统、无 capability 运行。日志写标准错误，审计写库；时区数据已嵌入二进制。
前端代理 `/api/v1/`、整个 `/flow/`、`/system-info` WebSocket 和 `/healthz`。

## 已有 Go 安装更新

`./panel_install.sh update` 先构建新镜像，停用当前 Go 写实例，再显式执行前向迁移，最后启动 backend/frontend 并等待健康。
构建失败不会停旧实例；迁移失败则 backend 保持停止，不自动重新启动旧代码继续写入。
不运行 `down -v`，不删除或重新创建业务数据库。`backup` 输出一致性 SQL 备份，文件权限由 umask 077 限制。

## 从旧 Java 面板整体交接

不能直接运行 update 自动接管。先核对当前版本/数据库备份/节点发布及能力、统计时区和任务执行状态，选择避开小时/每日重置的窗口。
停止管理写入、排空在途账本事务，明确停用旧面板的进程、自动重启及任务；确认只有一个写入者。
配置新的 Go Compose 指向同一个最新数据库，并沿用 JWT 密钥、时区与节点固定发布配置。
执行一次性命令 `docker compose run --rm --no-deps backend migrate`，不能加 `--init`；随后启动 Go、重连 Agent，核对余额、水位、节点与实际转发。
Go 单实例锁只约束 Go 实例，不能阻止旧 Java 写库。新脚本的安装标记不是跨语言执行权锁。

回滚使用历史 `a08e3d8` 的独立工作区/冻结产物：先停止 Go 并排空操作，再让旧面板接管最新合法数据库。
001–007 的增量数据库结构可保留；不执行旧引擎反迁移，不恢复旧快照覆盖新账单。
上述旧面板回滚仅适用于尚未引入 v7 统一 Agent 的节点。旧 Go/Java 的 credit 版本识别不兼容 v7，格式 8 账本也不能交给旧 Agent；已有统一节点应保留本版本面板/Agent并切回先前验证的转发模式，详见 [切换说明](../doc/unified-agent-switching.md)。
回滚不能理解成 Java/Go 同时运行。历史 Java 对照不属于当前分支构建依赖。

## 离线发布包

`panel-go/packaging/build.sh /指定输出目录` 产生两个 Linux 架构的静态程序、迁移文件、schema、运行时 Dockerfile、SHA256SUMS 和 release.json。
已有缓存可设置 `FLUX_GO_BIN` 选择工具链；构建脚本禁止隐式下载依赖。示例：

```sh
cp /已核对的发布包/flux-panel-linux-arm64 /已核对的发布包/flux-panel
docker build --network=none -t flux-panel-go:local /已核对的发布包
```

前端离线运行时 Dockerfile 为 `vite-frontend/packaging/Dockerfile`，将已构建 `dist/`、`nginx.conf` 放入该构建上下文。
保存/加载镜像后使用 `--no-build`，不要让安装脚本从其他分支下载 Compose 或旧版后端。
