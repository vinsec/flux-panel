# Flux Panel — Go 面板

本分支在 [原项目](https://github.com/bqlpfy/flux-panel) 上维护 Go 后端、React 前端、GOST 与原生 nftables Agent。
面板源码位于 `panel-go/`，不再包含 Java/Spring Boot 后端、Maven 构建或 JRE 运行依赖。
只支持 `gost` 与 `kernel`（原生 nftables）；不提供 iptables 转发后端或回退。

## 部署

使用本分支的完整源码，安装 Docker 和 Compose v2。不要下载官方旧分支的面板安装脚本。

```sh
git clone --branch main https://github.com/vinsec/flux-panel.git
cd flux-panel
./panel_install.sh install
```

脚本从本地源码构建 Go 和前端镜像，生成仅本机可读的 `.env`，启动数据库，显式初始化及迁移空库，然后等待服务健康。
默认端口仅绑定回环：前端 `127.0.0.1:6366`、后端 `127.0.0.1:6365`。通过自己的反向代理/TLS 对外提供服务。
默认管理员为 `admin_user / admin_user`，首次登录后修改密码。

已有配置可先复制 `.env.example` 为 `.env` 并填写变量。已有数据库不能执行初始化；从 Java 整体交接必须先读 [部署与交接](deploy/README.md)。
不会自动接管旧 Java 实例，不会恢复旧快照覆盖新账单，不在面板普通启动时执行 DDL。

```sh
./panel_install.sh update       # 只用于已由本脚本创建的 Go 安装
./panel_install.sh backup       # 一致性 SQL 备份到 backups/
./panel_install.sh logs
./panel_install.sh uninstall    # 保留数据库卷与 .env
```

离线环境先加载自己核对过的面板/前端/MySQL 镜像，再使用 `install --no-build`。镜像名可在 `.env` 中设置。
CI 只验证、构建和上传工作流产物，不因 push 开发分支自动发布镜像或上线。

## 开发与验证

Go 1.26.10，前端 Node 20.19.0。数据库结构为 `gost.sql` 加 `database/migrations/001–007`。

```sh
cd panel-go
go test ./...
go vet ./...
go build -o flux-panel ./cmd/panel
```

完整验证需要一次性 MySQL、浏览器和可丢弃 Linux VM；见 [Go 模块说明](panel-go/README.md)。
[功能矩阵](panel-go/contracts/feature-matrix.json) 覆盖冻结基线的 64 个 HTTP 映射以及控制连接、计费、额度和任务。
[首次功能验收](doc/go-panel-validation.md) 保留原始基线与范围；[Go 收尾验收](doc/go-only-validation.md) 记录去 Java 化后的新验证。

节点保持独立发布，构建、安装配置与固定哈希要求见 [node-agent](node-agent/README.md)。
生成节点安装命令前必须配置同一已验证发布包的 URL、manifest 与 installer 哈希；不能使用浮动下载替代。
GOST→nftables 的节点迁移与面板语言切换分别进行。

## 历史与回滚

`a08e3d8` 保留旧 Java/nftables 基线，`3126f8c` 保留最初 Go 与 Java 对照/切回验证。
当前分支的默认构建和测试均为 Go；如确需重做历史 Java 对照，使用独立历史工作区及旧产物，不把 Java 加回当前分支。
Android 客户端是独立的 Kotlin/Gradle 项目，不参与面板构建、安装或 CI。
本项目继承原项目许可与署名；仅用于合法授权的网络转发管理。

同一节点原生 nftables / 受管 GOST 切换见 [统一 Agent](doc/unified-agent-switching.md)，仅本地验证，未部署线上。
