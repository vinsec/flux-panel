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

## 安装转发节点

面板镜像已自带节点程序，不需要自己准备下载地址或填写校验值。

1. 在“网站配置”中填写面板的 HTTPS 访问地址。
2. 打开“节点监控”→“新增”，选择“统一 Agent”，填好节点名称、服务器 IP 和业务端口范围。
3. 保存后点击该节点的“安装”，复制弹窗里的整段命令。
4. SSH 登录要作为节点的服务器，使用 root 用户粘贴执行。
5. 等安装完成，回面板确认节点显示“在线”，再创建隧道和转发规则。

默认使用原生 nftables；需要受管 GOST 时可在“编辑节点”中切换。安装程序会识别常见 CPU 架构并准备必要依赖。适用于支持 systemd 的 Linux；已有旧节点迁移先按 [部署与交接](deploy/README.md) 安排维护，不能直接当新节点重装。完整说明见 [节点安装](node-agent/README.md)。

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

节点与面板分开部署，安装程序由面板镜像提供；维护者构建与校验说明见 [node-agent](node-agent/README.md)。
GOST→nftables 的节点迁移与面板语言切换分别进行。

## 历史与回滚

`a08e3d8` 保留旧 Java/nftables 基线，`3126f8c` 保留最初 Go 与 Java 对照/切回验证。
当前分支的默认构建和测试均为 Go；如确需重做历史 Java 对照，使用独立历史工作区及旧产物，不把 Java 加回当前分支。
Android 客户端是独立的 Kotlin/Gradle 项目，不参与面板构建、安装或 CI。
本项目继承原项目许可与署名；仅用于合法授权的网络转发管理。

同一节点原生 nftables / 受管 GOST 切换见 [统一 Agent](doc/unified-agent-switching.md)。qcloud 和 qhix 已升级并实际切到原生 nftables，分别见 [qcloud 上线记录](doc/qcloud-agent-migration-20261102.md)和 [qhix 上线记录](doc/qhix-agent-migration-20261102.md)。
