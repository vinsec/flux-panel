# 本地与 qcloud-sg 的维护约定

## 同步范围

- 本地项目：`/Users/vinsec/Projects/github.com/flux-panel`。
- 服务器项目：`qcloud-sg:/app/flux-panel`。
- 两端共同维护 `feat/node-wss-support` 分支，保持相同 Git 提交。
- 节点源码保留提交 `7011a9e` 增加的面板 WSS/HTTPS 连接支持。
- `adjust_user_flow.sh`、`docker-compose.yml` 和 `docker-compose.override.yml` 来自 qcloud-sg 的既有部署，已纳入版本管理。

## 环境配置与运行数据

真实 `.env` 保存在服务器，不复制到本地或提交到 Git。变量格式见根目录 `.env.example`；填写真实配置后应将 `.env` 权限设为 `600`。

当前 Compose 覆盖配置依赖外部 `infra_net` 网络及共享 MySQL 环境。两份 Compose 文件共同描述 qcloud-sg 的部署，本地运行前需要另行准备数据库、网络与环境变量。

`backups/`、日志、数据库及其他运行数据不纳入源码同步。`adjust_user_flow.sh` 会修改流量账本，应先阅读其帮助；只有明确需要调整账本时才使用 `--execute`。

## gost 编译产物

`go-gost/gost-amd64` 和 `go-gost/gost-arm64` 在两端各保存一份，二进制文件由 `.gitignore` 忽略，校验值由 `go-gost/SHA256SUMS` 记录。首次同步复用了本地已有成品，其中 amd64 成品与 2026-10-23 从 qhix 复制到 qcloud 的版本一致。

在 `go-gost` 目录运行以下命令核验已有成品：

```bash
sha256sum -c SHA256SUMS
```

macOS 可使用 `shasum -a 256 -c SHA256SUMS`。

需要重新构建时，在 `go-gost` 目录分别运行：

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o gost-amd64
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o gost-arm64
```

重新构建后更新 `SHA256SUMS`，再同步二进制并核验两端哈希。

## 同步验收

检查两端的 `git branch --show-current`、`git rev-parse HEAD` 与 `git status --short`，确认分支、提交相同且工作区干净；再对共同文件及二进制校验哈希。

同步源码、维护脚本和编译成品不等同于升级线上容器。2026-10-25 对齐文件时，线上仍使用 `1.4.3` 镜像，源码目录没有挂载到容器；部署升级应作为单独操作安排。
