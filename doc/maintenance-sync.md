# main 源码与线上成品的维护约定

## 同步范围

- GitHub 主仓库：`https://github.com/vinsec/flux-panel.git`，后续工作统一在 `main`。
- 本地主项目：`/Users/vinsec/Projects/github.com/flux-panel`，使用 `main`。
- 线上面板源码：`oracle:/app/flux-panel`，使用同一个 `main` 提交。
- `fork` 指向 vinsec 的维护仓库；`origin` 可保留官方上游地址，不能把本项目提交误推到官方仓库。
- 旧功能分支及独立历史 worktree 仅供回溯，不作为日常维护入口。源码同步不覆盖其他工作区的未提交草稿；整理前先将草稿原样备份到项目之外。
- `qcloud-sg:/app/flux-panel` 是早期维护副本，不是当前 Oracle 面板部署入口。其历史 WSS 分支名称不再是 main 的维护要求。

## 环境配置与运行数据

真实 `.env` 保存在服务器，不复制到本地或提交到 Git。变量格式见根目录 `.env.example`；填写真实配置后应将 `.env` 权限设为 `600`。源码切换分支时保留环境文件，并校验其内容没有变化。

Oracle 当前运行服务由 `/app/migration/compose.json` 描述，环境配置、数据卷及镜像部署信息属于运行环境，不能为了清理 Git 状态改成仓库默认值。源码目录的旧 Compose 修改和部署笔记应先保存到 root 私有备份，再恢复为 main 的文件；不对运行中的容器执行重建或整库恢复。

`backups/`、日志、数据库及其他运行数据不纳入源码同步。`adjust_user_flow.sh` 会修改流量账本，应先阅读其帮助；只有明确需要调整账本时才使用 `--execute`。

## 构建产物与版本证明

节点业务引擎为统一 Agent 的 `kernel` 或受管 `gost`；原生后端固定 nftables。WSS 控制通信支持保留。旧 `go-gost/gost-amd64`、`gost-arm64` 是历史构建产物，不能用它们覆盖统一 Agent 的受管 worker。

同步源码后，核对三个独立组件：

- Go 面板：固定 Go 工具链、目标架构和构建参数，比较新构建二进制与 Oracle 容器内 `/flux-panel` 的 SHA-256。
- 前端：TypeScript/Vite 构建后，逐个比较 `dist` 文件与线上前端容器内文件的 SHA-256；不能只检查镜像标签或首页能否打开。
- Agent：比较 main 构建的 Linux amd64 程序与 qcloud、qhix `/usr/local/bin/flux-agent` 的 SHA-256，并只读检查实际模式、规则及账本状态。

如果组件代码未变化、构建成品已与线上逐字节一致，复用既有部署即可，不为更新文档提交号重启服务。镜像标签保留实际构建时点；记录当前 main 提交、组件源码树与成品哈希之间的对应关系。

环境备份、完整数据库、密钥、私有状态和大型二进制不进入 Git。成品发布遵循各组件既有的固定哈希校验要求。

## 同步验收

检查本地主项目与 Oracle 源码的 `git branch --show-current`、`git rev-parse HEAD`、`git status --short`，再确认 GitHub `refs/heads/main` 同一提交。推送只允许普通 fast-forward；遇到远端新增提交先整合，不 force push。

同步前后核对运行容器 PID、挂载、节点进程、实际 `forwardingMode` 和额度状态。只在隔离环境执行功能/性能回归；线上验证默认只读。源码对齐不自动执行迁移、流量调整、模式切换或公网压测。
