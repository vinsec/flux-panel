# Go 面板去 Java 收尾验收

日期：2026-11-02。在 `feat/panel-go-native` 上继续完成，功能验收父提交为 `3126f8c`。

**本轮收尾及本地验证已完成。当前树不再包含 Java/Spring Boot 后端与 Maven 构建；没有线上操作。**

## 仓库与发布入口

删除原后端整个目录，其中 137 个 Java 源文件及 pom、Dockerfile、资源/配置/测试全部移除。
验证码所需图片/字体已由上一轮保留在 Go 资源目录。六份前向 SQL 原样移到 `database/migrations/`，基础 schema 仍为 `gost.sql`。
旧 005 引擎反迁移不再进入当前代码树或发布包；Java 语言回滚的旧源码/产物在历史提交中保留，无需改写 Git 历史。

根目录安装脚本只使用本地 checkout 的 Go Compose 和源码镜像，不再下载官方 Java 版，也不修改 Docker daemon 或自动重启其他服务。
全新安装显式执行 `migrate --init`，只接受空库；更新先停旧 Go 写实例，再前向迁移并启动。普通服务启动不执行 DDL。
`healthcheck` 是静态 Go 命令，scratch 健康检查不依赖 shell/wget；源代码及离线包均包含正确的 SQL 路径。
旧机器专用 Compose override 改为显式示例。默认只绑定回环，现有 Java 首次交接需按部署说明停用旧写入者，不能直接自动接管。

CI 改为 Go 面板、前端、独立 Agent 和 GOST 构建/验证；只上传构建产物，不自动发布镜像、Release 或部署。
保持 main/beta、PR 和手动触发入口；本次开发分支 push 不触发远端 CI，全部验证在本地隔离环境完成。
接口生成器默认读取冻结 JSON，可从历史 Git 对象复核，不需要把 Java 源码检出到当前树或安装 JRE。
节点集成测试入口固定 Go，删除 Java 启动、JAR 检查及双运行时开关。

前端新增可提交的锁文件和与既有依赖相符的安装选项，补齐不同平台的可选原生包；852 个既有依赖版本未变化。
实际验证干净 Linux 环境 `npm ci` 后完成 TypeScript/Vite 构建。前端 Nginx 代理完整 `/flow/`，包含原生会话/计费路径。
Android 是独立 Kotlin/Gradle 客户端，未混入面板构建和 CI；本次删除的是旧 Java 面板后端。

## 本轮实测

| 验证 | 结果 |
| --- | --- |
| Go/race/真实 MySQL/浏览器 | 49 项（含子测试），0 失败、0 跳过；含 64 HTTP 映射、权限及事务回归 |
| 原前端工作流 | 四类验证码及八个主要页面通过；浏览器只允许本地请求 |
| 节点/迁移/API | 23 项通过；测试容器没有 JRE，实际使用新 Go 二进制 |
| 实际 Nginx + Go | 7 项通过：静态页、登录、鉴权列表、健康、flow、原生会话、管理员 WS 升级 |
| 安装生命周期 | 全新安装、更新保留账本、重复初始化拒绝、600 权限一致性备份、卸载保留卷和最新账本全部通过 |
| GOST 实际 WSS | 原冻结二进制、可信 CA、加密控制、TCP/UDP、HTTPS 计费与删除通过 |
| 源码构建 | Go 与前端 Dockerfile 都从干净构建阶段成功构建；源码镜像 Go 二进制与离线包相同 |
| 独立节点 | Agent 单元测试通过；保留 GOST 两个 Linux 架构构建通过 |
| 发布包 | ARM64/AMD64 重复构建哈希一致，SQL 与 Dockerfile 纳入校验；复用旧输出目录也不夹带旧逆迁移 |
| 静态检查 | vet、合同生成器、去 Java 检查、shell/Python 语法、全部 Compose 变体通过 |

本轮安装和 API 测试全部使用自己创建的 Docker internal 网络、一次性数据库及本地浏览器，没有连接生产 Agent、数据库、SSH 或 GZ。
从源码镜像更新后再次执行实际 Nginx/Go 验证，卸载后重新挂载测试数据库卷，确认最新账本仍为测试写入值。
构建依赖取公开的软件源，业务验证流量全部留在本地隔离网络。

初期容器内网不能直接通过 Desktop 的主机映射端口连接，改用仅回环的受限本地 SQL 中转后重跑。
早期干净前端构建暴露未提交锁文件及平台可选包缺失，完成锁文件后重做构建；失败尝试未计为通过，日志保留本地。

## 证据和边界

机器可读摘要见 [JSON](go-only-validation.json)，逐项功能归属见 [功能矩阵](../panel-go/contracts/feature-matrix.json)，运行/交接说明见 [部署](../deploy/README.md)。

此前 92 项真实 VM 检查、10k 原生规则、600 秒稳态及 Go↔Java 切回属于 `3126f8c` 的历史功能验收；本轮没有冒充重新执行这些 VM 检查。
本轮没有修改控制/转发/计费的产品实现；变更涉及命令、构建、安装、SQL 路径及验证入口，并对这些路径完成上述复验。
Linux ARM64 实际运行，AMD64 只交叉编译，不声称已经运行。GOST delta 协议、单写入者及跨引擎迁移边界不变。

工作流格式参考 [GitHub 官方语法](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax)。
