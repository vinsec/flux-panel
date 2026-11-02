# Flux Panel

基于 [原版 Flux Panel](https://github.com/bqlpfy/flux-panel) 的二次开发版本，使用 Go 面板，支持原生 nftables 和 GOST 转发。默认使用原生 nftables，节点可按需要切换模式。

## 使用文档

| 你要做什么 | 看这里 |
|---|---|
| 安装面板 | 本页下面的步骤 |
| 安装转发节点 | [节点安装](node-agent/README.md) |
| 从旧版本迁移 | [存量迁移](deploy/migrate-existing.md)，含可复制给 AI 助手的提示词 |

## 安装面板

### 1. 准备服务器

准备一台 Linux 服务器和一个指向它的域名，安装好 Git、OpenSSL、Docker 和 Compose v2。面板与节点可以分别部署在不同服务器。

### 2. 执行安装

登录面板服务器，执行：

```sh
git clone --branch main --single-branch https://github.com/vinsec/flux-panel.git
cd flux-panel
./panel_install.sh install
```

脚本会构建镜像、生成配置、创建数据库并启动面板。首次构建需要下载依赖，请等待命令执行完成。

**这条命令用于新装。已有账号和数据库的用户先看 [迁移说明](deploy/migrate-existing.md)，不要用新装代替迁移。**

### 3. 配置域名访问

默认前端地址为 `http://127.0.0.1:6366`，只允许本机访问。

在你使用的反向代理管理工具中，新建一个网站：

- 域名：你的面板域名。
- 反向代理目标：`http://127.0.0.1:6366`。
- 开启 HTTPS 和 WebSocket 支持，代理整个网站。

然后在浏览器打开 `https://你的面板域名`。默认账号、密码都是 `admin_user`，首次登录后修改密码。

### 4. 安装节点

面板“网站配置”中填好面板的 HTTPS 地址，然后按 [节点安装](node-agent/README.md) 操作。节点安装文件由面板提供，不需要另外搭建下载站或手填校验值。

## 常用操作

在安装目录中执行：

```sh
./panel_install.sh logs       # 查看面板日志
./panel_install.sh backup     # 备份本脚本创建的内置数据库
```

端口和数据库参数保存在 `.env`，变量说明见 [.env.example](.env.example)。外部数据库使用自己的备份方式；已有安装升级也按 [迁移说明](deploy/migrate-existing.md) 处理。

## 性能介绍

同样带宽下减少 CPU 开销，通过内核查找表降低大量规则的匹配负担，同时保留统计、配额与暂停能力。实测数据和实现对比见 **[透明转发重构：性能与实现上的改进](doc/transparent-forwarding-performance.md)**。

本项目保留原项目署名与 [Apache-2.0 许可](LICENSE)。
