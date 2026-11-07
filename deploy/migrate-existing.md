# 从原版 Flux Panel 迁移

本文适用于原版 1.4.3 的 **旧面板＋独立 GOST 节点**。账号、用户额度、隧道、转发规则、节点密钥和累计流量都沿用原数据。

建议先迁面板，保留全部旧 GOST 节点。转发入口和客户端配置继续使用原地址。等新面板稳定运行后，再单独安排节点升级和引擎切换。

| 方案 | 适合谁 | 切换时的影响 |
|---|---|---|
| **A 原地换面板，推荐** | 继续使用原服务器、原数据库 | 面板和节点管理连接短暂重连，旧 GOST 持续转发 |
| **B 导出数据，搬到新数据库** | 同时换服务器或重建部署 | 最终备份到新面板启动期间进入维护窗口，旧 GOST 可继续转发 |

两种方案都会保留数据。旧 GOST 定期上报流量，管理连接中断时可能存在少量统计差额，因此不承诺每个字节都严丝合缝。需要迁移节点程序时，已有连接可能中断，客户端需要重连。

## 开始前

1. 找到旧面板目录、它使用的 Compose 文件和 `.env`。原版通常使用 `docker-compose-v4.yml` 或 `docker-compose-v6.yml`。
2. 保存旧镜像和配置，提前构建新镜像。核对域名、端口和 JWT 配置，确保节点仍能访问原管理地址。
3. 暂停用户注册、规则编辑和充值等操作，选好维护时间。先用数据库副本演练，确认登录、旧节点重连和实际转发正常。

以下命令适用于原版 Docker 部署。自行修改过表结构、认证或部署方式的版本，需要先检查兼容性。备份含密码和节点密钥，请保存在私有目录。

## A 原地换面板

整个过程保留原数据库容器和旧 GOST 服务。新面板继承原数据库连接、JWT、端口、网络和时区。

### 1. 准备新程序

将本仓库克隆到一个新目录，进入新目录后执行。把 `OLD` 改成原面板目录，`OLD_FILE` 改成原来使用的 Compose 文件。

```bash
export FLUX_SOURCE_DIR="$(pwd)"
OLD=/opt/flux-panel-old
OLD_FILE="$OLD/docker-compose-v4.yml"
PROJECT=$(docker inspect springboot-backend --format '{{index .Config.Labels "com.docker.compose.project"}}')

LEGACY=(docker compose --project-directory "$OLD" --env-file "$OLD/.env" -p "$PROJECT" -f "$OLD_FILE")
NEXT=("${LEGACY[@]}" -f "$FLUX_SOURCE_DIR/deploy/legacy-compose.yml")

"${NEXT[@]}" config --quiet
"${NEXT[@]}" build backend frontend
```

构建完成后再开始切换。在同一个终端中继续执行后面的命令。

### 2. 停旧面板并做最终备份

```bash
umask 077
BACKUP="$FLUX_SOURCE_DIR/backups/legacy-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$BACKUP"
cp "$OLD/.env" "$OLD_FILE" "$BACKUP/"
"${LEGACY[@]}" stop backend frontend
"${LEGACY[@]}" exec -T mysql sh -c \
  'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec mysqldump -uroot --single-transaction --no-tablespaces --set-gtid-purged=OFF "$MYSQL_DATABASE"' \
  > "$BACKUP/database.sql"
test -s "$BACKUP/database.sql"
```

这里停止的是面板服务，节点上的 GOST 继续运行。原版 MySQL 5.7 继续使用，数据库版本可以以后再单独升级。

### 3. 升级数据结构并启动

```bash
"${NEXT[@]}" run --rm --no-deps backend migrate
"${NEXT[@]}" up -d --no-deps --no-build --wait backend frontend
```

打开原面板地址，用原账号登录。核对用户额度、规则数量、累计流量和旧节点状态，再做少量 TCP／UDP 业务验证。验收通过后恢复用户操作。

以后管理这个部署时，要同时使用旧 Compose 文件和本仓库的 `deploy/legacy-compose.yml`，即上面的 `NEXT` 命令。保存好这组命令及新仓库目录。

### 如果失败

```bash
"${NEXT[@]}" stop backend frontend
"${LEGACY[@]}" up -d --no-deps --wait backend frontend
```

这一步切回旧面板程序，并继续使用最新数据库。迁移增加的表和字段保留，避免拿旧快照覆盖切换后已经产生的用量。此回退只适用于本阶段旧 GOST 节点仍全部保留的情况。

## B 导出后迁到新数据库

适合更换面板服务器。旧服务器先保持完整，提前将新仓库和镜像准备好。新服务器需有 Docker Engine 和 Compose v2。

### 1. 取得最终数据

进入维护窗口，按方案 A 第 2 步停止旧面板并导出 `database.sql`。将 SQL、旧 `.env` 和原 Compose 文件安全复制到新服务器。保留旧 GOST 服务。

新面板应继续使用原域名和管理端口。域名更换服务器时，提前降低 DNS TTL，准备好 HTTPS 证书和反向代理配置。

### 2. 配置新部署并恢复

在新仓库目录，将旧 `.env` 复制为当前目录的 `.env`，保留原 JWT 和访问端口。再在文件末尾加入以下配置，使用独立的新数据库卷。

```dotenv
DB_NAME=flux_migrated
DB_USER=flux_migrated
MYSQL_IMAGE=mysql:8.2
MYSQL_VOLUME_NAME=flux_migrated_mysql_data
PANEL_BIND=0.0.0.0
```

保留旧 `DB_PASSWORD`，它会用于创建新数据库用户。`PANEL_BIND` 应与原访问方式一致，使用 IPv6 入口时改为 `[::]`。原来通过反向代理访问的部署，可以使用 `127.0.0.1`。限制服务端口仍按原安全组和防火墙配置处理。

```bash
chmod 600 .env
DC=(docker compose --env-file .env -p flux-migrated -f docker-compose.yml)
"${DC[@]}" build backend frontend
"${DC[@]}" up -d --wait mysql
TABLES=$("${DC[@]}" exec -T mysql sh -c \
  'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec mysql -uroot --batch --skip-column-names "$MYSQL_DATABASE" -e "SHOW TABLES"')
test -z "$TABLES" || { echo '目标数据库已有表，请停止并核对，避免覆盖数据。'; exit 1; }
"${DC[@]}" exec -T mysql sh -c \
  'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec mysql -uroot "$MYSQL_DATABASE"' \
  < /private/path/database.sql
"${DC[@]}" run --rm --no-deps backend migrate
"${DC[@]}" up -d --no-deps --no-build --wait backend frontend
```

把示例中的 SQL 路径改成实际备份位置。已有数据使用 `migrate`，不加 `--init`。确认登录、数据和实际业务正常后，将原域名切到新面板，等待旧 GOST 重连，再恢复用户操作。

### 如果失败

尚未切换入口时，继续使用旧服务器。新面板开始接收写入后，优先修复新部署；如果需要切回旧面板程序，应让它连接已经迁移、包含最新用量的数据库。不要直接恢复旧快照，也不要同时启动两个面板写入同一数据库。

## 旧节点何时升级

面板迁移验收后，旧 GOST 可以继续使用。统一 Agent／nftables 的升级是后续独立操作，会涉及节点和隧道记录转换。面板的“安装”按钮用于安装已配置的节点，不能自动把旧 GOST 记录转换成统一 Agent。

## 给 AI 助手的迁移提示词

<details>
<summary>复制提示词，填写环境后交给 AI 助手</summary>

```text
请协助将原版 Flux Panel 1.4.3 的旧面板＋独立 GOST 节点迁到 https://github.com/vinsec/flux-panel 的 main。
先读取 README.md、deploy/migrate-existing.md、deploy/legacy-compose.yml 和安装脚本，并核对实际部署。

旧面板主机及目录：待填
旧 Compose 文件及 .env 位置：待填
面板域名、管理端口、JWT 和数据库凭据的安全来源：待盘点，不要输出凭据内容
本次选择 A 原地换面板，或 B 导出到新数据库：待填
允许维护窗口、最长中断时间、少量业务验证目标：待填

本次先迁面板，全部保留原独立 GOST 节点、节点密钥、规则、入口和客户端配置。保留账号、权限、额度、ID 和最终备份时点的累计流量。接受管理连接重连和少量统计差额。

先检查版本、Compose 项目名、容器名、实际端口、表结构、数据库字符集和时区。用独立数据库副本演练，禁止测试实例连接真实节点。提前构建镜像，验证备份可恢复，再停止旧面板写入并做最终备份。原地迁移使用旧 Compose 叠加 deploy/legacy-compose.yml；新数据库导入最终 SQL 后只执行 migrate，不加 --init。

确保只有一个面板在写数据库。验收原账号登录、权限和额度、规则和节点身份、旧 GOST 重连、TCP/UDP 业务及新增用量。只使用授权的少量流量，不自动测速或通过收费入口跑量。

回退保留最新数据库和用量，不能用旧整库覆盖新账单。不能删除数据卷或清空整机防火墙、连接表。节点程序升级和引擎转换另列计划，本次不顺带操作。

先给出针对本环境的具体操作、影响、备份位置、验收和回退方案。生产执行按我明确授权的范围进行。结束后报告实际版本和验证结果。
```

</details>

返回 [面板安装](../README.md)。
