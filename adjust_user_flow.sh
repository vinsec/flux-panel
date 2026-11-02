#!/usr/bin/env bash
# =============================================================================
# adjust_user_flow.sh
# -----------------------------------------------------------------------------
# flux-panel 用户流量「调账」工具（可回滚）
#
# 背景（给后续 agent / 维护者）：
#   flux-panel 的用量账本在 MySQL（本机部署为 docker 容器 infra-mysql-1，
#   库名/账号见 /app/flux-panel/.env）。节点 Gost 周期性 POST /flow/upload，
#   对下列字段做原子累加：
#     - user.in_flow / user.out_flow          账号总账
#     - user_tunnel.in_flow / out_flow        用户-隧道权限账
#     - forward.in_flow / out_flow            单条端口转发账
#   限额判断：used = in_flow + out_flow ，与 quota(user.flow / user_tunnel.flow，单位 GB) 比较。
#   小时曲线表 statistics_flow：
#     - total_flow : 当时用户累计 used 快照
#     - flow       : 相对上一条的小时增量（Dashboard 24h 柱状图）
#   定时任务 StatisticsFlowAsync 每小时：
#     hour_inc = user(in+out) - 上一条 total_flow
#   因此调账时必须：
#     1) 主账本三层同步加同一业务增量（避免面板各页数字不一致）
#     2) statistics_flow 全部 total_flow += delta，且最新一行 flow += delta
#        ——曲线整体上移，且下一整点不会再「假暴增」一次 50G
#
# 方向语义（Gost 入口 service 客户端连接视角）：
#   in_flow  <- 上报 d <- InputBytes  <- Read  自客户端（用户「上传」向）
#   out_flow <- 上报 u <- OutputBytes <- Write 向客户端（用户「下载」向）
# 代理场景通常 out >> in（下载多），调账默认按**当前 in:out 比例**拆分，
# 而不是 50:50（与 VPS 网卡 RX≈TX 是不同层级，勿混用）。
#
# 与 VPS 厂商「只算出站 TX」对齐时的隧道配置建议（本脚本不修改隧道配置）：
#   端口转发 + 流量计算「单向」+ 倍率 1 → 面板 used≈出站；勿开「双向」(实现里约 ×2)。
#
# 用法示例：
#   # 演练（只打印计划，不写库）
#   ./adjust_user_flow.sh --user wzl --add-gb 50
#   # 真正执行（先自动备份，再事务更新）
#   ./adjust_user_flow.sh --user wzl --add-gb 50 --execute
#   # 指定备份目录 / 同时提高配额以免超限 Pause
#   ./adjust_user_flow.sh --user wzl --add-gb 50 --also-add-quota-gb 50 --execute
#   # 回滚（使用备份目录里生成的 ROLLBACK.sh）
#   bash /root/flux-panel-backups/wzl_flow_.../ROLLBACK.sh
#
# 退出码：
#   0 成功（含 dry-run）
#   1 参数/用户不存在/校验失败
#   2 依赖缺失或 DB 不可用
# =============================================================================

set -euo pipefail

# ----------------------------- 可改默认值 ------------------------------------
# 面板项目根目录（脚本应位于此目录下，.env 同级）
PANEL_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${PANEL_ROOT}/.env"

# MySQL 所在容器名（override 把 gost-mysql 关掉后，数据在共享 infra-mysql）
MYSQL_CONTAINER="${MYSQL_CONTAINER:-infra-mysql-1}"

# 备份根目录
BACKUP_ROOT="${BACKUP_ROOT:-/root/flux-panel-backups}"

# 1 GiB（与面板 BYTES_TO_GB = 1024^3 一致，勿改成 1000^3）
GIB=1073741824

# ----------------------------- 参数 ------------------------------------------
USER_NAME=""
ADD_GB=""
ALSO_ADD_QUOTA_GB="0"
EXECUTE="0"
FORCE_RATIO=""   # 可选 "in_pct:out_pct" 如 "16:84"；空则用当前账本比例

usage() {
  sed -n '1,80p' "$0" | sed -n '/^# 用法示例/,/^# 退出码/p' | sed 's/^# \{0,1\}//'
  cat <<EOF

必选参数:
  --user NAME          面板登录名（user.user 字段，如 wzl）
  --add-gb N           增加的总用量（GiB，十进制，可为小数如 12.5）

可选参数:
  --execute            实际写库；缺省为 dry-run
  --also-add-quota-gb N
                       同步给 user.flow 与 user_tunnel.flow 增加配额(GB，整数语义与面板一致)
                       当 used 增加后可能超过原配额导致 Gost Pause 时使用
  --ratio IN:OUT       强制 in/out 拆分比例（百分比或权重，如 16:84 或 1:5）
                       默认按该用户当前 in_flow:out_flow
  --mysql-container C  默认 infra-mysql-1
  --backup-root DIR    默认 /root/flux-panel-backups
  -h, --help           帮助

注意:
  - dry-run 不会写库、不会生成备份；--execute 才会备份+事务更新
  - 多条 forward / user_tunnel 时：先按各行当前 total 占比分摊总增量，再按行内 in/out 比拆分
  - total=0 的行不参与分摊；若全部为 0，则增量全部记入 user，并按 50:50 拆 in/out（可用 --ratio 覆盖）
EOF
}

log()  { printf '[%s] %s\n' "$(date '+%F %T')" "$*"; }
die()  { log "ERROR: $*"; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "缺少命令: $1"; }

# ----------------------------- 参数解析 --------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --user) USER_NAME="${2:-}"; shift 2 ;;
    --add-gb) ADD_GB="${2:-}"; shift 2 ;;
    --also-add-quota-gb) ALSO_ADD_QUOTA_GB="${2:-0}"; shift 2 ;;
    --execute) EXECUTE="1"; shift ;;
    --ratio) FORCE_RATIO="${2:-}"; shift 2 ;;
    --mysql-container) MYSQL_CONTAINER="${2:-}"; shift 2 ;;
    --backup-root) BACKUP_ROOT="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "未知参数: $1（--help 查看用法）" ;;
  esac
done

[[ -n "$USER_NAME" ]] || die "必须指定 --user"
[[ -n "$ADD_GB" ]]    || die "必须指定 --add-gb"
[[ -f "$ENV_FILE" ]]  || die "找不到 $ENV_FILE"

need docker
need python3
need awk

# ----------------------------- 加载 DB 配置 ----------------------------------
# .env 形如 DB_NAME=... DB_USER=... DB_PASSWORD=...（可能含特殊字符，用 source 需谨慎）
# 这里用逐行解析，避免 password 中的特殊字符被 shell 展开两次
DB_NAME=""; DB_USER=""; DB_PASSWORD=""
while IFS= read -r line || [[ -n "$line" ]]; do
  line="${line%%#*}"
  line="$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  [[ -z "$line" ]] && continue
  case "$line" in
    DB_NAME=*) DB_NAME="${line#DB_NAME=}" ;;
    DB_USER=*) DB_USER="${line#DB_USER=}" ;;
    DB_PASSWORD=*) DB_PASSWORD="${line#DB_PASSWORD=}" ;;
  esac
done < "$ENV_FILE"
[[ -n "$DB_NAME" && -n "$DB_USER" && -n "$DB_PASSWORD" ]] || die ".env 缺少 DB_NAME/DB_USER/DB_PASSWORD"

docker inspect "$MYSQL_CONTAINER" >/dev/null 2>&1 || die "容器不存在或未运行: $MYSQL_CONTAINER"

# mysql 客户端封装：去掉 warning，失败则非 0
mysql_q() {
  docker exec "$MYSQL_CONTAINER" mysql -N -u"$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" -e "$1" 2>/dev/null
}
mysql_exec() {
  docker exec -i "$MYSQL_CONTAINER" mysql -u"$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" 2>/dev/null
}

# ----------------------------- 换算增量字节 ----------------------------------
# ADD_GB 支持小数；结果为整数字节，与面板 1024^3 一致
DELTA_BYTES="$(python3 - <<PY
from decimal import Decimal, ROUND_HALF_UP
gb = Decimal("${ADD_GB}")
if gb <= 0:
    raise SystemExit("add-gb 必须 > 0")
delta = (gb * Decimal(1024**3)).quantize(Decimal("1"), rounding=ROUND_HALF_UP)
print(int(delta))
PY
)"

log "目标用户=${USER_NAME}  增量=${ADD_GB} GiB (${DELTA_BYTES} bytes)  execute=${EXECUTE}"

# ----------------------------- 读取用户快照 ----------------------------------
USER_ROW="$(mysql_q "SELECT id, IFNULL(in_flow,0), IFNULL(out_flow,0), IFNULL(flow,0), IFNULL(status,0) FROM user WHERE user='${USER_NAME//\'/\\\'}' LIMIT 1")"
[[ -n "$USER_ROW" ]] || die "用户不存在: $USER_NAME"
read -r USER_ID U_IN U_OUT U_QUOTA U_STATUS <<<"$USER_ROW"
U_TOTAL=$((U_IN + U_OUT))

log "user id=${USER_ID} quota_gb=${U_QUOTA} status=${U_STATUS} in=${U_IN} out=${U_OUT} total=${U_TOTAL} (~$(python3 -c "print(round(${U_TOTAL}/1024**3,4))") GiB)"

# 拉取 user_tunnel / forward 明细（TSV）
UT_TSV="$(mysql_q "SELECT id, IFNULL(in_flow,0), IFNULL(out_flow,0), IFNULL(flow,0) FROM user_tunnel WHERE user_id=${USER_ID} ORDER BY id")"
FW_TSV="$(mysql_q "SELECT id, IFNULL(in_flow,0), IFNULL(out_flow,0) FROM forward WHERE user_id=${USER_ID} ORDER BY id")"

# ----------------------------- Python：计算分摊计划 ---------------------------
# 输出 shell 可 source 的变量 + SQL 片段文件
PLAN_DIR="$(mktemp -d /tmp/flux-adjust-plan.XXXXXX)"
PLAN_SH="${PLAN_DIR}/plan.sh"
PLAN_SQL="${PLAN_DIR}/apply.sql"
PLAN_TXT="${PLAN_DIR}/plan.txt"

export PLAN_SH PLAN_SQL PLAN_TXT
export DELTA_BYTES USER_ID U_IN U_OUT U_TOTAL U_QUOTA ALSO_ADD_QUOTA_GB FORCE_RATIO
export UT_TSV FW_TSV

python3 - <<'PY'
import os, sys
from decimal import Decimal

delta = int(os.environ["DELTA_BYTES"])
uid = int(os.environ["USER_ID"])
u_in = int(os.environ["U_IN"])
u_out = int(os.environ["U_OUT"])
u_total = int(os.environ["U_TOTAL"])
quota = int(os.environ["U_QUOTA"])
also_q = int(Decimal(os.environ.get("ALSO_ADD_QUOTA_GB") or "0"))
force = (os.environ.get("FORCE_RATIO") or "").strip()

def parse_rows(tsv, cols):
    rows = []
    for line in (tsv or "").splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) < cols:
            parts = line.split()
        rows.append([int(x) for x in parts[:cols]])
    return rows

ut_rows = parse_rows(os.environ.get("UT_TSV", ""), 4)  # id,in,out,flow
fw_rows = parse_rows(os.environ.get("FW_TSV", ""), 3)  # id,in,out

def split_in_out(total_delta, in_b, out_b, force_ratio):
    """按比例拆 total_delta -> (d_in, d_out)，保证 d_in+d_out==total_delta。"""
    if total_delta == 0:
        return 0, 0
    if force_ratio:
        a, b = force_ratio.replace("%", "").split(":")
        wa, wb = Decimal(a.strip()), Decimal(b.strip())
        if wa < 0 or wb < 0 or (wa + wb) == 0:
            raise SystemExit("无效 --ratio")
        d_in = int((Decimal(total_delta) * wa / (wa + wb)).to_integral_value(rounding="ROUND_HALF_UP"))
        d_out = total_delta - d_in
        return d_in, d_out
    t = in_b + out_b
    if t <= 0:
        # 无历史：默认 50:50（可用 --ratio 覆盖）
        d_in = total_delta // 2
        d_out = total_delta - d_in
        return d_in, d_out
    d_in = (total_delta * in_b) // t
    d_out = total_delta - d_in
    return d_in, d_out

def allocate_rows(rows, total_delta, has_quota_col=False):
    """
    rows: list of [id, in, out, (quota?)]
    按各行 (in+out) 占比分摊 total_delta；零流量行不参与。
    返回 list of dict.
    """
    if not rows:
        return []
    weights = []
    for r in rows:
        w = r[1] + r[2]
        weights.append(max(w, 0))
    sum_w = sum(weights)
    allocs = []
    if sum_w <= 0:
        # 全部为 0：均分到每一行
        n = len(rows)
        base = total_delta // n
        rem = total_delta - base * n
        for i, r in enumerate(rows):
            part = base + (1 if i < rem else 0)
            di, do = split_in_out(part, r[1], r[2], force)
            item = {"id": r[0], "d_in": di, "d_out": do, "part": part}
            if has_quota_col:
                item["quota"] = r[3]
            allocs.append(item)
        return allocs

    # 最大余数法，保证各 part 之和 == total_delta
    raw = []
    for w in weights:
        raw.append(total_delta * w / sum_w)
    floors = [int(x) for x in raw]
    missing = total_delta - sum(floors)
    # 按小数部分排序补齐
    order = sorted(range(len(rows)), key=lambda i: (raw[i] - floors[i]), reverse=True)
    for i in order[:missing]:
        floors[i] += 1

    for i, r in enumerate(rows):
        part = floors[i]
        di, do = split_in_out(part, r[1], r[2], force)
        item = {"id": r[0], "d_in": di, "d_out": do, "part": part}
        if has_quota_col:
            item["quota"] = r[3]
        allocs.append(item)
    return allocs

u_di, u_do = split_in_out(delta, u_in, u_out, force)
ut_alloc = allocate_rows(ut_rows, delta, has_quota_col=True)
fw_alloc = allocate_rows(fw_rows, delta, has_quota_col=False)

# 校验分摊和
assert u_di + u_do == delta
assert sum(x["d_in"] + x["d_out"] for x in ut_alloc) == delta or not ut_alloc
assert sum(x["d_in"] + x["d_out"] for x in fw_alloc) == delta or not fw_alloc
# 无 tunnel/forward 时只更新 user + stats（少见）

new_u_in, new_u_out = u_in + u_di, u_out + u_do
new_total = new_u_in + new_u_out
new_quota = quota + also_q
# 超限预警（面板 used 与 quota*GiB 比较）
GIB = 1024 ** 3
will_exceed = new_quota > 0 and new_quota < 99999 and new_total > new_quota * GIB

lines = []
lines.append(f"USER id={uid}")
lines.append(f"  delta_bytes={delta} ({delta/GIB:.4f} GiB)")
lines.append(f"  ratio_mode={'forced '+force if force else 'from current in/out'}")
lines.append(f"  user: in +{u_di} out +{u_do}")
lines.append(f"  user before: in={u_in} out={u_out} total={u_total} ({u_total/GIB:.4f} GiB) quota={quota}G")
lines.append(f"  user after:  in={new_u_in} out={new_u_out} total={new_total} ({new_total/GIB:.4f} GiB) quota={new_quota}G")
if will_exceed:
    lines.append(f"  WARNING: after adjust, used > quota → next /flow/upload may Pause services!")
    lines.append(f"           consider --also-add-quota-gb ...")
lines.append("  user_tunnel alloc:")
for a in ut_alloc:
    lines.append(f"    id={a['id']} +in={a['d_in']} +out={a['d_out']} (part={a['part']})")
if not ut_alloc:
    lines.append("    (none)")
lines.append("  forward alloc:")
for a in fw_alloc:
    lines.append(f"    id={a['id']} +in={a['d_in']} +out={a['d_out']} (part={a['part']})")
if not fw_alloc:
    lines.append("    (none)")
lines.append("  statistics_flow: ALL total_flow += delta; LATEST row flow += delta")

open(os.environ["PLAN_TXT"], "w").write("\n".join(lines) + "\n")

# shell exports for logging
with open(os.environ["PLAN_SH"], "w") as f:
    f.write(f"PLAN_U_DI={u_di}\nPLAN_U_DO={u_do}\n")
    f.write(f"PLAN_NEW_TOTAL={new_total}\nPLAN_NEW_QUOTA={new_quota}\n")
    f.write(f"PLAN_WILL_EXCEED={'1' if will_exceed else '0'}\n")

# SQL apply
sql = []
sql.append("START TRANSACTION;")
sql.append(f"SELECT id, in_flow, out_flow FROM user WHERE id={uid} FOR UPDATE;")
sql.append(
    f"UPDATE user SET in_flow=in_flow+({u_di}), out_flow=out_flow+({u_do})"
    + (f", flow=flow+({also_q})" if also_q else "")
    + f" WHERE id={uid};"
)
for a in ut_alloc:
    qpart = f", flow=flow+({also_q})" if also_q else ""
    sql.append(
        f"UPDATE user_tunnel SET in_flow=in_flow+({a['d_in']}), out_flow=out_flow+({a['d_out']}){qpart} WHERE id={a['id']} AND user_id={uid};"
    )
for a in fw_alloc:
    sql.append(
        f"UPDATE forward SET in_flow=in_flow+({a['d_in']}), out_flow=out_flow+({a['d_out']}) WHERE id={a['id']} AND user_id={uid};"
    )
sql.append(f"UPDATE statistics_flow SET total_flow=total_flow+({delta}) WHERE user_id={uid};")
sql.append(
    f"UPDATE statistics_flow SET flow=flow+({delta}) WHERE id=("
    f"SELECT id FROM (SELECT id FROM statistics_flow WHERE user_id={uid} ORDER BY id DESC LIMIT 1) t);"
)
sql.append("COMMIT;")
# 校验查询
sql.append(f"SELECT 'user' src, id, in_flow, out_flow, (in_flow+out_flow) total, flow quota FROM user WHERE id={uid};")
sql.append(
    f"SELECT 'user_tunnel' src, id, in_flow, out_flow, (in_flow+out_flow) total FROM user_tunnel WHERE user_id={uid};"
)
sql.append(
    f"SELECT 'forward' src, id, in_flow, out_flow, (in_flow+out_flow) total FROM forward WHERE user_id={uid};"
)
sql.append(
    f"SELECT id, flow hour_inc, total_flow, time FROM statistics_flow WHERE user_id={uid} ORDER BY id DESC LIMIT 3;"
)
open(os.environ["PLAN_SQL"], "w").write("\n".join(sql) + "\n")
print("\n".join(lines))
PY

# shellcheck: source plan
# shellcheck disable=SC1090
source "$PLAN_SH"

echo "======== PLAN ========"
cat "$PLAN_TXT"
echo "======== SQL (preview) ========"
cat "$PLAN_SQL"

if [[ "$EXECUTE" != "1" ]]; then
  log "dry-run 结束（未写库）。确认后加 --execute 执行。"
  rm -rf "$PLAN_DIR"
  exit 0
fi

if [[ "${PLAN_WILL_EXCEED}" == "1" ]]; then
  log "WARNING: 调账后可能超配额触发 Pause。继续执行（已指定 --execute）。"
fi

# ----------------------------- 备份 ------------------------------------------
TS="$(date +%Y%m%d_%H%M%S)"
# 文件名仅用安全字符
SAFE_USER="$(echo "$USER_NAME" | tr -cd 'A-Za-z0-9._-')"
BK_PREFIX="${BACKUP_ROOT}/${SAFE_USER}_flow_adjust_${TS}"
mkdir -p "$BACKUP_ROOT"

log "备份到 ${BK_PREFIX}_*"

docker exec "$MYSQL_CONTAINER" mysqldump -u"$DB_USER" -p"$DB_PASSWORD" \
  --single-transaction --no-create-info "$DB_NAME" user --where="id=${USER_ID}" \
  2>/dev/null > "${BK_PREFIX}_user.sql"
docker exec "$MYSQL_CONTAINER" mysqldump -u"$DB_USER" -p"$DB_PASSWORD" \
  --single-transaction --no-create-info "$DB_NAME" user_tunnel --where="user_id=${USER_ID}" \
  2>/dev/null > "${BK_PREFIX}_user_tunnel.sql"
docker exec "$MYSQL_CONTAINER" mysqldump -u"$DB_USER" -p"$DB_PASSWORD" \
  --single-transaction --no-create-info "$DB_NAME" forward --where="user_id=${USER_ID}" \
  2>/dev/null > "${BK_PREFIX}_forward.sql"
docker exec "$MYSQL_CONTAINER" mysqldump -u"$DB_USER" -p"$DB_PASSWORD" \
  --single-transaction --no-create-info "$DB_NAME" statistics_flow --where="user_id=${USER_ID}" \
  2>/dev/null > "${BK_PREFIX}_statistics_flow.sql"

cat "${BK_PREFIX}_user.sql" \
    "${BK_PREFIX}_user_tunnel.sql" \
    "${BK_PREFIX}_forward.sql" \
    "${BK_PREFIX}_statistics_flow.sql" \
  > "${BK_PREFIX}_all.sql"

cp "$PLAN_TXT" "${BK_PREFIX}_plan.txt"
cp "$PLAN_SQL" "${BK_PREFIX}_apply.sql"

# 回滚脚本：删除该用户相关行后灌回 mysqldump（仅含该用户数据）
cat > "${BK_PREFIX}_ROLLBACK.sh" <<ROLL
#!/usr/bin/env bash
# 回滚 ${USER_NAME} (id=${USER_ID}) 的流量调账
# 备份包: ${BK_PREFIX}_all.sql
set -euo pipefail
MYSQL_CONTAINER="${MYSQL_CONTAINER}"
DB_NAME="${DB_NAME}"
DB_USER="${DB_USER}"
DB_PASSWORD='${DB_PASSWORD}'
UID_NUM=${USER_ID}
BK_ALL="${BK_PREFIX}_all.sql"

echo "[\$(date '+%F %T')] 回滚用户 id=\${UID_NUM} from \${BK_ALL}"
[[ -f "\${BK_ALL}" ]] || { echo "backup missing"; exit 1; }

docker exec -i "\${MYSQL_CONTAINER}" mysql -u"\${DB_USER}" -p"\${DB_PASSWORD}" "\${DB_NAME}" <<SQL
START TRANSACTION;
DELETE FROM statistics_flow WHERE user_id=\${UID_NUM};
DELETE FROM forward WHERE user_id=\${UID_NUM};
DELETE FROM user_tunnel WHERE user_id=\${UID_NUM};
DELETE FROM user WHERE id=\${UID_NUM};
COMMIT;
SQL

docker exec -i "\${MYSQL_CONTAINER}" mysql -u"\${DB_USER}" -p"\${DB_PASSWORD}" "\${DB_NAME}" < "\${BK_ALL}"

echo "回滚完成，校验:"
docker exec "\${MYSQL_CONTAINER}" mysql -N -u"\${DB_USER}" -p"\${DB_PASSWORD}" "\${DB_NAME}" -e \
  "SELECT id,user,in_flow,out_flow,ROUND((in_flow+out_flow)/1073741824,4) GiB,flow FROM user WHERE id=\${UID_NUM};
   SELECT COUNT(*) stats_rows FROM statistics_flow WHERE user_id=\${UID_NUM};" 2>/dev/null
ROLL
chmod +x "${BK_PREFIX}_ROLLBACK.sh"

log "回滚命令: bash ${BK_PREFIX}_ROLLBACK.sh"

# ----------------------------- 执行事务 --------------------------------------
log "执行 apply.sql ..."
mysql_exec < "$PLAN_SQL"

# ----------------------------- 校验 ------------------------------------------
log "校验一致性..."
CHECK="$(mysql_q "
SELECT
  (SELECT in_flow+out_flow FROM user WHERE id=${USER_ID}) AS u,
  (SELECT IFNULL(SUM(in_flow+out_flow),0) FROM user_tunnel WHERE user_id=${USER_ID}) AS ut,
  (SELECT IFNULL(SUM(in_flow+out_flow),0) FROM forward WHERE user_id=${USER_ID}) AS fw,
  (SELECT IFNULL(total_flow,0) FROM statistics_flow WHERE user_id=${USER_ID} ORDER BY id DESC LIMIT 1) AS st
")"
read -r C_U C_UT C_FW C_ST <<<"$CHECK"
log "user_total=${C_U}  sum(user_tunnel)=${C_UT}  sum(forward)=${C_FW}  stats_latest_total=${C_ST}"

# 有 tunnel/forward 时要求三层 sum 一致；stats 允许与 live 差「未到整点的真实增量」
if [[ -n "$UT_TSV" && "$C_U" != "$C_UT" ]]; then
  die "校验失败: user_total != sum(user_tunnel) (${C_U} vs ${C_UT})"
fi
if [[ -n "$FW_TSV" && "$C_U" != "$C_FW" ]]; then
  die "校验失败: user_total != sum(forward) (${C_U} vs ${C_FW})"
fi

mysql_q "
SELECT id,user,flow AS quota_gb,in_flow,out_flow,
       ROUND((in_flow+out_flow)/1073741824,4) AS GiB
FROM user WHERE id=${USER_ID};
SELECT id,flow hour_inc_bytes, ROUND(total_flow/1073741824,4) total_GiB, time
FROM statistics_flow WHERE user_id=${USER_ID} ORDER BY id DESC LIMIT 3;
" | sed 's/\t/ | /g' || true

log "完成。备份前缀: ${BK_PREFIX}"
log "回滚: bash ${BK_PREFIX}_ROLLBACK.sh"

rm -rf "$PLAN_DIR"
exit 0
