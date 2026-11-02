#!/usr/bin/env bash
# Run from a checked-out Go branch or a verified source bundle. No remote scripts.
set -euo pipefail
umask 077
ROOT="$(cd "$(dirname "$0")" && pwd)"
usage() {
 cat <<'HELP'
Usage: ./panel_install.sh install|update|migrate|backup|logs|uninstall [--no-build]
  install    Initialize an EMPTY database and start the Go panel/frontend.
  update     Stop the existing Go writer, apply forward migrations, then restart.
  migrate    Explicitly stop the Go backend and apply forward migrations only.
  backup     Write a consistent SQL backup under ./backups/ (data is not deleted).
  uninstall  Remove project containers/network; keep the database volume and .env.
  --no-build Use already loaded local images (offline/verified release deployment).
Set COMPOSE_PROJECT_NAME and PANEL_COMPOSE_FILE to select a dedicated deployment.
HELP
}
ACTION="${1:-help}";[[ $# == 0 ]] || shift
NO_BUILD=0
for arg in "$@";do case "$arg" in --no-build)NO_BUILD=1;; *)usage >&2;exit 2;;esac;done
case "$ACTION" in help|--help|-h)usage;exit 0;; install|update|migrate|backup|logs|uninstall);; *)usage >&2;exit 2;;esac
command -v docker >/dev/null || { echo 'Docker with Compose v2 is required.' >&2;exit 1; }
docker compose version >/dev/null
COMPOSE_FILE="${PANEL_COMPOSE_FILE:-$ROOT/docker-compose.yml}"
[[ -f "$COMPOSE_FILE" ]] || { echo 'Compose file not found.' >&2;exit 1; }
ENV_FILE="$ROOT/.env"
MARKER="$ROOT/.flux-panel-go-install"
if [[ "$ACTION" == install && ! -f "$ENV_FILE" ]];then
 command -v openssl >/dev/null
 cat >"$ENV_FILE" <<EOF
DB_NAME=flux
DB_USER=flux
DB_PASSWORD=$(openssl rand -hex 24)
JWT_SECRET=$(openssl rand -hex 48)
FRONTEND_PORT=6366
BACKEND_PORT=6365
PANEL_BIND=127.0.0.1
TZ=Asia/Shanghai
EOF
fi
[[ -f "$ENV_FILE" ]] || { echo 'Copy .env.example to .env and fill in the configuration first.' >&2;exit 1; }
DC=(docker compose --project-directory "$ROOT" --env-file "$ENV_FILE" -p "${COMPOSE_PROJECT_NAME:-flux-panel}" -f "$COMPOSE_FILE")
"${DC[@]}" config --quiet
build_images() { if [[ "$NO_BUILD" == 0 ]];then "${DC[@]}" build backend frontend;fi; }
case "$ACTION" in
 install)
  [[ ! -f "$MARKER" ]] || { echo 'This Go installation already exists; use update.' >&2;exit 1; }
  build_images
  "${DC[@]}" up -d --wait mysql
  "${DC[@]}" run --rm --no-deps backend migrate --init
  touch "$MARKER"
  "${DC[@]}" up -d --no-build --wait backend frontend
  echo 'Go panel ready. Default login: admin_user / admin_user. Change the password after login.'
  ;;
 update)
  [[ -f "$MARKER" ]] || { echo '旧安装不能直接执行 update，请先按 deploy/migrate-existing.md 制定迁移步骤。' >&2;exit 1; }
  build_images
  "${DC[@]}" stop backend
  "${DC[@]}" run --rm --no-deps backend migrate
  "${DC[@]}" up -d --no-build --wait backend frontend
  ;;
 migrate)
  "${DC[@]}" stop backend
  "${DC[@]}" run --rm --no-deps backend migrate
  echo 'Migrations complete; backend remains stopped. Start it only after confirming writer ownership.'
  ;;
 backup)
  mkdir -p "$ROOT/backups"
  TARGET="$ROOT/backups/flux-$(date -u +%Y%m%dT%H%M%SZ).sql"
  "${DC[@]}" exec -T mysql sh -c 'MYSQL_PWD="$MYSQL_PASSWORD" exec mysqldump --single-transaction --no-tablespaces -u"$MYSQL_USER" "$MYSQL_DATABASE"' >"$TARGET"
  echo "Backup: $TARGET"
  ;;
 logs) "${DC[@]}" logs --tail=100 -f backend frontend;;
 uninstall) "${DC[@]}" down;echo 'Database volume and .env retained.';;
esac
