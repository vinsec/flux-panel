#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BACKEND="${1:-native}"
[[ "$BACKEND" == native ]] || { echo 'usage: run-local.sh [native]' >&2; exit 2; }
ENDPOINT="$(docker context inspect --format '{{(index .Endpoints "docker").Host}}')"
[[ "$ENDPOINT" == unix://* && "${DOCKER_HOST:-unix://}" == unix://* ]] || { echo 'Only a local Docker daemon is allowed for this verifier.' >&2; exit 2; }
RUN_ID="flux-native-test-$$"
WORK="${FLUX_TEST_WORK:-$ROOT/node-agent/.test-work/$BACKEND}"
mkdir -p "$WORK/build" "$WORK/evidence"
if [[ -n "${FLUX_TEST_GOST:-}" ]]; then
  [[ -f "$FLUX_TEST_GOST" ]] || { echo 'FLUX_TEST_GOST must point to a verified GOST binary' >&2; exit 2; }
  install -m 755 "$FLUX_TEST_GOST" "$WORK/build/gost"
fi
case "$(docker info --format '{{.Architecture}}')" in aarch64|arm64) ARCH=arm64;; x86_64|amd64) ARCH=amd64;; *) exit 2;; esac
IMAGE="${FLUX_TEST_IMAGE:-flux-native-test:local}"
if [[ "${FLUX_TEST_SKIP_BUILD:-0}" != 1 ]]; then
  (cd "$ROOT/panel-go" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -o "$WORK/build/flux-panel" ./cmd/panel)
  (cd "$ROOT/node-agent" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -o "$WORK/build/flux-agent" ./cmd/flux-agent)
  docker build -q -t "$IMAGE" -f "$ROOT/node-agent/tests/Linux.Dockerfile" "$ROOT"
else
  [[ -x "$WORK/build/flux-agent" && -x "$WORK/build/flux-panel" ]] || exit 2
fi
cleanup() {
  docker inspect "$RUN_ID-mysql" --format '{{json .State}}' >"$WORK/evidence/mysql-state.json" 2>/dev/null || true
  docker logs "$RUN_ID-mysql" >"$WORK/evidence/mysql.log" 2>&1 || true
  docker rm -f "$RUN_ID-runner" "$RUN_ID-mysql" >/dev/null 2>&1 || true
  docker network rm "$RUN_ID" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM
wait_container() {
  local name="$1" state
  local deadline=$((SECONDS + 900))
  while (( SECONDS < deadline )); do
    state="$(docker inspect "$name" --format '{{.State.Status}}')"
    if [[ "$state" == exited ]]; then docker inspect "$name" --format '{{.State.ExitCode}}'; return; fi
    sleep 1
  done
  echo "test container deadline exceeded: $name" >&2
  return 1
}
docker network create --internal --label flux-native-test=true "$RUN_ID" >/dev/null
docker create --name "$RUN_ID-mysql" --network "$RUN_ID" --network-alias mysql \
  --memory="${FLUX_TEST_MYSQL_MEMORY:-384m}" --tmpfs /var/lib/mysql:rw,size=256m \
  -e MYSQL_ROOT_PASSWORD=isolated-test-db-only -e MYSQL_ROOT_HOST=% -e MYSQL_DATABASE=flux_test \
  "${FLUX_TEST_MYSQL_IMAGE:-mysql:8.2}" --innodb-buffer-pool-size=32M --innodb-log-file-size=8M --key-buffer-size=8M --performance-schema=OFF --max-connections=20 >"$WORK/evidence/mysql-container.txt"
python3 "$ROOT/node-agent/tests/start-container.py" "$RUN_ID-mysql"
docker create --name "$RUN_ID-runner" --cap-add NET_ADMIN --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined --network "$RUN_ID" --memory=640m --cpus=1 \
  -e IPTABLES_BACKEND=nft -e FLUX_TEST_SCALE="${FLUX_TEST_SCALE:-0}" -v "$ROOT:/repo:ro" -v "$WORK/build:/build:ro" -v "$WORK/evidence:/evidence" \
  "$IMAGE" python3 /repo/node-agent/tests/integration.py >"$WORK/evidence/runner-container.txt"
python3 "$ROOT/node-agent/tests/start-container.py" "$RUN_ID-runner"
STATUS="$(wait_container "$RUN_ID-runner")"
docker logs "$RUN_ID-runner" 2>&1 | tee "$WORK/evidence/console.txt"
[[ "$STATUS" == 0 ]] || exit "$STATUS"
echo "Evidence: $WORK/evidence"
