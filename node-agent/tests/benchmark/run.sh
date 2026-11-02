#!/usr/bin/env bash
set -euo pipefail
ENDPOINT="$(docker context inspect --format '{{(index .Endpoints "docker").Host}}')"
[[ "$ENDPOINT" == unix://* && "${DOCKER_HOST:-unix://}" == unix://* ]] || { echo 'Use a local Docker socket on the selected isolated test host.' >&2; exit 2; }
# Run on the Linux host containing the previously verified artifacts. No public
# interfaces or production rules are used by the benchmark container.
ROOT="${FLUX_BENCH_ROOT:-/root/flux-forward-benchmark-20261025}"
[[ "$ROOT" == /* && "$ROOT" != / ]] || exit 2
NAME="flux-forward-benchmark-$$"
EVIDENCE="${FLUX_BENCH_EVIDENCE:-$ROOT/evidence}"
mkdir -p "$ROOT/build" "$EVIDENCE"
for binary in flux-agent gost bench-peer; do
  [[ -x "$ROOT/build/$binary" ]] || { echo "Missing executable benchmark artifact: $binary" >&2; exit 2; }
done
if [[ "${FLUX_BENCH_V2:-0}" == 1 ]]; then
  [[ -x "$ROOT/build/flux-agent-v2" ]] || { echo 'Missing executable comparison Agent' >&2; exit 2; }
fi
cleanup(){ docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM
docker create --name "$NAME" --network none --memory=512m --cpus=.75 --cpu-shares=128 --pids-limit=256 --ulimit nofile=8192:8192 \
  --cap-add NET_ADMIN --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined \
  -v "$ROOT/build:/build:ro" -v "$ROOT/code:/code:ro" -v "$EVIDENCE:/evidence" \
  -e FLUX_BENCH_PAIR_CPU_ONLY="${FLUX_BENCH_PAIR_CPU_ONLY:-0}" -e FLUX_BENCH_PACED_SECONDS="${FLUX_BENCH_PACED_SECONDS:-}" \
  -e FLUX_BENCH_CREDIT_STRESS="${FLUX_BENCH_CREDIT_STRESS:-1}" -e FLUX_BENCH_FOUNDATION="${FLUX_BENCH_FOUNDATION:-0}" -e FLUX_BENCH_FOUNDATION_CREDIT_ONLY="${FLUX_BENCH_FOUNDATION_CREDIT_ONLY:-0}" -e FLUX_BENCH_PACED_ONLY="${FLUX_BENCH_PACED_ONLY:-0}" -e FLUX_BENCH_V2="${FLUX_BENCH_V2:-0}" -e FLUX_BENCH_SCALE_ONLY="${FLUX_BENCH_SCALE_ONLY:-0}" -e FLUX_BENCH_FIRST_ONLY="${FLUX_BENCH_FIRST_ONLY:-0}" -e FLUX_BENCH_STRICT_BYTES="${FLUX_BENCH_STRICT_BYTES:-67108864}" -e FLUX_BENCH_STRICT="${FLUX_BENCH_STRICT:-0}" -e FLUX_BENCH_BYTE_LIMIT="${FLUX_BENCH_BYTE_LIMIT:-3221225472}" -e FLUX_BENCH_EXTRA="${FLUX_BENCH_EXTRA:-0}" -e FLUX_BENCH_PRIOR_BYTES="${FLUX_BENCH_PRIOR_BYTES:-0}" -e FLUX_BENCH_HOT_FIRST="${FLUX_BENCH_HOT_FIRST:-0}" \
  "${FLUX_BENCH_IMAGE:-flux-forward-benchmark:local}" nice -n 19 python3 /code/benchmark.py >"$ROOT/container-id.txt"
docker start "$NAME" >/dev/null
deadline=$((SECONDS+960))
while [[ "$(docker inspect "$NAME" --format '{{.State.Status}}')" == running ]]; do
  (( SECONDS < deadline )) || { echo 'benchmark deadline exceeded' >&2; exit 1; }
  sleep 1
done
status="$(docker inspect "$NAME" --format '{{.State.ExitCode}}')"
docker logs "$NAME" 2>&1 | tee "$EVIDENCE/console.txt"
exit "$status"
