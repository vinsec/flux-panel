#!/bin/bash
set -euo pipefail
suite="$1"
case "$suite" in p1-kernel|p1-faults|p1-restart|p1-metrics|p1-soak|fusion-perf|p2-traffic|p2-faults|p2-regression|p2-confirmation) ;; *) exit 2;;esac
if [[ "${IPTABLES_BACKEND:-nft}" == legacy ]];then backend=legacy;else backend=nft;fi
update-alternatives --set iptables "/usr/sbin/iptables-$backend" >/dev/null
update-alternatives --set ip6tables "/usr/sbin/ip6tables-$backend" >/dev/null
out="/opt/flux-p1/evidence/$suite-${IPTABLES_BACKEND:-nft}"
mkdir -p "$out" /evidence
export FLUX_TEST_EVIDENCE="$out"
script="/opt/flux-p1/tests/$suite.py"
if [[ "$suite" == p2-regression || "$suite" == p2-confirmation ]];then script="/opt/flux-p1/tests/benchmark/$suite.py";fi
exec unshare --mount --net --fork bash -c 'mount --make-rprivate /; mount -t tmpfs tmpfs /run/netns; mount -t tmpfs tmpfs /tmp; mount --bind "$FLUX_TEST_EVIDENCE" /evidence; exec python3 "$1"' bash "$script" > "$out/console.txt" 2>&1
