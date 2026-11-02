#!/usr/bin/env bash
set -euo pipefail
ENGINE=kernel ACTION=install PREFIX=/ BUNDLE= RELEASE_URL= PIN= CONFIG= NO_SERVICE=0 OFFLINE=0 DRY=0 INSTALL_DEPS=0 ENABLE_FORWARDING=0 KEEP_FORWARDING=0 OLD_FORWARDING= FORWARDING_CHANGED=0
usage(){ echo 'install.sh --engine kernel|gost --bundle DIR|--release-url HTTPS --manifest-sha256 SHA256 --config FILE [--action install|uninstall] [--prefix DIR --no-service] [--offline] [--dry-run] [--install-deps] [--enable-forwarding]' >&2; exit 2; }
while (($#)); do
 case "$1" in
 --engine) ENGINE="$2";shift 2;; --action) ACTION="$2";shift 2;; --prefix) PREFIX="$2";shift 2;;
 --bundle) BUNDLE="$2";shift 2;; --release-url) RELEASE_URL="$2";shift 2;; --manifest-sha256) PIN="$2";shift 2;; --config) CONFIG="$2";shift 2;;
 --no-service) NO_SERVICE=1;shift;; --offline) OFFLINE=1;shift;; --dry-run) DRY=1;shift;; --install-deps) INSTALL_DEPS=1;shift;; --enable-forwarding) ENABLE_FORWARDING=1;shift;; *) usage;; esac
done
[[ "$(uname -s)" == Linux && "$PREFIX" == /* && "$PIN" =~ ^[a-fA-F0-9]{64}$ && -f "$CONFIG" ]] || usage
[[ "$ENGINE" == kernel || "$ENGINE" == gost ]] || usage
[[ "$ACTION" == install || "$ACTION" == uninstall ]] || usage
[[ -n "$BUNDLE" || "$RELEASE_URL" == https://* ]] || usage
[[ -z "$BUNDLE" || -z "$RELEASE_URL" ]] || usage
if (( ! DRY && EUID != 0 )); then echo 'Root is required for installation.' >&2;exit 1;fi
case "$(uname -m)" in x86_64) ARCH=amd64;; aarch64|arm64) ARCH=arm64;; *) echo 'Unsupported architecture' >&2;exit 1;;esac
PREFIX="${PREFIX%/}"
STAGE="$(mktemp -d)"
cleanup(){
 local code=$?
 if (( FORWARDING_CHANGED && ! KEEP_FORWARDING ));then
  sysctl -w "net.ipv4.ip_forward=$OLD_FORWARDING" >/dev/null 2>&1 || true
  if [[ -f "$STAGE/previous-forwarding.conf" ]];then cp -p "$STAGE/previous-forwarding.conf" /etc/sysctl.d/90-flux-agent-forwarding.conf;else rm -f /etc/sysctl.d/90-flux-agent-forwarding.conf;fi
 fi
 rm -rf -- "$STAGE"
 return "$code"
}
trap cleanup EXIT
fetch(){ local file="$1";if [[ -n "$BUNDLE" ]];then cp -- "$BUNDLE/$file" "$STAGE/$file";else curl --fail --location --retry 2 --connect-timeout 10 --max-time 60 --proto '=https' --proto-redir '=https' "$RELEASE_URL/$file" -o "$STAGE/$file";fi; }
fetch SHA256SUMS
ACTUAL_PIN="$(sha256sum "$STAGE/SHA256SUMS" | cut -d' ' -f1)"
[[ "$ACTUAL_PIN" == "${PIN,,}" ]] || { echo 'Pinned manifest checksum mismatch' >&2;exit 1; }
verified(){ local file="$1";fetch "$file";local line;line="$(awk -v file="$file" '$2==file && $1 ~ /^[0-9a-f]+$/ {print}' "$STAGE/SHA256SUMS")";[[ ${#line} -gt 64 && "$(printf '%s\n' "$line" | wc -l)" -eq 1 ]] || { echo "Missing checksum: $file" >&2;exit 1; };(cd "$STAGE";printf '%s\n' "$line" | sha256sum --strict -c - >/dev/null); }
verified "flux-agent-linux-$ARCH";chmod 0755 "$STAGE/flux-agent-linux-$ARCH";TOOL="$STAGE/flux-agent-linux-$ARCH"
if [[ "$ENGINE" == kernel ]];then
 UNIT=flux-agent.service;NAME=flux-agent;DIRECTORY="$PREFIX/etc/flux-agent";BINARY="$PREFIX/usr/local/bin/flux-agent";STATE_DIRECTORY="$PREFIX/var/lib/flux-agent";STATE="$STATE_DIRECTORY/state.json"
 verified flux-agent.service;verified flux-kernel.service;verified flux-agent-tmpfiles.conf
 verified "gost-managed-linux-$ARCH";chmod 0755 "$STAGE/gost-managed-linux-$ARCH"
 MANAGED_BINARY="$PREFIX/usr/local/lib/flux-agent/gost-managed"
 MANAGED_SHA="$(sha256sum "$STAGE/gost-managed-linux-$ARCH" | cut -d' ' -f1)"
 "$TOOL" --config "$CONFIG" --write-managed-config "$STAGE/managed-config.json" --managed-binary "$MANAGED_BINARY" --managed-sha256 "$MANAGED_SHA"
 CONFIG="$STAGE/managed-config.json"
 "$TOOL" --check-config --expected-state-path "$STATE" --config "$CONFIG" >/dev/null
else
 UNIT=gost.service;NAME=gost;DIRECTORY="$PREFIX/etc/gost";BINARY="$DIRECTORY/gost";STATE_DIRECTORY="$PREFIX/var/lib/gost-installer";STATE="$STATE_DIRECTORY/unused"
 verified "gost-linux-$ARCH";verified gost-wss-evidence.json
 "$TOOL" --check-gost-config --config "$CONFIG" >/dev/null
fi
if (( DRY ));then printf 'Verified %s package. Would %s %s under %s; service=%s; no changes made.\n' "$ENGINE" "$ACTION" "$NAME" "${PREFIX:-/}" "$((1-NO_SERVICE))";exit 0;fi
if (( INSTALL_DEPS ));then
 MISSING=0
 for tool in nft conntrack ip curl;do command -v "$tool" >/dev/null || MISSING=1;done
 if (( MISSING ));then
  if command -v apt-get >/dev/null;then apt-get update;DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends nftables conntrack iproute2 ca-certificates curl
  elif command -v dnf >/dev/null;then dnf install -y nftables conntrack-tools iproute ca-certificates curl
  elif command -v yum >/dev/null;then yum install -y nftables conntrack-tools iproute ca-certificates curl
  else echo '无法自动安装依赖：请先安装 nftables、conntrack、iproute 和 curl，再重试。' >&2;exit 1;fi
 fi
fi
if (( ENABLE_FORWARDING )) && [[ "$ENGINE" == kernel && "$ACTION" == install ]];then
 [[ -z "$PREFIX" && "$NO_SERVICE" == 0 ]] || { echo 'Automatic forwarding setup is only available for a normal host installation.' >&2;exit 1; }
 OLD_FORWARDING="$(cat /proc/sys/net/ipv4/ip_forward)"
 if [[ "$OLD_FORWARDING" != 1 || ! -f /etc/sysctl.d/90-flux-agent-forwarding.conf ]];then
  [[ ! -L /etc/sysctl.d/90-flux-agent-forwarding.conf ]] || { echo 'Refusing a symbolic-link sysctl configuration.' >&2;exit 1; }
  [[ ! -f /etc/sysctl.d/90-flux-agent-forwarding.conf ]] || cp -p /etc/sysctl.d/90-flux-agent-forwarding.conf "$STAGE/previous-forwarding.conf"
  FORWARDING_CHANGED=1
  install -d -m 0755 /etc/sysctl.d
  printf '%s\n' '# Flux Agent IPv4 forwarding' 'net.ipv4.ip_forward = 1' >/etc/sysctl.d/90-flux-agent-forwarding.conf
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
 fi
fi
[[ ! -L "$BINARY" && ! -L "$DIRECTORY/config.json" ]] || { echo 'Refusing symbolic-link installation targets.' >&2;exit 1; }
if [[ "$ENGINE" == kernel ]];then "$TOOL" --preflight --config "$CONFIG" >/dev/null;fi
EFFECTIVE_CONFIG="$CONFIG"
if [[ "$ENGINE" == kernel ]] && (( ! NO_SERVICE ));then "$TOOL" --config "$CONFIG" --write-service-config "$STAGE/service-config.json";EFFECTIVE_CONFIG="$STAGE/service-config.json";fi
if [[ -f "$DIRECTORY/config.json" ]];then "$TOOL" --config "$CONFIG" --same-node-config "$DIRECTORY/config.json" >/dev/null;fi
if [[ "$ACTION" == install && -f "$BINARY" && -f "$DIRECTORY/config.json" ]];then
 CURRENT="$(sha256sum "$BINARY" | cut -d' ' -f1)";EXPECTED="$(sha256sum "$STAGE/${ENGINE/kernel/flux-agent}-linux-$ARCH" | cut -d' ' -f1)"
 MANAGED_MATCH=1
 if [[ "$ENGINE" == kernel ]] && { [[ ! -f "$MANAGED_BINARY" ]] || [[ "$(sha256sum "$MANAGED_BINARY" | cut -d' ' -f1)" != "$MANAGED_SHA" ]]; };then MANAGED_MATCH=0;fi
 if (( MANAGED_MATCH )) && [[ "$CURRENT" == "$EXPECTED" && ! -e "$STATE.maintenance" && ! -e "$STATE.journal" ]] && cmp -s "$EFFECTIVE_CONFIG" "$DIRECTORY/config.json";then KEEP_FORWARDING=1;echo 'Verified version and configuration already installed.';exit 0;fi
fi
install -d -m 0700 "$DIRECTORY" "$STATE_DIRECTORY" "$STATE_DIRECTORY/backups"
BACKUP="$STATE_DIRECTORY/backups/$(date -u +%Y%m%dT%H%M%SZ)-$$"
EXISTING=0;[[ ! -f "$BINARY" ]] || EXISTING=1
if (( ! NO_SERVICE ));then command -v systemctl >/dev/null || { echo '此安装方式需要 systemd，请在支持 systemd 的 Linux 上安装。' >&2;exit 1; };systemctl stop "$UNIT" 2>/dev/null || true;if [[ "$ENGINE" == kernel ]];then systemctl stop flux-kernel.service 2>/dev/null || true;fi;fi
FLAGS=();(( ! OFFLINE )) || FLAGS+=(--offline)
rollback(){
 local code=$?
 trap - ERR
 if (( ! NO_SERVICE ));then systemctl stop "$UNIT" 2>/dev/null || true;if [[ "$ENGINE" == kernel ]];then systemctl stop flux-kernel.service 2>/dev/null || true;fi;fi
 echo 'Installation failed; restoring the verified previous version where available.' >&2
 if [[ -f "$BACKUP/previous.bin" ]];then
  if [[ "$ENGINE" == kernel && -f "$BACKUP/manifest.json" ]];then
   "$TOOL" --config "$DIRECTORY/config.json" --maintenance rollback --backup-dir "$BACKUP" || { echo "Recovery required; forwarding remains blocked. Backup: $BACKUP" >&2;exit "$code"; }
  fi
  (cd "$BACKUP";sha256sum -c previous.sha256 >/dev/null) || exit "$code"
  cp -p -- "$BACKUP/previous.bin" "$BINARY"
  if [[ "$ENGINE" == kernel && -f "$BACKUP/previous-managed.bin" ]];then (cd "$BACKUP";sha256sum -c previous-managed.sha256 >/dev/null) || exit "$code";cp -p "$BACKUP/previous-managed.bin" "$MANAGED_BINARY";fi
  [[ ! -f "$BACKUP/previous-config.json" ]] || cp -p "$BACKUP/previous-config.json" "$DIRECTORY/config.json"
  if (( ! NO_SERVICE ));then
   if [[ -s "$BACKUP/previous-units.sha256" ]];then (cd "$BACKUP";sha256sum -c previous-units.sha256 >/dev/null) || exit "$code";fi
   for previous_unit in "$UNIT" flux-kernel.service;do
    if [[ -f "$BACKUP/previous-$previous_unit" ]];then cp -p "$BACKUP/previous-$previous_unit" "$PREFIX/etc/systemd/system/$previous_unit";else rm -f -- "$PREFIX/etc/systemd/system/$previous_unit";fi
   done
   systemctl daemon-reload
  fi
  if (( ! NO_SERVICE && ! OFFLINE ));then if [[ "$ENGINE" == kernel ]];then systemctl start flux-kernel.service || true;fi;systemctl start "$UNIT" || true;fi
 fi
 exit "$code"
}
trap rollback ERR
RESUMED=0
if [[ "$ENGINE" == kernel && -f "$STATE.maintenance" ]];then
 BACKUP="$("$TOOL" --config "$DIRECTORY/config.json" --maintenance resume --print-backup-path "${FLAGS[@]}")"
 RESUMED=1
else
 mkdir -m 0700 "$BACKUP"
fi
if (( EXISTING )) && [[ ! -f "$BACKUP/previous.bin" ]];then
 cp -p -- "$BINARY" "$BACKUP/previous.bin"
 (cd "$BACKUP";sha256sum previous.bin > previous.sha256)
fi
[[ ! -f "$DIRECTORY/config.json" || -f "$BACKUP/previous-config.json" ]] || cp -p "$DIRECTORY/config.json" "$BACKUP/previous-config.json"
if (( ! NO_SERVICE ));then
 for previous_unit in "$UNIT" flux-kernel.service;do
  if [[ -f "$PREFIX/etc/systemd/system/$previous_unit" && ! -f "$BACKUP/previous-$previous_unit" ]];then cp -p "$PREFIX/etc/systemd/system/$previous_unit" "$BACKUP/previous-$previous_unit";fi
 done
 (cd "$BACKUP";find . -maxdepth 1 -name 'previous-*.service' -type f -exec sha256sum '{}' ';' > previous-units.sha256)
fi
if [[ "$ENGINE" == kernel && -f "$MANAGED_BINARY" && ! -f "$BACKUP/previous-managed.bin" ]];then cp -p "$MANAGED_BINARY" "$BACKUP/previous-managed.bin";(cd "$BACKUP";sha256sum previous-managed.bin > previous-managed.sha256);fi
SOURCE="$STAGE/flux-agent-linux-$ARCH";[[ "$ENGINE" == kernel ]] || SOURCE="$STAGE/gost-linux-$ARCH"
if [[ "$ACTION" == install ]];then
 if [[ "$ENGINE" == kernel ]];then
 install -d -m 0755 "$(dirname "$BINARY")" "$(dirname "$MANAGED_BINARY")"
 install -m 0755 "$STAGE/gost-managed-linux-$ARCH" "$MANAGED_BINARY"
 fi
 install -m 0755 "$SOURCE" "$BINARY.new";mv -f -- "$BINARY.new" "$BINARY"
 install -m 0600 "$EFFECTIVE_CONFIG" "$DIRECTORY/config.json"
fi
if [[ "$ENGINE" == kernel && -f "$STATE" ]] && (( ! RESUMED ));then
 MODE=migrate;[[ "$ACTION" != uninstall ]] || MODE=uninstall
 "$TOOL" --config "$DIRECTORY/config.json" --maintenance "$MODE" --backup-dir "$BACKUP" "${FLAGS[@]}"
fi
if [[ "$ACTION" == uninstall ]];then
 if (( ! NO_SERVICE ));then systemctl disable "$UNIT" 2>/dev/null || true;if [[ "$ENGINE" == kernel ]];then systemctl disable flux-kernel.service 2>/dev/null || true;rm -f -- "$PREFIX/etc/systemd/system/flux-kernel.service";fi;rm -f -- "$PREFIX/etc/systemd/system/$UNIT";if [[ "$ENGINE" == kernel ]];then rm -f -- "$PREFIX/etc/tmpfiles.d/flux-agent.conf";fi;systemctl daemon-reload;fi
 rm -f -- "$BINARY"
 if [[ "$ENGINE" == kernel ]];then rm -f -- "$MANAGED_BINARY";fi
 printf 'Uninstalled %s. State, credentials and recoverable backup retained at %s.\n' "$NAME" "$BACKUP";exit 0
fi
if [[ "$ENGINE" == gost ]];then [[ -f "$DIRECTORY/gost.json" ]] || printf '{}\n' > "$DIRECTORY/gost.json";chmod 0600 "$DIRECTORY/gost.json";fi
if (( ! NO_SERVICE ));then
 install -d -m 0755 "$PREFIX/etc/systemd/system"
 if [[ "$ENGINE" == kernel ]];then
 install -d -m 0755 "$PREFIX/etc/tmpfiles.d" "$PREFIX/run"
 install -m 0644 "$STAGE/flux-agent-tmpfiles.conf" "$PREFIX/etc/tmpfiles.d/flux-agent.conf"
 [[ -e "$PREFIX/run/xtables.lock" ]] || install -m 0600 /dev/null "$PREFIX/run/xtables.lock"
 getent group flux-agent >/dev/null || groupadd --system flux-agent
 getent passwd flux-agent >/dev/null || useradd --system --gid flux-agent --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin flux-agent
 install -m 0644 "$STAGE/flux-kernel.service" "$PREFIX/etc/systemd/system/flux-kernel.service"
 install -m 0644 "$STAGE/flux-agent.service" "$PREFIX/etc/systemd/system/$UNIT";else
 cat > "$PREFIX/etc/systemd/system/$UNIT" <<'UNIT'
[Unit]
Description=Flux verified GOST node
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
WorkingDirectory=/etc/gost
ExecStart=/etc/gost/gost
Restart=on-failure
RestartSec=3
UMask=0077
NoNewPrivileges=true
[Install]
WantedBy=multi-user.target
UNIT
 fi
 SERVICE_STARTED_AT="$(date +%s)"
 systemctl daemon-reload;if [[ "$ENGINE" == kernel ]];then systemctl enable flux-kernel.service;systemctl start flux-kernel.service;fi;systemctl enable "$UNIT";systemctl start "$UNIT"
 if [[ "$ENGINE" == kernel ]];then
  READY=0
  for _ in {1..40};do if "$BINARY" --ready --config "$DIRECTORY/config.json" >/dev/null 2>&1;then READY=1;break;fi;sleep 1;done
  (( READY )) || { echo 'Agent did not confirm a fresh authenticated panel report.' >&2;false; }
 else
  READY=0
  INVOCATION="$(systemctl show "$UNIT" -p InvocationID --value 2>/dev/null || true)"
  JOURNAL_SCOPE=(--since "@$SERVICE_STARTED_AT")
  [[ ! "$INVOCATION" =~ ^[a-fA-F0-9]{32}$ ]] || JOURNAL_SCOPE=("_SYSTEMD_INVOCATION_ID=$INVOCATION")
  for _ in {1..40};do
   if systemctl is-active --quiet "$UNIT" && journalctl -u "$UNIT" "${JOURNAL_SCOPE[@]}" -n 100 --no-pager | grep -Eq 'WebSocket连接建立成功|WebSocket connection';then READY=1;break;fi
   sleep 1
  done
  (( READY )) || { echo '节点未完成面板注册，请检查面板地址和连接状态。' >&2;false; }
 fi
fi
trap - ERR
KEEP_FORWARDING=1
printf 'Installed pinned %s build. Backup: %s. Migrated forwards remain paused until explicit panel resume.\n' "$NAME" "$BACKUP"
