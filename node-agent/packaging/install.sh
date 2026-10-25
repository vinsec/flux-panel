#!/usr/bin/env bash
set -euo pipefail
ENGINE=iptables ACTION=install PREFIX=/ BUNDLE= RELEASE_URL= PIN= CONFIG= NO_SERVICE=0 OFFLINE=0 DRY=0 INSTALL_DEPS=0
usage(){ echo 'install.sh --engine iptables|gost --bundle DIR|--release-url HTTPS --manifest-sha256 SHA256 --config FILE [--action install|uninstall] [--prefix DIR --no-service] [--offline] [--dry-run] [--install-deps]' >&2; exit 2; }
while (($#)); do
 case "$1" in
 --engine) ENGINE="$2";shift 2;; --action) ACTION="$2";shift 2;; --prefix) PREFIX="$2";shift 2;;
 --bundle) BUNDLE="$2";shift 2;; --release-url) RELEASE_URL="$2";shift 2;; --manifest-sha256) PIN="$2";shift 2;; --config) CONFIG="$2";shift 2;;
 --no-service) NO_SERVICE=1;shift;; --offline) OFFLINE=1;shift;; --dry-run) DRY=1;shift;; --install-deps) INSTALL_DEPS=1;shift;; *) usage;; esac
done
[[ "$(uname -s)" == Linux && "$PREFIX" == /* && "$PIN" =~ ^[a-fA-F0-9]{64}$ && -f "$CONFIG" ]] || usage
[[ "$ENGINE" == iptables || "$ENGINE" == gost ]] || usage
[[ "$ACTION" == install || "$ACTION" == uninstall ]] || usage
[[ -n "$BUNDLE" || "$RELEASE_URL" == https://* ]] || usage
[[ -z "$BUNDLE" || -z "$RELEASE_URL" ]] || usage
if (( ! DRY && EUID != 0 )); then echo 'Root is required for installation.' >&2;exit 1;fi
case "$(uname -m)" in x86_64) ARCH=amd64;; aarch64|arm64) ARCH=arm64;; *) echo 'Unsupported architecture' >&2;exit 1;;esac
PREFIX="${PREFIX%/}"
STAGE="$(mktemp -d)";trap 'rm -rf -- "$STAGE"' EXIT
fetch(){ local file="$1";if [[ -n "$BUNDLE" ]];then cp -- "$BUNDLE/$file" "$STAGE/$file";else curl --fail --location --retry 2 --connect-timeout 10 --max-time 60 --proto '=https' --proto-redir '=https' "$RELEASE_URL/$file" -o "$STAGE/$file";fi; }
fetch SHA256SUMS
ACTUAL_PIN="$(sha256sum "$STAGE/SHA256SUMS" | cut -d' ' -f1)"
[[ "$ACTUAL_PIN" == "${PIN,,}" ]] || { echo 'Pinned manifest checksum mismatch' >&2;exit 1; }
verified(){ local file="$1";fetch "$file";local line;line="$(awk -v file="$file" '$2==file && $1 ~ /^[0-9a-f]+$/ {print}' "$STAGE/SHA256SUMS")";[[ ${#line} -gt 64 && "$(printf '%s\n' "$line" | wc -l)" -eq 1 ]] || { echo "Missing checksum: $file" >&2;exit 1; };(cd "$STAGE";printf '%s\n' "$line" | sha256sum --strict -c - >/dev/null); }
verified "flux-agent-linux-$ARCH";chmod 0755 "$STAGE/flux-agent-linux-$ARCH";TOOL="$STAGE/flux-agent-linux-$ARCH"
if [[ "$ENGINE" == iptables ]];then
 UNIT=flux-agent.service;NAME=flux-agent;DIRECTORY="$PREFIX/etc/flux-agent";BINARY="$PREFIX/usr/local/bin/flux-agent";STATE_DIRECTORY="$PREFIX/var/lib/flux-agent";STATE="$STATE_DIRECTORY/state.json"
 verified flux-agent.service;verified flux-agent-tmpfiles.conf
 "$TOOL" --check-config --expected-state-path "$STATE" --config "$CONFIG" >/dev/null
else
 UNIT=gost.service;NAME=gost;DIRECTORY="$PREFIX/etc/gost";BINARY="$DIRECTORY/gost";STATE_DIRECTORY="$PREFIX/var/lib/gost-installer";STATE="$STATE_DIRECTORY/unused"
 verified "gost-linux-$ARCH";verified gost-wss-evidence.json
 "$TOOL" --check-gost-config --config "$CONFIG" >/dev/null
fi
if (( DRY ));then printf 'Verified %s package. Would %s %s under %s; service=%s; no changes made.\n' "$ENGINE" "$ACTION" "$NAME" "${PREFIX:-/}" "$((1-NO_SERVICE))";exit 0;fi
if (( INSTALL_DEPS ));then command -v apt-get >/dev/null || { echo 'Install the documented dependencies for this distribution.' >&2;exit 1; };apt-get update;DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends iptables ipset nftables conntrack ca-certificates curl;fi
[[ ! -L "$BINARY" && ! -L "$DIRECTORY/config.json" ]] || { echo 'Refusing symbolic-link installation targets.' >&2;exit 1; }
if [[ "$ENGINE" == iptables ]];then "$TOOL" --preflight --config "$CONFIG" >/dev/null;fi
if [[ -f "$DIRECTORY/config.json" ]] && ! cmp -s "$CONFIG" "$DIRECTORY/config.json";then echo 'Existing node configuration differs; migrate identity explicitly before replacing it.' >&2;exit 1;fi
if [[ "$ACTION" == install && -f "$BINARY" && -f "$DIRECTORY/config.json" ]];then
 CURRENT="$(sha256sum "$BINARY" | cut -d' ' -f1)";EXPECTED="$(sha256sum "$STAGE/${ENGINE/iptables/flux-agent}-linux-$ARCH" | cut -d' ' -f1)"
 if [[ "$CURRENT" == "$EXPECTED" && ! -e "$STATE.maintenance" && ! -e "$STATE.journal" ]];then echo 'Verified version and configuration already installed.';exit 0;fi
fi
install -d -m 0700 "$DIRECTORY" "$STATE_DIRECTORY" "$STATE_DIRECTORY/backups"
BACKUP="$STATE_DIRECTORY/backups/$(date -u +%Y%m%dT%H%M%SZ)-$$"
EXISTING=0;[[ ! -f "$BINARY" ]] || EXISTING=1
if (( ! NO_SERVICE ));then systemctl stop "$UNIT" 2>/dev/null || true;fi
FLAGS=();(( ! OFFLINE )) || FLAGS+=(--offline)
rollback(){
 local code=$?
 trap - ERR
 echo 'Installation failed; restoring the verified previous version where available.' >&2
 if [[ -f "$BACKUP/previous.bin" ]];then
  if [[ "$ENGINE" == iptables && -f "$BACKUP/manifest.json" ]];then
   "$TOOL" --config "$DIRECTORY/config.json" --maintenance rollback --backup-dir "$BACKUP" || { echo "Recovery required; forwarding remains blocked. Backup: $BACKUP" >&2;exit "$code"; }
  fi
  (cd "$BACKUP";sha256sum -c previous.sha256 >/dev/null) || exit "$code"
  cp -p -- "$BACKUP/previous.bin" "$BINARY"
  if (( ! NO_SERVICE && ! OFFLINE ));then systemctl start "$UNIT" || true;fi
 fi
 exit "$code"
}
trap rollback ERR
RESUMED=0
if [[ "$ENGINE" == iptables && -f "$STATE.maintenance" ]];then
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
SOURCE="$STAGE/flux-agent-linux-$ARCH";[[ "$ENGINE" == iptables ]] || SOURCE="$STAGE/gost-linux-$ARCH"
if [[ "$ACTION" == install ]];then
 if [[ "$ENGINE" == iptables ]];then install -d -m 0755 "$(dirname "$BINARY")";fi
 install -m 0755 "$SOURCE" "$BINARY.new";mv -f -- "$BINARY.new" "$BINARY"
 install -m 0600 "$CONFIG" "$DIRECTORY/config.json"
fi
if [[ "$ENGINE" == iptables && -f "$STATE" ]] && (( ! RESUMED ));then
 MODE=migrate;[[ "$ACTION" != uninstall ]] || MODE=uninstall
 "$TOOL" --config "$DIRECTORY/config.json" --maintenance "$MODE" --backup-dir "$BACKUP" "${FLAGS[@]}"
fi
if [[ "$ACTION" == uninstall ]];then
 if (( ! NO_SERVICE ));then systemctl disable "$UNIT" 2>/dev/null || true;rm -f -- "$PREFIX/etc/systemd/system/$UNIT";if [[ "$ENGINE" == iptables ]];then rm -f -- "$PREFIX/etc/tmpfiles.d/flux-agent.conf";fi;systemctl daemon-reload;fi
 rm -f -- "$BINARY"
 printf 'Uninstalled %s. State, credentials and recoverable backup retained at %s.\n' "$NAME" "$BACKUP";exit 0
fi
if [[ "$ENGINE" == gost ]];then [[ -f "$DIRECTORY/gost.json" ]] || printf '{}\n' > "$DIRECTORY/gost.json";chmod 0600 "$DIRECTORY/gost.json";fi
if (( ! NO_SERVICE ));then
 install -d -m 0755 "$PREFIX/etc/systemd/system"
 if [[ "$ENGINE" == iptables ]];then
 install -d -m 0755 "$PREFIX/etc/tmpfiles.d" "$PREFIX/run"
 install -m 0644 "$STAGE/flux-agent-tmpfiles.conf" "$PREFIX/etc/tmpfiles.d/flux-agent.conf"
 [[ -e "$PREFIX/run/xtables.lock" ]] || install -m 0600 /dev/null "$PREFIX/run/xtables.lock"
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
 systemctl daemon-reload;systemctl enable "$UNIT";systemctl start "$UNIT"
 if [[ "$ENGINE" == iptables ]];then
  READY=0
  for _ in {1..40};do if "$BINARY" --ready --config "$DIRECTORY/config.json" >/dev/null 2>&1;then READY=1;break;fi;sleep 1;done
  (( READY )) || { echo 'Agent did not confirm a fresh authenticated panel report.' >&2;false; }
 else
  systemctl is-active --quiet "$UNIT"
  journalctl -u "$UNIT" -n 100 --no-pager | grep -Eq 'WebSocket连接建立成功|WebSocket connection' || { echo 'GOST registration not confirmed in journal.' >&2;false; }
 fi
fi
trap - ERR
printf 'Installed pinned %s build. Backup: %s. Migrated forwards remain paused until explicit panel resume.\n' "$NAME" "$BACKUP"
