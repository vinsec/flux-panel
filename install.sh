#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
if [[ "${1:-}" == --engine || "${1:-}" == --engine=* ]]; then
    exec bash "$ROOT/node-agent/packaging/install.sh" "$@"
fi
printf '%s\n' '安装节点：请在面板“节点监控”中新增节点，点击“安装”，复制整段命令到节点服务器执行。' '安装面板：请使用 ./panel_install.sh install，步骤见 README.md。' >&2
exit 2
