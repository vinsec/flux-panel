#!/usr/bin/env bash
# Install prerequisites from the distribution and Docker's official repositories.
set -euo pipefail
if command -v docker >/dev/null && docker compose version >/dev/null 2>&1 && command -v openssl >/dev/null; then
    docker info >/dev/null
    exit 0
fi
[[ $EUID == 0 ]] || { echo '请使用 root 执行，或先自行安装 Docker Engine 和 Compose v2。' >&2; exit 1; }
. /etc/os-release
case "$ID" in
    debian|ubuntu) ;;
    *) echo '自动准备依赖目前支持 Debian 和 Ubuntu。其他系统请按 Docker 官方文档安装 Engine 和 Compose v2，再重试。' >&2; exit 1 ;;
esac
if command -v docker >/dev/null && docker compose version >/dev/null 2>&1; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssl
    docker info >/dev/null
    exit 0
fi
if command -v docker >/dev/null; then
    echo '检测到已有 Docker，但 Compose v2 不可用。请为现有 Docker 安装匹配的 Compose 插件，再重试。' >&2
    exit 1
fi
for package in docker.io docker-compose docker-doc podman-docker containerd runc; do
    if dpkg-query -W -f='${db:Status-Status}' "$package" 2>/dev/null | grep -qx installed; then
        echo "检测到已有 $package，请先按 Docker 官方文档处理软件包冲突。" >&2
        exit 1
    fi
done
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends ca-certificates curl gnupg openssl
install -d -m 0755 /etc/apt/keyrings
curl --fail --silent --show-error --location --proto '=https' "https://download.docker.com/linux/$ID/gpg" -o /etc/apt/keyrings/flux-docker.asc
chmod 0644 /etc/apt/keyrings/flux-docker.asc
fingerprint="$(gpg --show-keys --with-colons /etc/apt/keyrings/flux-docker.asc | awk -F: '$1=="fpr" {print $10;exit}')"
[[ "$fingerprint" == 9DC858229FC7DD38854AE2D88D81803C0EBFCD88 ]] || { echo 'Docker 仓库签名公钥不匹配。' >&2; exit 1; }
[[ "${VERSION_CODENAME:-}" =~ ^[a-z]+$ ]] || { echo '无法识别发行版代号。' >&2; exit 1; }
architecture="$(dpkg --print-architecture)"
cat > /etc/apt/sources.list.d/flux-docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/$ID
Suites: $VERSION_CODENAME
Components: stable
Architectures: $architecture
Signed-By: /etc/apt/keyrings/flux-docker.asc
EOF
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker
docker compose version
docker info >/dev/null
