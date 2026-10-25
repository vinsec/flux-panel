ARG BASE=flux-iptables-test:local
FROM ${BASE}
RUN DEBIAN_FRONTEND=noninteractive apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends iperf3 ethtool && rm -rf /var/lib/apt/lists/*
