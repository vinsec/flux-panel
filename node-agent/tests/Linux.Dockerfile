FROM debian:bookworm-slim
RUN apt-get -o Acquire::Retries=3 update && apt-get -o Acquire::Retries=3 install -y --no-install-recommends iproute2 iptables nftables ipset iputils-ping conntrack python3 python3-cryptography python3-pymysql curl procps ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /tests
