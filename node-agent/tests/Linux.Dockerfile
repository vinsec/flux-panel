FROM maven:3.9.9-eclipse-temurin-21 AS jdk
FROM debian:bookworm-slim
COPY --from=jdk /opt/java/openjdk /opt/java/openjdk
ENV JAVA_HOME=/opt/java/openjdk
ENV PATH=/opt/java/openjdk/bin:$PATH
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 iptables ipset conntrack python3 python3-pymysql curl procps ca-certificates libfontconfig1 libfreetype6 && rm -rf /var/lib/apt/lists/*
WORKDIR /tests
