#!/bin/bash
set -euo pipefail
install -d -m 0700 /etc/flux-agent /var/lib/flux-agent
python3 - <<'PY'
import json,pathlib
p=pathlib.Path('/etc/flux-agent/config.json');p.write_text(json.dumps({'addr':'http://172.16.246.1:18090','secret':'fusion-isolated-p1-only','statePath':'/var/lib/flux-agent/state.json','helperSocket':'/run/flux-agent/kernel.sock','apply':True,'allowInsecure':True,'intervalSeconds':1}));p.chmod(0o600)
PY
getent group flux-agent >/dev/null || groupadd --system flux-agent
getent passwd flux-agent >/dev/null || useradd --system --gid flux-agent --no-create-home --shell /usr/sbin/nologin flux-agent
install -m 0755 /opt/flux-p1/build/flux-agent /usr/local/bin/flux-agent
install -m 0644 /opt/flux-p1/packaging/flux-agent.service /opt/flux-p1/packaging/flux-kernel.service /etc/systemd/system/
install -m 0644 /opt/flux-p1/packaging/flux-agent-tmpfiles.conf /etc/tmpfiles.d/flux-agent.conf
systemd-tmpfiles --create /etc/tmpfiles.d/flux-agent.conf
cat > /etc/systemd/system/p1-topology.service <<'UNIT'
[Unit]
Description=Disposable P1 private veth topology
Before=flux-kernel.service p1-echo.service
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/flux-p1/guest/power-topology.py
RemainAfterExit=true
[Install]
WantedBy=multi-user.target
UNIT
cat > /etc/systemd/system/p1-echo.service <<'UNIT'
[Unit]
Description=Disposable P1 private echo peer
Requires=p1-topology.service
After=p1-topology.service
[Service]
ExecStart=/usr/sbin/ip netns exec p1target /usr/bin/python3 /opt/flux-p1/tests/echo_server.py
Restart=on-failure
[Install]
WantedBy=multi-user.target
UNIT
install -d /etc/systemd/system/flux-kernel.service.d
cat > /etc/systemd/system/flux-kernel.service.d/p1-topology.conf <<'UNIT'
[Unit]
Requires=p1-topology.service p1-echo.service
After=p1-topology.service p1-echo.service
UNIT
systemctl daemon-reload
systemctl enable p1-topology.service p1-echo.service flux-kernel.service flux-agent.service
systemctl start flux-agent.service
