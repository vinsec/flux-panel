"""Nine durable crash boundaries with local smooth shaping enabled."""
from pathlib import Path
source=Path('/tests/p1-faults.py').read_text()
source=source.replace("'schemaVersion':3", "'schemaVersion':4")
source=source.replace('from foundation_fixture import *', 'from foundation_fixture import *\nBPF_PREP=\'mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf; mount -o remount,rw /sys/fs/bpf; mkdir -p /sys/fs/bpf/tc/globals /sys/fs/bpf/ip/globals /sys/fs/bpf/xdp/globals; mkdir -p /run/flux-agent-bpf; mount -t tmpfs -o mode=0700 tmpfs /run/flux-agent-bpf; /build/flux-agent --prepare-local-shaping > /dev/null; mount --bind /sys/fs/bpf /sys/fs/bpf; mount -o remount,bind,ro /sys/fs/bpf; exec "$@"\'\ndef agent(fault=\'\',timeout=20):\n serial=PANEL.serial;args=[str(BUILD/\'flux-agent\'),\'--config\',str(CONFIG)]\n if fault:args+=[\'--test-fault\',fault]\n p=spawn(ns(\'router\',\'sh\',\'-c\',BPF_PREP,\'sh\',*args),\'agent.log\');wait(lambda:PANEL.serial>serial and p.poll() is None,timeout);return p\n')
source=source.replace("'10.205.3.2'","'10.205.2.1'")
source=source.replace(" topology();", " topology();run(['sh','-c','mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf; mount -o remount,rw /sys/fs/bpf; mkdir -p /sys/fs/bpf/tc/globals /sys/fs/bpf/ip/globals /sys/fs/bpf/xdp/globals']);router('ip','link','set','lo','mtu','131072');router('sysctl','-w','net.ipv4.conf.lo.accept_local=1','net.ipv4.conf.lo.rp_filter=2');")
source=source.replace("'selection':'round','bandwidth':", "'selection':'round','traffic':{'localOutput':True,'localTargets':True},'bandwidth':")
source=source.replace(" apply(s);", " spawn(ns('router','python3','/tests/echo_server.py'),'local-target.log');time.sleep(.2)\n apply(s);")
source=source.replace("probe()", "(probe() and run(ns('router','python3','-c',\"import socket;s=socket.create_connection(('10.205.1.1',18000),timeout=2);s.sendall(b'journal');assert s.recv(1024)==b'journal';s.close();print('ok')\"))=='ok')")
source=source.replace('advanced crash recovery', 'local smooth-shaping crash recovery').replace('p1-fault-result.json','p2-shaping-fault-result.json')
exec(compile(source,'/tests/p1-faults.py','exec'))
