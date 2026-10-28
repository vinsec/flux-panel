from pathlib import Path
import subprocess,json,time,socket,os
assert os.environ.get('FLUX_DISPOSABLE_SYSTEMD_TEST')=='1', 'requires explicit disposable VM authorization'
assert not subprocess.check_output(['ip','route','show','default'],text=True).strip(), 'test VM must have no public default route'
out=Path('/opt/flux-p1/evidence/p2-security-systemd');out.mkdir(exist_ok=True)
def run(*a):return subprocess.check_output(a,text=True,stderr=subprocess.STDOUT).strip()
name='flux-security-unit'
units=['flux-security-helper-test.service','flux-security-prepare-test.service']
try:
 run('sh','-c','mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf; mount -o remount,rw /sys/fs/bpf')
 run('ip','netns','add',name);run('ip','-n',name,'link','set','lo','up','mtu','131072')
 run('ip','netns','exec',name,'sysctl','-w','net.ipv4.conf.lo.accept_local=1','net.ipv4.conf.lo.rp_filter=2')
 base=Path('/etc/systemd/system')
 prep=Path('/home/fluxlab/flux-local-shaping-prepare.service').read_text().replace('/usr/local/bin/flux-agent','/opt/flux-p1/build/flux-agent').replace('Before=flux-kernel.service','Before=flux-security-helper-test.service')
 (base/units[1]).write_text(prep)
 directory=Path('/var/lib/flux-security-test');directory.mkdir(mode=0o700,exist_ok=True)
 cfg=directory/'config.json';cfg.write_text(json.dumps({'addr':'http://127.0.0.1:9','secret':'isolated-systemd-only','statePath':str(directory/'state.json'),'helperSocket':'/run/flux-security-test/kernel.sock','apply':True,'allowInsecure':True,'intervalSeconds':1}));cfg.chmod(0o600)
 helper=Path('/home/fluxlab/flux-kernel.service').read_text().replace('Group=flux-agent','Group=root').replace('Before=flux-agent.service','Before=flux-unused-network.service').replace('ExecStart=/usr/local/bin/flux-agent --kernel-helper --helper-user flux-agent --config /etc/flux-agent/config.json','ExecStart=/opt/flux-p1/build/flux-agent --kernel-helper --helper-user 0 --config '+str(cfg)).replace('StateDirectory=flux-agent','StateDirectory=flux-security-test').replace('RuntimeDirectory=flux-agent','RuntimeDirectory=flux-security-test').replace('/var/lib/flux-agent /run/flux-agent','/var/lib/flux-security-test /run/flux-security-test')
 helper=helper.replace('[Service]','Requires=flux-security-prepare-test.service\nAfter=flux-security-prepare-test.service\n[Service]\nNetworkNamespacePath=/run/netns/'+name+'\nReadOnlyPaths=/sys/fs/bpf /run/flux-agent-bpf',1)
 (base/units[0]).write_text(helper);run('systemctl','daemon-reload');run('systemctl','start',units[0])
 deadline=time.monotonic()+20
 while not Path('/run/flux-security-test/kernel.sock').exists():
  assert time.monotonic()<deadline,'helper readiness expired'
  time.sleep(.05)
 pid=int(run('systemctl','show',units[0],'-p','MainPID','--value'));prep_pid=int(run('systemctl','show',units[1],'-p','MainPID','--value'))
 status=Path('/proc/'+str(pid)+'/status').read_text();caps={l.split(':')[0]:int(l.split()[1],16) for l in status.splitlines() if l.startswith(('CapEff:','CapPrm:','CapBnd:','CapAmb:'))}
 assert prep_pid==0 and caps['CapEff']==0x3400 and all(v&((1<<21)|(1<<39))==0 for v in caps.values()),caps
 def rpc(kind,data):
  s=socket.socket(socket.AF_UNIX);s.settimeout(20);s.connect('/run/flux-security-test/kernel.sock');s.sendall((json.dumps({'type':kind,'data':data})+'\n').encode());f=s.makefile();result=json.loads(f.readline());s.close();return result
 spec={'schemaVersion':4,'id':'150_1_0','revision':1,'enabled':True,'listen':{'host':'127.0.0.1','port':18550},'targets':[{'endpoint':{'host':'127.0.0.1','port':19000},'weight':1}],'traffic':{'localOutput':True,'localTargets':True},'bandwidth':{'upBitsPerSecond':8000000}}
 reply=rpc('ApplyForward',spec);(out/'rpc.json').write_text(json.dumps(reply));assert reply.get('success'),reply
 text=run('ip','netns','exec',name,'tc','-j','filter','show','dev','lo','egress','chain','201');assert 'bpf' in text,text
 (out/'result.json').write_text(json.dumps({'success':True,'preparerMainPID':prep_pid,'helperCaps':caps,'helperUnit':run('systemctl','show',units[0],'-p','ProtectKernelTunables','-p','ProtectSystem','-p','ReadOnlyPaths'),'pinAttached':True},indent=2));print('PASS actual oneshot exits; protected helper attaches pin without SYS_ADMIN/BPF',flush=True)
finally:
 for unit in units:subprocess.run(['systemctl','stop',unit],capture_output=True)
 for unit in units:(Path('/etc/systemd/system')/unit).unlink(missing_ok=True)
 subprocess.run(['systemctl','daemon-reload'],capture_output=True);subprocess.run(['ip','netns','del',name],capture_output=True)
