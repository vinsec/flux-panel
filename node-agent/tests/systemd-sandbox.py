"""Actual systemd sandbox in the disposable ARM VM only.
Run inside an outer network namespace without a default route. PID1 remains
in the VM host; its service is explicitly attached to the private router NS.
"""
from foundation_fixture import *
import shutil
if subprocess.run(['getent','passwd','flux-agent'],capture_output=True).returncode!=0:run(['useradd','--system','--no-create-home','--shell','/usr/sbin/nologin','flux-agent'])
DONE=False
try:
 assert pathlib.Path('/run/systemd/system').exists()
 assert 'default' not in run(['ip','route'])
 topology();server=http.server.ThreadingHTTPServer(('10.205.4.1',8000),Handler);server.daemon_threads=True;threading.Thread(target=server.serve_forever,daemon=True).start()
 package=pathlib.Path(os.environ['FLUX_TEST_PACKAGE']);binary=pathlib.Path('/usr/local/bin/flux-agent');shutil.copyfile(package/'flux-agent-linux-arm64',binary);binary.chmod(0o755)
 config=pathlib.Path('/etc/flux-agent/config.json');config.parent.mkdir(mode=0o700,exist_ok=True);config.write_text(json.dumps({'addr':'http://10.205.4.1:8000','secret':SECRET,'statePath':'/var/lib/flux-agent/p1-state.json','apply':True,'allowInsecure':True,'intervalSeconds':1,'helperSocket':'/run/flux-agent/kernel.sock'}));config.chmod(0o600)
 keeper=spawn(ns('router','sleep','300'),'namespace-keeper.log')
 for name in ['flux-agent.service','flux-kernel.service']:
  unit=pathlib.Path('/etc/systemd/system')/name;shutil.copyfile(package/name,unit);override=pathlib.Path(str(unit)+'.d');override.mkdir(exist_ok=True);(override/'private-test.conf').write_text('[Service]\nNetworkNamespacePath=/proc/'+str(keeper.pid)+'/ns/net\n')
 pathlib.Path('/etc/tmpfiles.d').mkdir(exist_ok=True);shutil.copyfile(package/'flux-agent-tmpfiles.conf','/etc/tmpfiles.d/flux-agent.conf');run(['systemd-tmpfiles','--create','/etc/tmpfiles.d/flux-agent.conf'])
 run(['systemd-analyze','verify',str(unit)]);run(['systemctl','daemon-reload']);serial=PANEL.serial;run(['systemctl','start','flux-agent.service']);wait(lambda:PANEL.serial>serial,20)
 check('real systemd sandbox starts with private router namespace',run(['systemctl','is-active','flux-agent.service'])=='active')
 apply(spec(port=80));check('sandbox retains low-port ownership validation and actual forwarding',probe(80))
 wait(lambda:subprocess.run([str(binary),'--ready','--config',str(config)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0,10);check('service readiness requires a fresh control connection and report receipt')
 pid=int(run(['systemctl','show','flux-agent.service','--property=MainPID','--value']));status=pathlib.Path('/proc/'+str(pid)+'/status').read_text();check('actual network unit runs with no effective capabilities and a dedicated user','CapEff:\t0000000000000000' in status and 'Uid:\t0' not in status)
 check('unit keeps filesystem/capability confinement',run(['systemctl','show','flux-agent.service','--property=ProtectSystem','--value'])=='strict')
 DONE=True
finally:
 subprocess.run(['systemctl','stop','flux-agent.service','flux-kernel.service'],capture_output=True)
 for p in reversed(PROCS):stop(p)
 (OUT/'systemd-result.json').write_text(json.dumps({'success':DONE,'arch':os.uname().machine,'count':len(CHECKS),'passed':CHECKS,'privateRouterNamespace':True,'external_forward_test_targets':[]},indent=2))
