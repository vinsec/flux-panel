"""Pinned installer sandbox. Uses fake systemctl, never a host service manager."""
from foundation_fixture import *
import shutil
DONE=False
try:
 if os.getenv('IPTABLES_BACKEND')=='legacy':run(['update-alternatives','--set','iptables','/usr/sbin/iptables-legacy'])
 topology();server=http.server.ThreadingHTTPServer(('10.205.4.1',8000),Handler);server.daemon_threads=True;threading.Thread(target=server.serve_forever,daemon=True).start()
 package=pathlib.Path('/package');pin=hashlib.sha256((package/'SHA256SUMS').read_bytes()).hexdigest();arch='arm64' if os.uname().machine=='aarch64' else 'amd64';prefix=pathlib.Path('/tmp/package-root');config=pathlib.Path('/tmp/package-config.json');ledger=prefix/'var/lib/flux-agent/state.json';binary=prefix/'usr/local/bin/flux-agent'
 config.write_text(json.dumps({'addr':'http://10.205.4.1:8000','secret':SECRET,'statePath':str(ledger),'apply':True,'allowInsecure':True,'intervalSeconds':1,'kernelBackend':KERNEL_BACKEND}))
 def install(action='install',extra=(),success=True,service=False):
  args=ns('router','bash',str(package/'install.sh'),'--engine','kernel','--bundle',str(package),'--manifest-sha256',pin,'--config',str(config),'--prefix',str(prefix),'--action',action)
  if not service:args+=['--no-service']
  args+=list(extra);env=os.environ.copy();env['PATH']='/tmp/fake-systemctl:'+env['PATH'];p=subprocess.run(args,capture_output=True,text=True,env=env,timeout=60)
  if success:assert p.returncode==0,(p.stdout,p.stderr)
  return p
 wrong=install(extra=['--manifest-sha256','0'*64],success=False);check('wrong pinned manifest cannot install a binary',wrong.returncode!=0 and not binary.exists())
 install(extra=['--dry-run']);check('dry run verifies package without creating target directories',not prefix.exists())
 install();expected=hashlib.sha256((package/('flux-agent-linux-'+arch)).read_bytes()).hexdigest();check('offline pinned installation writes exact binary and protected config',hashlib.sha256(binary.read_bytes()).hexdigest()==expected and (prefix/'etc/flux-agent/config.json').stat().st_mode&0o777==0o600)
 managed=prefix/'usr/local/lib/flux-agent/gost-managed';expected_managed=hashlib.sha256((package/('gost-managed-linux-'+arch)).read_bytes()).hexdigest();check('managed artifact is checksum-pinned and installed separately',managed.exists() and hashlib.sha256(managed.read_bytes()).hexdigest()==expected_managed)
 before=binary.stat().st_mtime_ns;install();check('repeated identical install is idempotent',binary.stat().st_mtime_ns==before)
 serial=PANEL.serial;a=spawn(ns('router',str(binary),'--config',str(prefix/'etc/flux-agent/config.json')),'installed-agent.log');wait(lambda:PANEL.serial>serial);apply(spec());check('installed artifact actually forwards TCP and UDP',probe());stop(a)
 install('uninstall');check('uninstall keeps durable state and backup while removing owned dataplane',not binary.exists() and ledger.exists() and 'keep-unrelated' in router('iptables-save'))
 baseline=pathlib.Path(os.getenv('FLUX_INSTALL_BASELINE',str(BUILD/'agent-v2')))
 if os.getenv('FLUX_INSTALL_BASELINE'):assert baseline.exists(),'explicit native baseline missing'
 if baseline.exists():
  # Prepare a genuine previous executable/checkpoint before the new installer.
  prefix=pathlib.Path('/tmp/package-upgrade');ledger=prefix/'var/lib/flux-agent/state.json';binary=prefix/'usr/local/bin/flux-agent';binary.parent.mkdir(parents=True);(prefix/'etc/flux-agent').mkdir(parents=True)
  config=pathlib.Path('/tmp/package-upgrade-config.json');config.write_text(json.dumps({'addr':'http://10.205.4.1:8000','secret':SECRET,'statePath':str(ledger),'apply':True,'allowInsecure':True,'intervalSeconds':1,'kernelBackend':'nftables'}));shutil.copyfile(config,prefix/'etc/flux-agent/config.json');shutil.copyfile(baseline,binary);binary.chmod(0o755)
  serial=PANEL.serial;a=spawn(ns('router',str(binary),'--config',str(config)),'previous-agent.log');wait(lambda:PANEL.serial>serial);apply(spec());assert probe();wait(lambda:json.loads(ledger.read_text()).get('totals',{}).get('1_1_0',{}).get('up',0)>0);old=json.loads(ledger.read_text());stop(a)
  fake=pathlib.Path('/tmp/fake-systemctl');fake.mkdir();command=fake/'systemctl';command.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> /evidence/systemctl.calls\n[ "$1" != start ]\n');command.chmod(0o755)
  failed=install(service=True,success=False);check('service activation failure triggers a verified version rollback',failed.returncode!=0 and hashlib.sha256(binary.read_bytes()).hexdigest()==hashlib.sha256(baseline.read_bytes()).hexdigest())
  current=json.loads(ledger.read_text());check('installer rollback preserves epoch, newer totals and paused business',current['epoch']==old['epoch'] and current['totals']['1_1_0']['up']>=old['totals']['1_1_0']['up'] and all(not s['enabled'] for s in current['rules'].values()) and probe(blocked=True))
  install();check('retry upgrades the native checkpoint without resetting accounting',json.loads(ledger.read_text())['formatVersion']==6 and hashlib.sha256(binary.read_bytes()).hexdigest()==expected)
  install('uninstall')
 check('sandbox never invoked the real system service manager',not pathlib.Path('/run/systemd/system').exists())
 DONE=True
except Exception:
 traceback.print_exc();raise
finally:
 for p in reversed(PROCS):stop(p)
 (OUT/'install-result.json').write_text(json.dumps({'success':DONE,'arch':os.uname().machine,'backend':os.getenv('IPTABLES_BACKEND','nft'),'count':len(CHECKS),'passed':CHECKS,'prefix':'/tmp/package-root and /tmp/package-upgrade','external_forward_test_targets':[]},indent=2))
