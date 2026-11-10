"""Real split-service cutover/rollback in the explicitly disposable Fusion VM."""
import os
assert os.environ.get('FLUX_DISPOSABLE_SYSTEMD_TEST')=='1'
import sys
sys.path.insert(0,'/opt/flux-repair-20261110/tests')
import foundation_fixture as f
from foundation_fixture import *
import shutil,hashlib
ROOT=pathlib.Path('/opt/flux-repair-20261110');OUT=ROOT/'evidence'/'systemd';OUT.mkdir(exist_ok=True)
K='flux-repair-kernel.service';A='flux-repair-agent.service'
BINARY=ROOT/'systemd-agent';CONF=pathlib.Path('/etc/flux-repair/config.json');LEDGER=pathlib.Path('/var/lib/flux-repair/state.json')
f.STATE=LEDGER;f.CONFIG=CONF
STATE=LEDGER;CONFIG=CONF
TIMES=[];saved_lock=pathlib.Path('/run/flux-repair-xtables.saved');lock=pathlib.Path('/run/xtables.lock')
def svc(*args,timeout=4):return run(['systemctl',*args],timeout=timeout)
def healthy():
 try:
  for unit in [K,A]:
   if svc('is-active',unit)!='active':return False
  p=subprocess.run([str(BINARY),'--status','--config',str(CONF)],capture_output=True,text=True,timeout=1)
  d=json.loads(p.stdout)
  return not d['blocked'] and not d['accountingBlocked'] and d.get('lastAckAt',0)>int(time.time()*1000)-4000
 except Exception:return False
def units(raw):
 return raw.replace('flux-kernel.service',K).replace('flux-agent.service',A).replace('/usr/local/bin/flux-agent',str(BINARY)).replace('flux-agent','flux-repair').replace('[Service]','[Service]\nNetworkNamespacePath=/run/netns/router',1)
def monotonic(old,new):return old['epoch']==new['epoch'] and old['kernelId']==new['kernelId'] and set(old['rules'])==set(new['rules']) and all(new['totals'][k]['up']>=v['up'] and new['totals'][k]['down']>=v['down'] for k,v in old['totals'].items())
def exchange(binary,fail=False):
 # All copies and hashes are prepared before the critical phase.
 old=ROOT/'rollback-agent';shutil.copy2(BINARY,old);ready=ROOT/'ready-agent';shutil.copy2(binary,ready);ready.chmod(0o755)
 old_unit=ROOT/'rollback-kernel.service';unit=pathlib.Path('/etc/systemd/system/'+K);old_unit.write_text(unit.read_text())
 clean_unit='\n'.join(line for line in unit.read_text().splitlines() if not line.startswith('Environment=PATH='))+'\n'
 before=state();started=time.monotonic();svc('stop',A);svc('stop',K);os.replace(ready,BINARY);unit.write_text(clean_unit);svc('daemon-reload');svc('start','--no-block',A)
 if fail:
  # PID 1 owns this deadline. Recovery must still happen if the SSH-side
  # controller disappears or its candidate never becomes healthy.
  rollback=ROOT/'watchdog-rollback.sh'
  rollback.write_text('#!/bin/bash\nset -e\nsystemctl stop '+A+' '+K+'\ncp '+str(old)+' '+str(BINARY)+'.restore\nchmod 0755 '+str(BINARY)+'.restore\nmv '+str(BINARY)+'.restore '+str(BINARY)+'\ncp '+str(old_unit)+' /etc/systemd/system/'+K+'\nsystemctl daemon-reload\nsystemctl reset-failed '+K+' '+A+' || true\nsystemctl start '+A+'\ntouch '+str(ROOT/'watchdog-fired')+'\n')
  (ROOT/'watchdog-fired').unlink(missing_ok=True)
  run(['systemd-run','--unit=flux-repair-watchdog','--on-active=12s','--timer-property=AccuracySec=100ms','/bin/bash',str(rollback)])
  wait(lambda:(ROOT/'watchdog-fired').exists() and healthy(),24)
  check('independent systemd deadline restores the old executable without controller intervention',(ROOT/'watchdog-fired').exists())
 wait(healthy,8);elapsed=time.monotonic()-started
 check(('failed replacement rollback' if fail else 'split-systemd replacement')+' completes under 30 seconds',elapsed<30)
 check('per-rule ledger and exact rule IDs survive '+('rollback' if fail else 'upgrade'),monotonic(before,state()))
 TIMES.append({'failed_candidate':fail,'seconds':elapsed,'epoch_preserved':True})
try:
 assert not pathlib.Path('/etc/systemd/system/'+K).exists()
 assert not pathlib.Path('/run/netns/router').exists()
 topology();server=http.server.ThreadingHTTPServer(('10.205.4.1',8000),Handler);server.daemon_threads=True;threading.Thread(target=server.serve_forever,daemon=True).start()
 subprocess.run(['groupadd','--system','flux-repair'],capture_output=True);subprocess.run(['useradd','--system','--gid','flux-repair','--no-create-home','--shell','/usr/sbin/nologin','flux-repair'],capture_output=True)
 CONF.parent.mkdir(mode=0o700,exist_ok=True);
 if LEDGER.parent.exists():shutil.move(str(LEDGER.parent),str(OUT/('prior-state-'+str(time.time_ns()))))
 CONF.write_text(json.dumps({'addr':'http://10.205.4.1:8000','secret':SECRET,'statePath':str(LEDGER),'helperSocket':'/run/flux-repair/kernel.sock','apply':True,'allowInsecure':True,'intervalSeconds':1,'kernelBackend':'nftables'}));CONF.chmod(0o600)
 shutil.copy2(ROOT/'build/flux-agent-baseline',BINARY)
 old_kernel=(ROOT/'packaging/flux-kernel.service').read_text().replace('ReadWritePaths=/var/lib/flux-agent /run/flux-agent','ReadWritePaths=/var/lib/flux-agent /run/flux-agent /run/xtables.lock')
 pathlib.Path('/etc/systemd/system/'+K).write_text(units(old_kernel));pathlib.Path('/etc/systemd/system/'+A).write_text(units((ROOT/'packaging/flux-agent.service').read_text()))
 if lock.exists():lock.rename(saved_lock)
 svc('daemon-reload');svc('start','--no-block',K)
 wait(lambda:svc('show','--value','-p','ExecMainStatus',K)=='226',5)
 check('old unit reproduces missing xtables.lock namespace failure',not lock.exists())
 svc('stop',K)
 # Reproduce the exact previous-version dependency on a PATH compatibility
 # shim at a 49-day authorization, then prove rollback restores it.
 compat=ROOT/'compat';compat.mkdir(exist_ok=True)
 compat_nft=compat/'nft'
 compat_nft.write_text('''#!/usr/bin/python3
import os,re,subprocess,sys
args=sys.argv[1:]
if '-f' not in args or '-' not in args:os.execv('/usr/sbin/nft',['/usr/sbin/nft']+args)
def fmt(m):
 n=int(m.group(1))
 if n<=2147483647:return m.group(0)
 out=[]
 for size,u in [(86400000,'d'),(3600000,'h'),(60000,'m'),(1000,'s'),(1,'ms')]:
  v,n=divmod(n,size)
  if v:out.append(str(v)+u)
 return 'timeout '+''.join(out)
p=subprocess.run(['/usr/sbin/nft']+args,input=re.sub('timeout ([0-9]+)ms',fmt,sys.stdin.read()),text=True)
sys.exit(p.returncode)
''');compat_nft.chmod(0o755)
 fixed=units((ROOT/'packaging/flux-kernel.service').read_text()).replace('[Service]','[Service]\nEnvironment=PATH='+str(compat)+':/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',1)
 pathlib.Path('/etc/systemd/system/'+K).write_text(fixed);svc('daemon-reload');subprocess.run(['systemctl','reset-failed',K],capture_output=True);svc('start','--no-block',A);wait(healthy)
 check('fixed unit starts with xtables.lock absent, using original restricted capabilities',not lock.exists())
 s=spec();s['expiresAt']=int(time.time()*1000)+49*86400000;apply(s);probe()
 limited=spec('2_2_3',18001);limited.update(leaseRequired=True,expiresAt=s['expiresAt']);PANEL.quota=1024*1024;apply(limited);wait(lambda:'2_2_3' in state()['leases']);probe(18001)
 lease=state()['leases']['2_2_3']['grant']['id']
 held_code='''import socket,time,pathlib,json
s=socket.create_connection(('10.205.1.1',18000),timeout=3);s.settimeout(28);n=0;last=time.monotonic();gap=0
try:
 while not pathlib.Path('/tmp/systemd-held-done').exists():
  s.sendall(b'fixed-connection');out=b''
  while len(out)<16:
   b=s.recv(16-len(out));assert b;out+=b
  assert out==b'fixed-connection';now=time.monotonic();gap=max(gap,now-last);last=now;n+=1;pathlib.Path('/tmp/systemd-held-ready').touch();time.sleep(.02)
 pathlib.Path('/tmp/systemd-held-result.json').write_text(json.dumps({'success':True,'messages':n,'max_gap_seconds':gap}))
except Exception as e:
 pathlib.Path('/tmp/systemd-held-result.json').write_text(json.dumps({'success':False,'error':repr(e)}));raise
'''
 for marker in ['systemd-held-done','systemd-held-ready','systemd-held-result.json']:pathlib.Path('/tmp/'+marker).unlink(missing_ok=True)
 held=spawn(ns('client','python3','-c',held_code),'systemd-held.log');wait(lambda:pathlib.Path('/tmp/systemd-held-ready').exists())
 broken=ROOT/'broken-agent';broken.write_text('#!/bin/sh\nexit 70\n');broken.chmod(0o755);exchange(broken,True)
 check('rollback restores the original binary and its 49-day compatibility configuration',state()['leases']['2_2_3']['grant']['id']==lease and 'compat' in svc('show','--value','-p','Environment',K))
 exchange(ROOT/'build/flux-agent')
 check('new executable handles 49-day rules with all PATH compatibility removed','compat' not in svc('show','--value','-p','Environment',K))
 check('unprivileged transport reconnects and reserved credit is not reissued',state()['leases']['2_2_3']['grant']['id']==lease)
 pathlib.Path('/tmp/systemd-held-done').touch();wait(lambda:held.poll() is not None);held_result=json.loads(pathlib.Path('/tmp/systemd-held-result.json').read_text());check('same TCP socket survives systemd cutover and timed rollback',held_result['success'] and held_result['messages']>100)
 check('post-upgrade TCP and UDP pass',probe() and probe(18001))
 (OUT/'timings.json').write_text(json.dumps({'cutovers':TIMES,'held_connection':held_result},indent=2));DONE=True
except Exception:
 traceback.print_exc()
 (OUT/'systemd.log').write_text(subprocess.run(['journalctl','-u',K,'-u',A,'-n','80','--no-pager'],capture_output=True,text=True).stdout)
 raise
finally:
 for unit in ['flux-repair-watchdog.timer','flux-repair-watchdog.service',A,K]:subprocess.run(['systemctl','stop',unit],capture_output=True,timeout=8)
 for p in reversed(PROCS):stop(p)
 for unit in [A,K]:pathlib.Path('/etc/systemd/system/'+unit).unlink(missing_ok=True)
 subprocess.run(['systemctl','daemon-reload'],capture_output=True)
 for name in ['client','router','transit','target']:subprocess.run(['ip','netns','del',name],capture_output=True)
 subprocess.run(['ip','link','del','control'],capture_output=True)
 if saved_lock.exists():saved_lock.rename(lock)
 (OUT/'systemd-result.json').write_text(json.dumps({'success':DONE,'count':len(CHECKS),'passed':CHECKS,'external_forward_test_targets':[]},indent=2))
