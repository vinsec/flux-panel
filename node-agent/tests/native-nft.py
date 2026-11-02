"""Native nft black-box acceptance. Real sockets and kernel JSON, no Go imports.
Run only in a private mount/net namespace with no public routes.
"""
from foundation_fixture import *

def raw_counts(ident):
 totals=[0,0]
 for item in json.loads(router('nft','-j','list','table','inet','FP_NATIVE'))['nftables']:
  c=item.get('counter')
  if not c:continue
  fields=c['comment'].split('|')
  for i,d in enumerate(['up','down']):
   if fields[2]=='flux:v2:'+ident+':'+d:totals[i]+=c['bytes']
 return totals

try:
 topology();router('iptables','-P','FORWARD','ACCEPT')
 server=http.server.ThreadingHTTPServer(('10.205.4.1',8000),Handler);server.daemon_threads=True;threading.Thread(target=server.serve_forever,daemon=True).start()
 cfg={'addr':'http://10.205.4.1:8000','secret':SECRET,'statePath':str(STATE),'apply':True,'allowInsecure':True,'intervalSeconds':1,'kernelBackend':'nftables'}
 CONFIG.write_text(json.dumps(cfg));a=agent()
 check('native mode initializes without ipset or owned iptables chains','FP4_' not in router('iptables-save') and 'FPV' not in router('ipset','list','-name'))
 s=spec();apply(s);check('native IPv4 TCP/UDP sockets pass',probe())
 time.sleep(1.3)
 def rule_handles():return [x['rule']['handle'] for x in json.loads(router('nft','-j','list','table','inet','FP_NATIVE'))['nftables'] if 'rule' in x]
 handles=rule_handles();router('ip','link','add','flux-noop','type','dummy');time.sleep(1.3);router('ip','link','del','flux-noop');time.sleep(1.3)
 check('irrelevant addressless link events do not rebuild rules or fence traffic',rule_handles()==handles and probe())
 before=raw_counts(s['id']);payload=b'e'*123
 run(ns('client','python3','-c',f"import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(2);s.sendto({payload!r},('10.205.1.1',18000));assert s.recv(1024)=={payload!r}"))
 after=raw_counts(s['id']);check('exact network accounting once per direction',[b-a for a,b in zip(before,after)]==[151,151])
 counts=raw_counts(s['id']);PANEL.rpc('SetForwardState',{'id':s['id'],'revision':2,'enabled':False});check('pause stops TCP and UDP',probe(blocked=True));check('pause preserves named counters',raw_counts(s['id'])==counts)
 PANEL.rpc('SetForwardState',{'id':s['id'],'revision':3,'enabled':True});check('resume restores flow',probe())
 wrong=pathlib.Path('/tmp/wrong-backend.json');wrong.write_text(json.dumps(dict(cfg,kernelBackend='iptables')))
 stop(a)
 result=subprocess.run(ns('router',str(BUILD/'flux-agent'),'--config',str(wrong),'--maintenance','backup','--backup-dir','/tmp/wrong-backup'),capture_output=True,text=True)
 check('wrong-backend maintenance refuses before touching live rules',result.returncode!=0 and 'retired' in result.stderr and probe())
 a=agent()
 # Confirmed TCP and UDP connections must not bypass a map update.
 code="""import socket,pathlib,time
connections=[]
for kind in [socket.SOCK_STREAM,socket.SOCK_DGRAM]:
 s=socket.socket(socket.AF_INET,kind);s.settimeout(.3);s.connect(('10.205.1.1',18000));s.sendall(b'held');assert s.recv(100)==b'held';connections.append(s)
pathlib.Path('/tmp/native-held-ready').touch()
while not pathlib.Path('/tmp/native-held-paused').exists():time.sleep(.01)
for s in connections:
 try:s.sendall(b'held');s.recv(100);raise AssertionError('pause bypass')
 except OSError:pass
 s.close()
"""
 held=spawn(ns('client','python3','-c',code),'held.log');wait(lambda:pathlib.Path('/tmp/native-held-ready').exists());PANEL.rpc('SetForwardState',{'id':s['id'],'revision':4,'enabled':False});pathlib.Path('/tmp/native-held-paused').touch();assert held.wait(timeout=4)==0;check('pause blocks already confirmed connections')
 PANEL.rpc('SetForwardState',{'id':s['id'],'revision':5,'enabled':True});before=raw_counts(s['id']);stop(a);a=agent();check('restart preserves kernel and cumulative counts',all(b>=c for b,c in zip(raw_counts(s['id']),before)) and probe())
 stop(a);saved=STATE.read_bytes();STATE.unlink();result=subprocess.run(ns('router',str(BUILD/'flux-agent'),'--config',str(CONFIG)),capture_output=True,text=True,timeout=15)
 check('lost checkpoint cannot reset the existing accounting epoch',result.returncode!=0 and 'persistent state missing' in result.stderr)
 STATE.write_bytes(saved);a=agent();check('restored checkpoint resumes the original cumulative ledger',probe() and state()['epoch']==json.loads(saved)['epoch'])
 limited=spec('2_2_3',18001);limited['leaseRequired']=True;PANEL.quota=8192;apply(limited);wait(lambda:'2_2_3' in state().get('leases',{}));time.sleep(.5)
 code="""import socket,threading
def worker():
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(.01)
 for _ in range(80):
  s.sendto(b'q'*1000,('10.205.1.1',18001))
  try:s.recv(2048)
  except socket.timeout:pass
ts=[threading.Thread(target=worker) for _ in range(4)]
for t in ts:t.start()
for t in ts:t.join()
"""
 run(ns('client','python3','-c',code));time.sleep(1.1);usage=raw_counts(limited['id']);check('concurrent directions share one finite 8KiB budget',0<sum(usage)<=8192);check('exhausted credit remains closed',probe(18001,True));PANEL.quota=0
 objects=[x['quota'] for x in json.loads(router('nft','-j','list','table','inet','FP4_QUOTA'))['nftables'] if 'quota' in x];check('quota uses a shared stateful nft object',len(objects)==1 and objects[0]['used']>=objects[0]['bytes'])
 snapshot=router('nft','-j','list','table','inet','FP_NATIVE');before=raw_counts(s['id']);bad=router('nft','list','table','inet','FP_NATIVE')
 r=subprocess.run(ns('router','nft','-f','-'),input='flush map inet FP_NATIVE bind4\nadd rule inet FP_NATIVE filter_forward invalid_expression\n',text=True,capture_output=True);check('invalid native batch is atomic',r.returncode!=0 and router('nft','-j','list','table','inet','FP_NATIVE')==snapshot and probe())
 # Unrelated firewall table and chain survive every apply and maintenance.
 check('unrelated host firewall preserved','keep-unrelated' in router('iptables-save'))
 baseline=pathlib.Path('/build/flux-agent-v52-baseline')
 if baseline.exists():
  old_state=pathlib.Path('/tmp/native-old-version-state.json');old_state.write_text(json.dumps(state()));old_cfg=pathlib.Path('/tmp/native-old-version-config.json');old_cfg.write_text(json.dumps(dict(cfg,statePath=str(old_state))))
  result=subprocess.run(['unshare','--net','--fork','sh','-c','ip link set lo up; sysctl -w net.ipv4.ip_forward=1 >/dev/null; exec "$@"','sh',str(baseline),'--config',str(old_cfg)],capture_output=True,text=True,timeout=20)
  check('frozen v5.2 refuses native checkpoint even after kernel rules disappear',result.returncode!=0 and 'unsupported state format' in result.stderr)
 stop(a);before_reset=state();router('nft','delete','table','inet','FP_NATIVE');router('nft','delete','table','inet','FP4_QUOTA');router('conntrack','-F');a=agent()
 after_reset=state();check('kernel resource loss rotates its instance without resetting the ledger',after_reset['epoch']==before_reset['epoch'] and after_reset['kernelId']!=before_reset['kernelId'] and after_reset['recovery']['possibleLoss'] and after_reset['totals']['1_1_0']['up']>=before_reset['totals']['1_1_0']['up'])
 check('kernel loss cannot recreate an old credit reservation',probe() and probe(18001,True))
 stop(a);before_state=state();run(ns('router',str(BUILD/'flux-agent'),'--config',str(CONFIG),'--maintenance','uninstall','--backup-dir',str(OUT/'native-uninstall')))
 after_state=state();check('settled uninstall retains epoch and monotonic ledger',before_state['epoch']==after_state['epoch'] and after_state['totals']['1_1_0']['up']>=before_state['totals']['1_1_0']['up']);check('uninstall removes native and quota resources','FP_NATIVE' not in router('nft','list','tables') and 'FP4_QUOTA' not in router('nft','list','tables'));check('uninstall leaves external firewall','keep-unrelated' in router('iptables-save'))
 DONE=True
except Exception:
 traceback.print_exc()
 for name in ['agent.log','held.log']:
  p=OUT/name
  if p.exists():print(name,p.read_text()[-10000:])
 try:(OUT/'nft-failed.json').write_text(router('nft','-j','list','ruleset'))
 except Exception:pass
 raise
finally:
 for p in reversed(PROCS):stop(p)
 (OUT/'native-result.json').write_text(json.dumps({'success':DONE,'count':len(CHECKS),'passed':CHECKS,'external_forward_test_targets':[]},indent=2))
