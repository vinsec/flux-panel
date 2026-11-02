"""Disposable private netns only; /build/gost is the managed-capable GOST.
See doc/unified-agent-switching.md for the isolated runner.
"""
from foundation_fixture import *
import hashlib
DONE=False
try:
 topology();server=http.server.ThreadingHTTPServer(('10.205.4.1',8000),Handler);server.daemon_threads=True;threading.Thread(target=server.serve_forever,daemon=True).start()
 cfg={'addr':'http://10.205.4.1:8000','secret':SECRET,'statePath':str(STATE),'apply':True,'allowInsecure':True,'intervalSeconds':1,'kernelBackend':'nftables','managedGost':{'binary':'/build/gost','sha256':hashlib.sha256(pathlib.Path('/build/gost').read_bytes()).hexdigest(),'socket':'/tmp/worker/control.sock'}}
 shared=pathlib.Path('/tmp/shared');shared.mkdir(mode=0o750);os.chown(shared,0,12345)
 worker=pathlib.Path('/tmp/worker');worker.mkdir(mode=0o750);os.chown(worker,12345,12345);worker.chmod(0o750)
 cfg['helperSocket']=str(shared/'kernel.sock')
 CONFIG.write_text(json.dumps(cfg));CONFIG.chmod(0o644)
 helper=spawn(ns('router','setpriv','--regid=12345','--clear-groups','--bounding-set=-all,+net_admin,+net_raw,+net_bind_service',str(BUILD/'flux-agent'),'--kernel-helper','--helper-user','12345','--config',str(CONFIG)),'helper.log')
 wait(lambda:pathlib.Path(cfg['helperSocket']).exists(),40)
 def agent(fault='',timeout=40):
  serial=PANEL.serial
  p=spawn(ns('router','setpriv','--reuid=12345','--regid=12345','--clear-groups','--bounding-set=-all',str(BUILD/'flux-agent'),'--config',str(CONFIG)),'network.log');wait(lambda:PANEL.serial>serial and p.poll() is None,timeout);return p
 a=agent(timeout=40)
 check('managed worker exposes no TCP management listener',not router('ss','-H','-lnt'))
 check('network transport has zero capabilities','CapEff:\t0000000000000000' in pathlib.Path('/proc/'+str(a.pid)+'/status').read_text())
 check('helper lacks SYS_ADMIN and SETUID',all(int(line.split()[1],16)&((1<<21)|(1<<7))==0 for line in pathlib.Path('/proc/'+str(helper.pid)+'/status').read_text().splitlines() if line.startswith(('CapEff:','CapBnd:'))))
 s={'schemaVersion':3,'id':'1_1_0','revision':1,'enabled':True,'listen':{'host':'10.205.1.1','port':18000},'targets':[{'endpoint':{'host':'10.205.3.2','port':19000},'weight':1}]}
 apply(s);check('initial native mode forwards TCP and UDP',probe())
 def mode(target,ident):
  result=PANEL.rpc('SubmitModeSwitch',{'id':ident,'mode':target})['data'];assert result['id']==ident
  job=wait(lambda:(v if v['status'] in ['succeeded','failed','blocked'] else None) if (v:=PANEL.rpc('GetModeSwitchStatus',{'id':ident})['data']) else None,60)
  assert job['status']=='succeeded',job
  check('same-node mode switch to '+target,probe(18001) if ident=='quota-to-gost' else probe())
 before=state();mode('gost','switch-to-gost');after=state()
 check('mode and format durable; epoch and totals continuous',after['forwardingMode']=='gost' and after['formatVersion']==8 and after['epoch']==before['epoch'] and after['totals']['1_1_0']['up']>=before['totals']['1_1_0']['up'])
 def exact():
  def counters():
   out=[0,0]
   for item in json.loads(router('nft','-j','list','table','inet','FP_NATIVE'))['nftables']:
    c=item.get('counter')
    if not c:continue
    for i,d in enumerate(['up','down']):
     if c['comment'].endswith('|flux:v2:1_1_0:'+d):out[i]+=c['bytes']
   return out
  b=counters();run(ns('client','python3','-c',"import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(2);s.sendto(b'a'*123,('10.205.1.1',18000));assert s.recv(1000)==b'a'*123"));c=counters()
  check('GOST client-facing network bytes counted exactly once',[y-x for x,y in zip(b,c)]==[151,151])
 exact()
 PANEL.rpc('SetForwardState',{'id':'1_1_0','revision':2,'enabled':False});check('managed GOST pause blocks both protocols',probe(blocked=True))
 PANEL.rpc('SetForwardState',{'id':'1_1_0','revision':3,'enabled':True});check('managed GOST resume restores forwarding',probe())
 # Backends must not become unmetered public listeners.
 port=next(iter(json.loads(pathlib.Path(str(STATE)+'.gost-ports.json').read_text()).values()))
 result=subprocess.run(ns('client','python3','-c',f"import socket;s=socket.socket();s.settimeout(.3)\ntry:s.connect(('10.205.1.1',{port}));raise AssertionError('private backend reachable')\nexcept OSError:pass"),capture_output=True,text=True)
 check('managed worker backend refuses unmarked direct ingress',result.returncode==0)
 # Killing the worker must recover under the same unprivileged supervisor.
 children=[]
 for d in pathlib.Path('/proc').glob('[0-9]*'):
  try:
   text=(d/'status').read_text()
   if 'PPid:\t'+str(a.pid)+'\n' in text and 'gost' in (d/'cmdline').read_text():children.append(int(d.name))
  except OSError:pass
 assert len(children)==1,children
 check('managed GOST child also has zero capabilities','CapEff:\t0000000000000000' in pathlib.Path('/proc/'+str(children[0])+'/status').read_text())
 os.kill(children[0],signal.SIGKILL);time.sleep(.2)
 check('worker crash automatically recovers without changing epoch',wait(lambda:probe(),40) and state()['epoch']==after['epoch'])
 saved=state();stop(a);a=agent(timeout=40);check('restart restores GOST mode and same epoch',state()['forwardingMode']=='gost' and state()['epoch']==saved['epoch'] and wait(lambda:probe(),40))
 # Mirror Type=simple boot ordering: helper starts before network/worker.
 stop(a);stop(helper)
 helper=spawn(ns('router','setpriv','--regid=12345','--clear-groups','--bounding-set=-all,+net_admin,+net_raw,+net_bind_service',str(BUILD/'flux-agent'),'--kernel-helper','--helper-user','12345','--config',str(CONFIG)),'helper.log')
 a=agent(timeout=40)
 check('GOST-mode helper starts before network worker without restart loop',helper.poll() is None and state()['forwardingMode']=='gost' and wait(lambda:probe(),40))
 mode('kernel','switch-back-kernel');check('both engines retain one cumulative ledger',state()['epoch']==saved['epoch'] and state()['totals']['1_1_0']['up']>=saved['totals']['1_1_0']['up'])
 repeat=PANEL.rpc('SubmitModeSwitch',{'id':'switch-back-kernel','mode':'kernel'})['data'];check('same operation ID is idempotent',repeat['status']=='succeeded')
 DONE=True
except Exception:
 traceback.print_exc()
 for n in ['agent.log']:
  p=OUT/n
  if p.exists():print(p.read_text()[-12000:])
 raise
finally:
 for p in reversed(PROCS):stop(p)
 (OUT/'switch-unprivileged-result.json').write_text(json.dumps({'success':DONE,'passed':CHECKS,'count':len(CHECKS),'externalForwardTestTargets':[]},indent=2))
