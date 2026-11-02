"""Disposable private netns only; /build/gost is the managed-capable GOST.
The private topology and controller are defined in foundation_fixture.py.
"""
from foundation_fixture import *
import hashlib
DONE=False
try:
 topology();server=http.server.ThreadingHTTPServer(('10.205.4.1',8000),Handler);server.daemon_threads=True;threading.Thread(target=server.serve_forever,daemon=True).start()
 cfg={'addr':'http://10.205.4.1:8000','secret':SECRET,'statePath':str(STATE),'apply':True,'allowInsecure':True,'intervalSeconds':1,'kernelBackend':'nftables','managedGost':{'binary':'/build/gost','sha256':hashlib.sha256(pathlib.Path('/build/gost').read_bytes()).hexdigest(),'socket':'/tmp/gost-worker/control.sock'}}
 CONFIG.write_text(json.dumps(cfg));a=agent(timeout=40)
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
 saved=state();stop(a);a=agent(timeout=40);check('restart restores GOST mode and same epoch',state()['forwardingMode']=='gost' and state()['epoch']==saved['epoch'] and probe())
 mode('kernel','switch-back-kernel');check('both engines retain one cumulative ledger',state()['epoch']==saved['epoch'] and state()['totals']['1_1_0']['up']>=saved['totals']['1_1_0']['up'])
 repeat=PANEL.rpc('SubmitModeSwitch',{'id':'switch-back-kernel','mode':'kernel'})['data'];check('same operation ID is idempotent',repeat['status']=='succeeded')
 # Faults on either side of the durable commit must restore the right mode.
 for phase,expected in [('mode-prepared','kernel'),('mode-applied','kernel'),('mode-committed','gost')]:
  stop(a);a=agent(''+phase,timeout=40)
  try:PANEL.rpc('SubmitModeSwitch',{'id':'fault-'+phase,'mode':'gost'},timeout=2)
  except AssertionError:pass
  wait(lambda:a.poll()==82,30);a=agent(timeout=40)
  check('crash recovery at '+phase,state()['forwardingMode']==expected and state()['epoch']==saved['epoch'] and probe())
  if expected=='gost':mode('kernel','restore-'+phase)
 # A normal activation failure rolls back in the same process, no restart.
 stop(a);a=agent('mode-reject',timeout=40)
 PANEL.rpc('SubmitModeSwitch',{'id':'runtime-rollback','mode':'gost'})
 failure=wait(lambda:(v if v['status'] in ['failed','blocked'] else None) if (v:=PANEL.rpc('GetModeSwitchStatus',{'id':'runtime-rollback'})['data']) else None,30)
 check('activation failure restores original mode and live forwarding',failure['status']=='failed' and state()['forwardingMode']=='kernel' and probe())
 stop(a);a=agent(timeout=40)
 # Reject an unsupported operation before touching the working kernel graph.
 rejected=dict(s);rejected['revision']=4;rejected['schemaVersion']=4;rejected['traffic']={'sourceMode':'preserve','returnPathConfirmed':True}
 apply(rejected)
 result=PANEL.rpc('SubmitModeSwitch',{'id':'unsupported-mode','mode':'gost'},success=False)
 check('unsupported source preservation rejects before stopping native traffic',not result['success'] and state()['forwardingMode']=='kernel' and probe())
 # Cross-mode strict quota uses the same local kernel budget.
 PANEL.rpc('DeleteForward',{'id':'1_1_0','revision':5})
 limited=dict(s);limited['id']='2_2_3';limited['listen']['port']=18001;limited['leaseRequired']=True;PANEL.quota=8192
 apply(limited);wait(lambda:'2_2_3' in state().get('leases',{}));mode('gost','quota-to-gost')
 code="import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(.005)\nfor _ in range(100):\n s.sendto(b'q'*1000,('10.205.1.1',18001))\n try:s.recv(4096)\n except socket.timeout:pass"
 run(ns('client','python3','-c',code))
 check('managed GOST cannot exceed shared kernel credit',probe(18001,blocked=True))
 DONE=True
except Exception:
 traceback.print_exc()
 for n in ['agent.log']:
  p=OUT/n
  if p.exists():print(p.read_text()[-12000:])
 raise
finally:
 for p in reversed(PROCS):stop(p)
 (OUT/'switch-result.json').write_text(json.dumps({'success':DONE,'passed':CHECKS,'count':len(CHECKS),'externalForwardTestTargets':[]},indent=2))
