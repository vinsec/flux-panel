"""Ten-minute private-netns concurrency, mutation and resource soak.
No public destination/default route exists. Default payload budget is 1 GiB
counting both application directions; control messages are excluded.
"""
from foundation_fixture import *
import statistics
SECONDS=int(os.getenv('FLUX_P1_SOAK_SECONDS','600'));COUNT=int(os.getenv('FLUX_P1_SOAK_RULES','10000'))
assert 30<=SECONDS<=1800 and 2<=COUNT<=10000
DONE=False;samples=[];updates=[];artifacts={}
def process_sample(pid):
 raw=pathlib.Path('/proc/'+str(pid)+'/stat').read_text().rsplit(')',1)[1].split();hz=os.sysconf('SC_CLK_TCK')
 return {'cpuSeconds':(int(raw[11])+int(raw[12]))/hz,'rssBytes':int(raw[21])*os.sysconf('SC_PAGE_SIZE')}
try:
 topology();server=http.server.ThreadingHTTPServer(('10.205.4.1',8000),Handler);server.daemon_threads=True;threading.Thread(target=server.serve_forever,daemon=True).start()
 CONFIG.write_text(json.dumps({'addr':'http://10.205.4.1:8000','secret':SECRET,'statePath':str(STATE),'apply':True,'allowInsecure':True,'intervalSeconds':1}))
 reportCount=[0];normalReport=PANEL.report
 def boundedReport(value):
  reportCount[0]+=1;ack=normalReport(value);PANEL.reports[:]=PANEL.reports[-2:];return ack
 PANEL.report=boundedReport
 a=agent();artifacts['agent']=hashlib.sha256((BUILD/'flux-agent').read_bytes()).hexdigest()
 rules=[{'schemaVersion':3,'id':str(i+1)+'_1_0','revision':1,'enabled':True,'listen':{'host':'10.205.1.1','port':20000+i},'targets':[{'endpoint':{'host':'10.205.3.2','port':19000},'weight':1}]} for i in range(COUNT)]
 started=time.monotonic();reply=PANEL.rpc('SubmitBatch',{'id':'soak-cold','specs':rules},timeout=180);cold=time.monotonic()-started
 if reply['data'] and isinstance(reply['data'],dict) and reply['data'].get('id'):
  job=reply['data']['id']
  def finished():
   status=PANEL.rpc('GetBatchStatus',{'id':job})['data']
   assert status['status']!='failed',status
   return status['status']=='succeeded'
  deadline=time.monotonic()+180
  while not finished():
   assert time.monotonic()<deadline,'batch deadline';time.sleep(.2)
 cold=time.monotonic()-started
 check('ten thousand advanced forwards installed through actual encrypted control',len(state()['rules'])==COUNT)
 hot=20000+COUNT-1
 clientcode=r'''import socket,time,json,pathlib,statistics
port=PORT;duration=SECONDS;setup=time.monotonic();conns=[socket.create_connection(('10.205.1.1',port),timeout=3) for _ in range(128)]
for s in conns:s.settimeout(4)
start=time.monotonic();pathlib.Path('/evidence/soak-ready.json').write_text(json.dumps({'startedAt':start,'setupSeconds':start-setup}));latency=[];count=0;payload=0;fresh=0;failures=[];freshLatency=[]
while time.monotonic()-start<duration:
 cycle=time.monotonic()
 try:
  s=conns[count%128];data=(b'x'*65536 if count%10==0 else b'x'*64);t=time.monotonic();s.sendall(data);out=b''
  while len(out)<len(data):
   b=s.recv(len(data)-len(out));assert b;out+=b
  assert out==data;latency.append((time.monotonic()-t)*1e6);payload+=len(data)*2
  if count%5==0:
   t=time.monotonic();s=socket.create_connection(('10.205.1.1',port),timeout=3);s.settimeout(3);s.sendall(b'fresh');assert s.recv(5)==b'fresh';s.close();freshLatency.append((time.monotonic()-t)*1e6);fresh+=1;payload+=10
  assert payload<=1073741824
 except Exception as e:failures.append(str(e));break
 count+=1;time.sleep(max(0,.02-(time.monotonic()-cycle)))
for s in conns:s.close()
pathlib.Path('/evidence/soak-client.json').write_text(json.dumps({'durationSeconds':time.monotonic()-start,'concurrentEstablished':128,'exchanges':count,'freshConnections':fresh,'bidirectionalApplicationBytes':payload,'failures':failures,'latencyUs':latency,'freshLatencyUs':freshLatency}))
'''.replace('PORT',str(hot)).replace('SECONDS',str(SECONDS))
 (OUT/'soak-ready.json').unlink(missing_ok=True)
 client=spawn(ns('client','python3','-c',clientcode),'soak-client.log');wait(lambda:(OUT/'soak-ready.json').exists(),90);ready=json.loads((OUT/'soak-ready.json').read_text());start=ready['startedAt'];revision=1;lastUpdate=-10
 while client.poll() is None:
  elapsed=time.monotonic()-start
  if elapsed>SECONDS+60:raise AssertionError('soak client exceeded deadline')
  row={'elapsedSeconds':elapsed,**process_sample(a.pid),'conntrackCount':int(router('cat','/proc/sys/net/netfilter/nf_conntrack_count'))};samples.append(row)
  if elapsed-lastUpdate>=10:
   revision+=1;lastUpdate=elapsed;t=time.monotonic();PANEL.rpc('SetForwardState',{'id':'1_1_0','revision':revision,'enabled':revision%2==1},timeout=40);updates.append({'elapsedSeconds':elapsed,'seconds':time.monotonic()-t,'revision':revision})
  time.sleep(1)
 assert client.wait(timeout=5)==0
 result=json.loads((OUT/'soak-client.json').read_text());check('128 established connections and repeated fresh connections remain correct during mutations',not result['failures'] and result['exchanges']>SECONDS*20)
 check('traffic and updates ran with normal one-second persistent counter reporting',reportCount[0]>SECONDS//3 and len(updates)>=SECONDS//15)
 warm=[s['rssBytes'] for s in samples if s['elapsedSeconds']>min(30,SECONDS/3)]
 check('warm RSS remains within a bounded 64 MiB band',max(warm)-min(warm)<64*1024*1024)
 # Pause one hot forwarding after the traffic run, then verify no stale flow
 # survives the policy. A resume must use the same monotonic accounting token.
 before=state();t=time.monotonic();PANEL.rpc('SetForwardState',{'id':str(COUNT)+'_1_0','revision':2,'enabled':False},timeout=40);pause=time.monotonic()-t
 check('hot forwarding pause still blocks TCP/UDP after long load',probe(hot,True))
 PANEL.rpc('SetForwardState',{'id':str(COUNT)+'_1_0','revision':3,'enabled':True},timeout=40);check('resume restores the hot forwarding without resetting its ledger',probe(hot))
 stop(a);restartStarted=time.monotonic();a=agent(timeout=90);restartSeconds=time.monotonic()-restartStarted;check('restart restores 10k advanced rules and data after concurrent load',probe(hot))
 info={'success':True,'rules':COUNT,'durationSeconds':result['durationSeconds'],'coldApplySeconds':cold,'connectionSetupSeconds':ready['setupSeconds'],'pauseSeconds':pause,'restartSeconds':restartSeconds,'agentSha256':artifacts['agent'],'reportCount':reportCount[0],'samples':samples,'updates':updates,'bidirectionalApplicationBytes':result['bidirectionalApplicationBytes'],'externalForwardTestTargets':[],'hostIsShared':True,'acceptance':'functional resource soak, not an exclusive physical-host perf attribution'}
 (OUT/'soak.json').write_text(json.dumps(info,indent=2));DONE=True
except Exception:
 traceback.print_exc()
 for name in ['agent.log','soak-client.log']:
  p=OUT/name
  if p.exists():print(p.read_text()[-4000:])
 raise
finally:
 for p in reversed(PROCS):stop(p)
 (OUT/'soak-result.json').write_text(json.dumps({'success':DONE,'passed':CHECKS,'count':len(CHECKS),'samples':samples,'updates':updates,'artifactSha256':artifacts,'externalForwardTestTargets':[]},indent=2))
