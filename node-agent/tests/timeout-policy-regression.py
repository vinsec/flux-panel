"""Outage reproducer and lossless recovery acceptance; private namespaces only."""
from foundation_fixture import *
import shutil

def filtered(ident, port, duration, revision=1):
 return dict(schemaVersion=5,id=ident,revision=revision,enabled=True,
  listen={'host':'10.205.1.1','port':port},
  targets=[{'endpoint':{'host':'10.205.3.2','port':19000},'weight':1}],
  expiresAt=int(time.time()*1000)+duration,
  protocolFilter={'http':True,'tls':True,'socks':True,'unknown':'allow'})
def exchange(port,payload,blocked=False):
 code=f'''import socket
s=socket.create_connection(('10.205.1.1',{port}),timeout=3);s.settimeout(1.5);s.sendall({payload!r})
try:
 out=s.recv(65535);assert {blocked!r} and not out or not {blocked!r} and out=={payload!r},out
except OSError:assert {blocked!r}
'''
 run(ns('client','python3','-c',code))
def counters_monotonic(old,new):
 return old['epoch']==new['epoch'] and old['kernelId']==new['kernelId'] and all(new['totals'][k]['up']>=v['up'] and new['totals'][k]['down']>=v['down'] for k,v in old.get('totals',{}).items())

try:
 topology()
 # A persistent parser rejection used to fail both apply and rollback after
 # the packet fence. Only nft --check is faulted; production nft is untouched.
 shim=pathlib.Path('/tmp/nft-check-shim');shim.mkdir()
 real=shutil.which('nft')
 (shim/'nft').write_text('#!/usr/bin/python3\nimport os,sys\nif "-c" in sys.argv and os.path.exists("/tmp/reject-nft-check"):\n print("injected nft parser rejection",file=sys.stderr);sys.exit(1)\nos.execv('+repr(real)+', ['+repr(real)+']+sys.argv[1:])\n')
 (shim/'nft').chmod(0o755);os.environ['PATH']=str(shim)+':'+os.environ['PATH']
 server=http.server.ThreadingHTTPServer(('10.205.4.1',8000),Handler);server.daemon_threads=True;threading.Thread(target=server.serve_forever,daemon=True).start()
 write_config({'addr':'http://10.205.4.1:8000','secret':SECRET,'statePath':str(STATE),'apply':True,'allowInsecure':True,'intervalSeconds':1})
 a=agent()
 durations=[99999999,100000000,2147483647,2147483648,4294967295,4294967296,49*86400000,52*86400000,138*86400000]
 rules=[filtered(f'{i+1}_1_0',18000+i,d) for i,d in enumerate(durations)]
 result=job({'id':'ab'*16,'baseGeneration':state()['generation'],'specs':rules})
 check('all parser boundaries and 49/52/138-day authorizations install as a batch',result['status']=='succeeded' and len(state()['rules'])==len(rules))
 for i in range(len(rules)):check('long-authorization TCP/UDP '+str(i),probe(18000+i))
 exchange(18000,b'GET / HTTP/1.1\r\nHost: private.test\r\n\r\n',True)
 # Same endpoints, schema 5 -> 2, no policy fields. All three formerly
 # blocked plaintext protocols must pass after the removal.
 off=spec('1_1_0',18000,2);off['schemaVersion']=2;off['listen']={'host':'10.205.1.1','port':18000};off['target']={'host':'10.205.3.2','port':19000};off['expiresAt']=rules[0]['expiresAt']
 apply(off)
 for payload in [b'GET / HTTP/1.1\r\nHost: private.test\r\n\r\n',b'\x05\x01\x00',b'\x16\x03\x03\x00\x00']:
  exchange(18000,payload)
 check('schema downgrade removes HTTP/TLS/SOCKS filtering, not just its UI state',not state()['rules']['1_1_0'].get('protocolFilter'))
 # Keep exactly one TCP socket across rejection, graceful restart, and WAL
 # recovery. No reconnect is allowed in this independent peer.
 held_code='''import socket,time,pathlib,json
s=socket.create_connection(('10.205.1.1',18000),timeout=3);s.settimeout(12);start=time.monotonic();last=start;maximum=0;n=0
try:
 while not pathlib.Path('/tmp/held-finish').exists():
  data=(str(n)+'|').encode();s.sendall(data);out=b''
  while len(out)<len(data):
   b=s.recv(len(data)-len(out));assert b,'closed';out+=b
  assert out==data
  now=time.monotonic();maximum=max(maximum,now-last);last=now;n+=1;pathlib.Path('/tmp/held-ready').touch();time.sleep(.02)
 pathlib.Path('/tmp/held-result.json').write_text(json.dumps({'success':True,'messages':n,'max_gap_seconds':maximum,'socket_source_port':s.getsockname()[1]}))
except Exception as e:
 pathlib.Path('/tmp/held-result.json').write_text(json.dumps({'success':False,'error':repr(e),'messages':n}));raise
'''
 held=spawn(ns('client','python3','-c',held_code),'held-repair.log');wait(lambda:pathlib.Path('/tmp/held-ready').exists())
 before=state();pathlib.Path('/tmp/reject-nft-check').touch()
 bad=dict(off,revision=3,expiresAt=off['expiresAt']+1000)
 rejected=apply(bad,False)
 check('persistent parser failure is rejected before fencing or creating a WAL',not rejected['success'] and not pathlib.Path(str(STATE)+'.journal').exists() and state()['generation']==before['generation'] and held.poll() is None)
 pathlib.Path('/tmp/reject-nft-check').unlink();check('old TCP/UDP remains usable after failed config',probe())
 apply(bad);check('valid retry works without restart or recovery intervention',probe())
 # An actual previous-version checkpoint is used for the timed upgrade.
 # Give the old formatter a safe compound-duration graph first.
 for r in rules[1:]:
  r['revision']=2;r['expiresAt']=int(time.time()*1000)+138*86400000;apply(r)
 bad['revision']=4;bad['expiresAt']=int(time.time()*1000)+138*86400000;apply(bad)
 before=state();stop(a)
 candidate=BUILD/'flux-agent';baseline=BUILD/'flux-agent-baseline'
 shutil.copy2(candidate,BUILD/'flux-agent-candidate');shutil.copy2(baseline,candidate)
 started=time.monotonic();a=agent();old_ready=time.monotonic()-started
 check('previous binary can run the same checkpoint before replacement',probe())
 before=state();started=time.monotonic();stop(a);shutil.copy2(BUILD/'flux-agent-candidate',candidate);a=agent();probe();elapsed=time.monotonic()-started
 check('same-engine binary cutover recovers under 30 seconds',elapsed<30)
 check('binary cutover preserves epoch, kernel identity and each cumulative counter',counters_monotonic(before,state()))
 # A candidate that cannot execute must be backed out without restoring an
 # older ledger checkpoint or deleting the existing NAT/conntrack objects.
 before=state();started=time.monotonic();stop(a)
 candidate.write_text('#!/bin/sh\nexit 70\n');candidate.chmod(0o755)
 failed=spawn(ns('router',str(candidate),'--config',str(CONFIG)),'failed-candidate.log');wait(lambda:failed.poll() is not None)
 shutil.copy2(baseline,candidate);a=agent();probe();rollback_elapsed=time.monotonic()-started
 check('failed candidate rolls back under 30 seconds without reverting the ledger',rollback_elapsed<30 and counters_monotonic(before,state()))
 stop(a);shutil.copy2(BUILD/'flux-agent-candidate',candidate);a=agent()
 # Restore a 49-day graph then crash at a real transaction boundary. The
 # new executable must recover it with no external PATH compatibility layer.
 current=state()['rules']['2_1_0'];rev=current['revision']+1
 recover_rule=filtered('2_1_0',18001,49*86400000,rev);apply(recover_rule);before=state();stop(a);a=agent('prepared')
 def crash_request():
  try:apply(dict(recover_rule,revision=rev+1,expiresAt=recover_rule['expiresAt']+1000))
  except Exception:pass
 started=time.monotonic();threading.Thread(target=crash_request,daemon=True).start()
 wait(lambda:a.poll() is not None);check('interrupted configuration leaves a real recovery journal',pathlib.Path(str(STATE)+'.journal').exists())
 a=agent();probe();recovery_elapsed=time.monotonic()-started
 check('long-timeout journal replay finishes under 30 seconds',recovery_elapsed<30 and not pathlib.Path(str(STATE)+'.journal').exists())
 check('journal rollback retains exact rules and per-rule accounting',set(state()['rules'])==set(before['rules']) and counters_monotonic(before,state()))
 pathlib.Path('/tmp/held-finish').touch();wait(lambda:held.poll() is not None)
 held_result=json.loads(pathlib.Path('/tmp/held-result.json').read_text());check('one established TCP socket survives every cutover without reconnect',held_result['success'])
 # A coordinator with a fixed lifetime budget models legitimate lease
 # settlement/reissue on policy changes and pause/resume. It never reuses a
 # closed lease ID or replenishes already consumed traffic.
 budget={'used':0,'claims':{},'grant':None,'generation':0}
 def limited_report(r):
  PANEL.reports.append(r)
  ack={'epoch':r['epoch'],'sequence':r['sequence'],'usage':r['usage'],'counters':r.get('counters',[]),'closedLeases':[l['id'] for l in r.get('leases',[]) if l['closed']],'leaseWatermarks':r.get('leases',[]),'grants':[]}
  for claim in r.get('leases',[]):
   if claim['serviceId']!='20_2_3':continue
   prior=budget['claims'].get(claim['id'],0);assert claim['used']>=prior
   budget['used']+=claim['used']-prior;budget['claims'][claim['id']]=claim['used'];assert budget['used']<=8192
   if claim['closed'] and budget['grant'] and budget['grant']['id']==claim['id']:budget['grant']=None
  if '20_2_3' in r.get('requests',[]) and budget['used']<8192:
   if budget['grant'] is None:
    budget['generation']+=1
    budget['grant']={'id':format(budget['generation'],'032x'),'serviceId':'20_2_3','epoch':r['epoch'],'bootId':r['bootId'],'generation':budget['generation'],'totalGranted':8192-budget['used'],'windowBytes':8192-budget['used'],'requestSequence':r['sequence'],'validForMillis':60000}
   g=dict(budget['grant'],requestSequence=r['sequence']);ack['grants']=[g]
  return ack
 PANEL.report=limited_report
 PANEL.quota=8192;limited=filtered('20_2_3',18020,138*86400000);limited['leaseRequired']=True;apply(limited);wait(lambda:'20_2_3' in state().get('leases',{}));probe(18020)
 lease_before=state();stop(a);started=time.monotonic();a=agent();lease_elapsed=time.monotonic()-started
 check('credit lease remains reserved across restart',state()['leases']['20_2_3']['grant']['id']==lease_before['leases']['20_2_3']['grant']['id'] and counters_monotonic(lease_before,state()))
 downgraded=spec('20_2_3',18020,2);downgraded.update(schemaVersion=2,listen={'host':'10.205.1.1','port':18020},target={'host':'10.205.3.2','port':19000},leaseRequired=True,expiresAt=limited['expiresAt']);apply(downgraded)
 wait(lambda:state()['leases']['20_2_3']['grant']['id']!=lease_before['leases']['20_2_3']['grant']['id'] and not state()['leases']['20_2_3']['closed']);probe(18020)
 check('policy removal settles the old lease and reserves only the remaining budget',not state()['rules']['20_2_3'].get('protocolFilter') and state()['leases']['20_2_3']['grant']['totalGranted']<8192)
 PANEL.rpc('SetForwardState',{'id':limited['id'],'revision':3,'enabled':False});check('pause still blocks TCP and UDP',probe(18020,True))
 PANEL.rpc('SetForwardState',{'id':limited['id'],'revision':4,'enabled':True});wait(lambda:not state()['leases']['20_2_3']['closed']);probe(18020)
 run(ns('client','python3','-c',"import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(.01)\nfor i in range(100):\n s.sendto(b'q'*500,('10.205.1.1',18020))\n try:s.recv(2048)\n except socket.timeout:pass"))
 PANEL.rpc('CollectCounters');total=state()['totals']['20_2_3'];check('schema downgrade cannot reset or enlarge the shared 8KiB quota',0<total['up']+total['down']<=8192 and probe(18020,True))
 check('unrelated firewall remains untouched','keep-unrelated' in router('iptables-save'))
 (OUT/'timings.json').write_text(json.dumps({'upgrade_seconds':elapsed,'failed_candidate_rollback_seconds':rollback_elapsed,'journal_recovery_seconds':recovery_elapsed,'lease_restart_seconds':lease_elapsed,'old_start_seconds':old_ready,'held_connection':held_result},indent=2))
 DONE=True
except Exception:
 traceback.print_exc()
 try:print((OUT/'agent.log').read_text()[-5000:])
 except Exception:pass
 raise
finally:
 for p in reversed(PROCS):stop(p)
 (OUT/'timeout-policy-result.json').write_text(json.dumps({'success':DONE,'count':len(CHECKS),'passed':CHECKS,'external_forward_test_targets':[]},indent=2))
