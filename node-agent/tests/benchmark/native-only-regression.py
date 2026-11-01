"""Same HTTP/TLS/SOCKS switches: frozen native v5.5 vs native-only candidate.
Run only in a private mount+network namespace, no public/default route.
"""
from pathlib import Path
import os
os.environ.update(FLUX_BENCH_FOUNDATION_CREDIT_ONLY='1',FLUX_BENCH_P1='1',FLUX_BENCH_V2='1',FLUX_BENCH_STRICT='1',FLUX_BENCH_PACED_SECONDS='20',FLUX_BENCH_BYTE_LIMIT=str(256*1024**3))
source=Path('/code/benchmark.py').read_text().replace('mount -o remount,rw /proc/sys && sysctl','(mount -o remount,rw /proc/sys || true); sysctl')
exec(compile(source[:source.rindex('\ntry:main()')],'/code/benchmark.py','exec'))
COUNT=int(os.getenv('FLUX_NATIVE_COMPARE_COUNT','3'));ROUNDS=int(os.getenv('FLUX_NATIVE_COMPARE_ROUNDS','3'));assert COUNT in [3,20,10000] and 1<=ROUNDS<=3
ARTIFACTS={p:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in ['/build/flux-agent-v55-baseline','/build/flux-agent-native','/build/bench-peer']}
assert ARTIFACTS['/build/flux-agent-v55-baseline']=='150b81c5937ddd54692970210e92830cad510f5ce0f00d4c29948933083fe1f9'
assert ARTIFACTS['/build/flux-agent-native']==os.environ['FLUX_CANDIDATE_SHA256']
PROGRAMS=[];CASE_INDEX=0;PROOF=[];CASES=[];STEADY=[];BULK=[];DELAYS=[]

def reset():
 for table in ['FP_NATIVE','FP_PROTOCOL','FP4_QUOTA']:
  subprocess.run(ns('router','nft','delete','table','inet',table),capture_output=True)
 clean_rules()

def setup_case(engine,index):
 global CASE_INDEX
 reset();CASE_INDEX+=1;path=Path(f'/tmp/gost-dpi-{engine}-{COUNT}-{index}');path.mkdir()
 data=specs(COUNT)

 for s in data.values():
  s.update(schemaVersion=5,listen={'host':s['listenIP'],'port':s['listenPort']},targets=[{'endpoint':{'host':s['targetIP'],'port':s['targetPort']},'weight':1}],protocolFilter={'http':True,'tls':True,'socks':True,'unknown':'allow'})
  s['runtime']={'status':'ready','targets':[{'host':s['targetIP'],'port':s['targetPort'],'family':'ipv4','origin':s['targetIP']+':'+str(s['targetPort']),'weight':1,'healthy':True,'acceptNew':True}]}
 backend='nftables'
 router('iptables','-P','FORWARD','ACCEPT')
 state={'kernelBackend':backend,'epoch':hashlib.md5(str(path).encode()).hexdigest(),'sequence':0,'rules':data,'totals':{},'last':{}}
 (path/'state.json').write_text(json.dumps(state));(path/'config.json').write_text(json.dumps({'addr':'ws://10.204.3.1:8000','secret':'isolated-benchmark-only','statePath':str(path/'state.json'),'kernelBackend':backend,'apply':True,'allowInsecure':True,'intervalSeconds':1}));binary='/build/flux-agent-native' if engine=='native' else '/build/flux-agent-v55-baseline';args=[binary,'--config',str(path/'config.json')];cwd=None
 env=dict(os.environ,GOMAXPROCS='1',GOST_LOGGER_LEVEL='error');p=spawn(ns('router','taskset','-c',str(CPU),*args),f'{engine}-{COUNT}-{index}',cwd=cwd,env=env)
 deadline=time.monotonic()+60
 while True:
  if p.poll() is not None:raise RuntimeError('forwarder failed: '+(OUT/f'{engine}-{COUNT}-{index}.log').read_text()[-2000:])
  try:
   v=json.loads(run(ns('client','taskset','-c',str(CPU),'/build/bench-peer','-host','10.204.1.1','-port','18001','-samples','1','-pace-us','0'),timeout=3))
   if v['samples']==1 and not v['lost']:break
  except (RuntimeError,subprocess.TimeoutExpired):pass
  assert time.monotonic()<deadline,'readiness deadline';time.sleep(.1)
 assert hashlib.sha256(Path('/proc/'+str(p.pid)+'/exe').read_bytes()).hexdigest()==ARTIFACTS[binary]
 assert json.loads((path/'state.json').read_text())['formatVersion']==7
 program=[{k:v for k,v in item['rule'].items() if k not in ['handle','index']} for item in json.loads(router('nft','-j','list','table','inet','FP_NATIVE'))['nftables'] if 'rule' in item]
 PROGRAMS.append({'engine':engine,'count':COUNT,'round':index,'sha256':hashlib.sha256(json.dumps(program,sort_keys=True).encode()).hexdigest()})
 time.sleep(.5);return p

def policy_proof(engine,p):
 for name,payload in [('HTTP',b'GET / HTTP/1.1\r\nHost: private.test\r\n\r\n'),('TLS',b'\x16\x03\x03\x00\x04\x01\x00\x00\x00'),('SOCKS5',b'\x05\x01\x00'),('SOCKS4',b'\x04\x01\x01\xbb\x7f\x00\x00\x01\x00')]:
  code=f"import socket;s=socket.create_connection(('10.204.1.1',18001),timeout=2);s.settimeout(.4);s.sendall({payload!r})\ntry:assert not s.recv(1024)\nexcept OSError:pass"
  run(ns('client','python3','-c',code));PROOF.append({'engine':engine,'ruleCount':COUNT,'protocol':name,'blocked':True})
 for proto in ['tcp','udp']:
  v=json.loads(run(ns('client','taskset','-c',str(CPU),'/build/bench-peer','-host','10.204.1.1','-port','18001','-protocol',proto,'-samples','10','-pace-us','0'),timeout=5));assert v['samples']==10 and v['lost']==0
 PROOF.append({'engine':engine,'ruleCount':COUNT,'opaqueTCPAndUDPAllowed':True})
 (OUT/'policy-proof.json').write_text(json.dumps(PROOF,indent=2))

def steady(engine,index,p,mbps):
 global TOTAL_BYTES
 before=proc(p);a=snapshot();v=json.loads(run(ns('client','taskset','-c',str(CPU),'iperf3','-c','10.204.1.1','-p','30000','-t','20','-b',f'{mbps}M','-J'),timeout=30));b=snapshot();after=proc(p);assert 'error' not in v,v
 end=v['end'];received=end['sum_received'];sent=end['sum_sent'];assert received['bytes']>0 and abs(received['bits_per_second']/1e6-mbps)/mbps<.02
 TOTAL_BYTES+=received['bytes'];assert TOTAL_BYTES<BYTE_LIMIT
 row={'engine':engine,'rules':COUNT,'round':index,'profile':f'{mbps}Mbps_single_stream','receivedBytes':received['bytes'],'mbps':received['bits_per_second']/1e6,'forwarderCPUSeconds':after['seconds']-before['seconds'],'forwarderCPUPercent':(after['seconds']-before['seconds'])/(b['time']-a['time'])*100,'rssBytes':after['rss'],'cpu':delta(a,b)};STEADY.append(row)
 (OUT/f'iperf-{engine}-{index}-{mbps}.json').write_text(json.dumps(v));print('STEADY',engine,COUNT,index,mbps,round(row['forwarderCPUPercent'],2),'CPU%',flush=True)

def delays(engine,index,p):
 for proto,fresh,n in [('tcp',False,5000),('tcp',True,1000),('udp',False,5000)]:
  args=['/build/bench-peer','-host','10.204.1.1','-port','18001','-protocol',proto,'-samples',str(n),'-pace-us','1000']
  if fresh:args+=['-fresh']
  a=snapshot();v=json.loads(run(ns('client','taskset','-c',str(CPU),*args),timeout=20));b=snapshot();assert v['samples']==n and v['lost']==0
  v.update(engine=engine,rules=COUNT,round=index,profile='fresh_response' if fresh else proto+'_persistent',cpu=delta(a,b));DELAYS.append(v);print('LATENCY',engine,COUNT,index,v['profile'],v['p50_us'],v['p95_us'],flush=True)
 (OUT/'latency-progress.json').write_text(json.dumps(DELAYS))

def bulk(engine,index,p,reverse,parallel):
 global TOTAL_BYTES
 size=1024**3;args=['/build/bench-peer','-host','10.204.1.1','-port','18000','-bulk-bytes',str(size),'-parallel',str(parallel)]
 if reverse:args+=['-reverse']
 before=proc(p);a=snapshot();v=json.loads(run(ns('client','taskset','-c',str(CPU),*args),timeout=30));b=snapshot();after=proc(p);assert v['receiver_acknowledged'] and v['bytes']==size;TOTAL_BYTES+=size
 v.update(engine=engine,rules=COUNT,round=index,profile='bulk_'+('download' if reverse else 'upload')+f'_{parallel}stream',forwarderCPUSeconds=after['seconds']-before['seconds'],cpu=delta(a,b));BULK.append(v)

def continuous(engine,index,p):
 startIP=40+(CASE_INDEX-1)*20;before=proc(p);a=snapshot();values=[];lost=0
 for j in range(20):
  ip='10.204.1.'+str(startIP+j);run(['ip','-n','client','addr','add',ip+'/32','dev','c0']);run(['ip','-n','client','route','replace','10.204.1.0/24','dev','c0','src',ip])
  v=json.loads(run(ns('client','taskset','-c',str(CPU),'/build/bench-peer','-host','10.204.1.1','-port','18001','-protocol','tcp','-fresh','-pace-us','0','-samples','5000'),timeout=30));assert v['samples']==5000 and v['lost']==0;values.extend(v['values_us']);lost+=v['lost']
 b=snapshot();after=proc(p);values.sort();row={'engine':engine,'rules':COUNT,'round':index,'samples':len(values),'lost':lost,'cps':len(values)/(b['time']-a['time']),'p50_us':values[(len(values)-1)//2],'p95_us':values[int((len(values)-1)*.95)],'p99_us':values[int((len(values)-1)*.99)],'forwarderCPUSecondsPer1000':(after['seconds']-before['seconds'])/(len(values)/1000),'cpu':delta(a,b)};CASES.append(row);(OUT/'continuous-progress.json').write_text(json.dumps(CASES,indent=2));print('CONTINUOUS',engine,COUNT,index,round(row['cps']),row['p50_us'],row['p95_us'],flush=True)

try:
 topology();server=http.server.ThreadingHTTPServer(('10.204.3.1',8000),Sink);server.daemon_threads=True;server.leases={};threading.Thread(target=server.serve_forever,daemon=True).start()
 for index,order in enumerate([['baseline','native'],['native','baseline'],['baseline','native']][:ROUNDS]):
  for engine in order:
   p=setup_case(engine,index)
   try:
    policy_proof(engine,p)
    if os.getenv('FLUX_NATIVE_COMPARE_SMOKE')!='1':
     steady(engine,index,p,150)
     if COUNT==3:steady(engine,index,p,25)
     delays(engine,index,p);continuous(engine,index,p)
     bulk(engine,index,p,True,1);bulk(engine,index,p,False,1)
     if COUNT==3:bulk(engine,index,p,True,4)
   finally:stop(p)
 assert ARTIFACTS=={p:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in ARTIFACTS}
 (OUT/'comparison.json').write_text(json.dumps({'success':True,'artifactSHA256':ARTIFACTS,'logicalRules':COUNT,'rounds':ROUNDS,'nativeProgramHashes':PROGRAMS,'allProtocolSwitches':{'http':1,'tls':1,'socks':1},'policyProof':PROOF,'continuous':CASES,'steady':STEADY,'latency':DELAYS,'bulk':BULK,'payloadBytes':TOTAL_BYTES,'externalForwardTestTargets':[],'scope':'opaque transport, no proxy encryption; all processes share testCPU1, GOMAXPROCS1; both native backends report1s; frozen v5.5 vs native-only v6'},indent=2))
finally:
 for p in reversed(PROCESSES):stop(p)
