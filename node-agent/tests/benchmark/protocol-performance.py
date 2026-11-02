"""Three-way rotated v5.4 DPI-on / v5.5 DPI-off / v5.5 DPI-on native nft regression.
Same private VM topology and 8GiB windows as the accepted v5.2 experiment.
"""
from pathlib import Path
import os
os.environ.update(FLUX_BENCH_FOUNDATION_CREDIT_ONLY='1',FLUX_BENCH_P1='1',FLUX_BENCH_V2='1',FLUX_BENCH_STRICT='1',FLUX_BENCH_BYTE_LIMIT=str(512*1024**3),FLUX_BENCH_PACED_SECONDS='20')
PERF_BACKEND=os.getenv('FLUX_PERF_BACKEND','nftables')
assert PERF_BACKEND in ['iptables','nftables']
ROLES=os.getenv('FLUX_PERF_ROLES','iptables,iptables_v2,iptables_p1').split(',')
ROUNDS=int(os.getenv('FLUX_PERF_ROUNDS','3'));assert 1<=ROUNDS<=3
COUNTS=[int(n) for n in os.getenv('FLUX_PERF_COUNTS','3,10000').split(',')]
source=Path('/code/benchmark.py').read_text()
source=source.replace('/build/flux-agent-v2','/build/flux-agent-native').replace("else '/build/flux-agent'","else '/build/flux-agent-v54-baseline'")
source=source.replace("if os.getenv('FLUX_BENCH_FOUNDATION_CREDIT_ONLY')=='1' and engine=='iptables_v2':","if False:")
source=source.replace(" clean_rules();path=", " clean_rules();router('iptables','-P','FORWARD',"+repr('ACCEPT' if PERF_BACKEND=='nftables' else 'DROP')+");path=")
source=source.replace(" state={'epoch':", " state={'kernelBackend':"+repr(PERF_BACKEND)+",'epoch':")
source=source.replace("'statePath':str(path/'state.json'),'apply':True", "'statePath':str(path/'state.json'),'kernelBackend':"+repr(PERF_BACKEND)+",'apply':True")
source=source.replace(" if engine=='iptables_p1':", " if False:")
source=source.replace("def clean_rules():", "def clean_rules():\n subprocess.run(ns('router','nft','delete','table','inet','FP_NATIVE'),capture_output=True)\n subprocess.run(ns('router','nft','delete','table','inet','FP_PROTOCOL'),capture_output=True)")
source=source.replace(" args=['iperf3','-c',ip,'-p',port,'-J']"," if profile=='tcp_paced':port='30000'\n args=['iperf3','-c',ip,'-p',port,'-J']")
source=source.replace("timeout=15)\n b=snapshot()", "timeout=max(15,int(os.environ['FLUX_BENCH_PACED_SECONDS'])+8))\n b=snapshot()")
source=source.replace("mount -o remount,rw /proc/sys && sysctl", "(mount -o remount,rw /proc/sys || true); sysctl").replace('deadline=time.monotonic()+20','deadline=time.monotonic()+90').replace('if time.monotonic()-START>(900','if time.monotonic()-START>(1800')
exec(compile(source[:source.rindex('\ntry:main()')],'/code/benchmark.py','exec'))
original_specs=specs
def specs(count):
 rules=original_specs(count)
 for s in rules.values():
  s.update(schemaVersion=3,listen={'host':s['listenIP'],'port':s['listenPort']},targets=[{'endpoint':{'host':s['targetIP'],'port':s['targetPort']},'weight':1}])
  s['runtime']={'status':'ready','targets':[{'host':s['targetIP'],'port':s['targetPort'],'family':'ipv4','origin':s['targetIP']+':'+str(s['targetPort']),'weight':1,'healthy':True,'acceptNew':True}]}
 if CURRENT_PROFILE in ['iptables','iptables_p1']:
  for s in rules.values():s.update(schemaVersion=5,protocolFilter={'http':True,'tls':True,'socks':True,'unknown':'allow'})
 return rules
artifacts={p:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in ['/build/flux-agent-v54-baseline','/build/flux-agent-native','/build/bench-peer']}
CURRENT_PROFILE='iptables'
CASE_INDEX=0
PROGRAMS={}
original_setup=setup
def setup(engine,count,round_id):
 global CURRENT_PROFILE,CASE_INDEX
 CURRENT_PROFILE=engine
 CASE_INDEX+=1
 clientIP="10.204.1."+str(10+CASE_INDEX)
 run(["ip","-n","client","addr","add",clientIP+"/32","dev","c0"])
 run(["ip","-n","client","route","replace","10.204.1.0/24","dev","c0","src",clientIP])
 p=original_setup(engine,count,round_id)
 expected='/build/flux-agent-v54-baseline' if engine=='iptables' else '/build/flux-agent-native'
 actual=hashlib.sha256(Path('/proc/'+str(p.pid)+'/exe').read_bytes()).hexdigest();assert actual==artifacts[expected]
 state=json.loads(Path(f'/tmp/{engine}-{count}-{round_id}/state.json').read_text());expected_backend=PERF_BACKEND;assert state.get('kernelBackend','iptables')==expected_backend
 if expected_backend=='iptables':assert state['formatVersion']==(4 if engine=='iptables_v2' else 7)
 if expected_backend=='nftables':assert state['formatVersion']==(6 if engine=='iptables_v2' else 7) and 'FP_NATIVE' in router('nft','list','tables') and not router('ipset','list','-name')
 if PERF_BACKEND=='iptables':
  import shlex
  program={}
  for table in ['mangle','nat','filter']:
   raw=router('iptables-save','-t',table)
   program[table]=[shlex.split(line) for line in raw.splitlines() if line.startswith('-A ')]
   if (engine,count) not in PROGRAMS:(OUT/f'program-{engine}-{count}-{table}.txt').write_text(raw)
  PROGRAMS[(engine,count)]=hashlib.sha256(json.dumps(program,sort_keys=True).encode()).hexdigest()
 return p
start=source.index('\ndef latency(');end=source.index('\ndef collection(',start)
exec(compile(source[start:end].replace("[('tcp',False,500),('tcp',True,100),('udp',False,500)]", "[('tcp',False,5000),('tcp',True,1000),('udp',False,5000)]"),'/code/benchmark.py','exec'))
WINDOWS=[]
FRESH=[]
window_source=Path('/code/p2-security-window.py').read_text()
start=window_source.index('\ndef window(');end=window_source.index('\ntry:\n topology();',start)
exec(compile(window_source[start:end],'/code/p2-security-window.py','exec'))
labels={'iptables':'baseline_v54_dpi_on','iptables_v2':'candidate_dpi_off','iptables_p1':'candidate_dpi_on'}
try:
 topology();server=http.server.ThreadingHTTPServer(('10.204.3.1',8000),Sink);server.daemon_threads=True;server.leases={};threading.Thread(target=server.serve_forever,daemon=True).start()
 for count in COUNTS:
  for index,order in enumerate([['iptables','iptables_v2','iptables_p1'],['iptables_p1','iptables','iptables_v2'],['iptables_v2','iptables_p1','iptables']][:ROUNDS]):
   for engine in order:
    if engine not in ROLES:continue
    round_id=70000+count*10+index;p=setup(engine,count,round_id)
    try:
     window(engine,count,round_id,p,False);window(engine,count,round_id,p,True)
     measure(engine,count,round_id,'tcp_paced',p);latency(engine,count,round_id,p,True)
     if count==10000:
      before=proc(p);a=snapshot();v=json.loads(run(ns('client','taskset','-c',str(CPU),'/build/bench-peer','-host','10.204.1.1','-port','18001','-protocol','tcp','-fresh','-pace-us','0','-samples','5000'),timeout=25));b=snapshot();after=proc(p)
      assert v['samples']==5000 and v['lost']==0,v
      v.update(engine=engine,forwards=count,round=round_id,profile='fresh_tcp_burst',proxy_cpu_seconds=after['seconds']-before['seconds'],cpu=delta(a,b));FRESH.append(v);(OUT/'fresh-burst.json').write_text(json.dumps(FRESH,indent=2));print('FRESH_BURST',engine,v['p50_us'],v['p95_us'],v['p99_us'],flush=True)
    finally:stop(p)
 if PERF_BACKEND=='iptables':
  for count in COUNTS:assert len({PROGRAMS[(engine,count)] for engine in ROLES})==1,'retained core forwarding programs changed'
 assert artifacts=={p:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in artifacts}
 for row in ROWS+WINDOWS+LATENCY+FRESH:row['release']=labels[row['engine']]
 (OUT/'protocol-window.json').write_text(json.dumps({'success':True,'kernelBackend':PERF_BACKEND,'forwardProgramSHA256':{engine+'-'+str(count):v for (engine,count),v in PROGRAMS.items()},'artifactSHA256':artifacts,'throughput':WINDOWS,'freshBurst':FRESH,'paced':ROWS,'latency':LATENCY,'payloadBytes':TOTAL_BYTES,'byteLimit':BYTE_LIMIT,'allTargetsPrivate':True,'externalForwardTestTargets':[],'statsIntervalSeconds':1,'pacedSeconds':20,'persistentSamplesPerProbe':5000,'freshTCPSamplesPerProbe':1000,'windowBytes':8*1024**3,'roundsPerBackendPerCount':ROUNDS},indent=2))
finally:
 for p in reversed(PROCESSES):stop(p)
