"""Measure sustained multi-transfer windows across one-second reporting cycles.

Each chunk remains <=1GiB with an independent receiver receipt. Unlike isolated
sub-second peaks, an 8GiB window spans collector work and averages its phase.
"""
from pathlib import Path
import os
os.environ.update(FLUX_BENCH_FOUNDATION_CREDIT_ONLY='1',FLUX_BENCH_P1='1',FLUX_BENCH_V2='1',FLUX_BENCH_STRICT='1',FLUX_BENCH_BYTE_LIMIT=str(256*1024**3),FLUX_BENCH_PACED_SECONDS='20')
source=Path('/code/p2-next-regression.py').read_text()
exec(compile(source[:source.index('\ntry:\n topology();')],'/code/p2-next-regression.py','exec'))
source=Path('/code/benchmark.py').read_text();start=source.index('\ndef latency(');end=source.index('\ndef collection(',start)
exec(compile(source[start:end].replace("[('tcp',False,500),('tcp',True,100),('udp',False,500)]", "[('tcp',False,5000),('udp',False,5000)]"),'/code/benchmark.py','exec'))
WINDOWS=[];PROGRAMS=[]
def program(engine,count,round_id):
 import shlex
 tables={}
 for table,roots in [('mangle',['PREROUTING']),('nat',['PREROUTING','POSTROUTING']),('filter',['FORWARD'])]:
  raw=router('iptables-save','-t',table);(OUT/(engine+'-'+str(count)+'-'+str(round_id)+'-'+table+'.rules')).write_text(raw)
  chains={};declarations=set()
  for line in raw.splitlines():
   if line.startswith(':'):declarations.add(line.split()[0][1:])
   if line.startswith('-A '):
    fields=shlex.split(line);chains.setdefault(fields[1],[]).append(fields[2:])
  todo=list(roots);reachable=set()
  while todo:
   name=todo.pop()
   if name in reachable:continue
   reachable.add(name)
   for fields in chains.get(name,[]):
    for jump in ['-j','-g']:
     if jump in fields:
      target=fields[fields.index(jump)+1]
      if target in declarations:todo.append(target)
  tables[table]={name:chains.get(name,[]) for name in sorted(reachable)}
 names=router('ipset','list','-name').splitlines()
 PROGRAMS.append({'engine':engine,'forwards':count,'round':round_id,'forwardProgramSHA256':hashlib.sha256(json.dumps(tables,sort_keys=True).encode()).hexdigest(),'ownedSets':sorted(names)})
 (OUT/'programs.json').write_text(json.dumps(PROGRAMS,indent=2))
def window(engine,count,round_id,p,reverse):
 global TOTAL_BYTES
 before=proc(p);a=snapshot();receipts=[]
 for index in range(8):
  args=['/build/bench-peer','-host','10.204.1.1','-port','18000','-bulk-bytes',str(1024**3)]
  if reverse:args+=['-reverse']
  result=json.loads(run(ns('client','taskset','-c',str(CPU),*args),timeout=20));assert result['receiver_acknowledged'] and result['bytes']==1024**3;receipts.append(result)
 b=snapshot();after=proc(p);size=sum(x['bytes'] for x in receipts);TOTAL_BYTES+=size;assert TOTAL_BYTES<=BYTE_LIMIT
 timing=delta(a,b);row={'engine':engine,'forwards':count,'round':round_id,'profile':'window_down' if reverse else 'window_up','received_bytes':size,'mbps':size*8/timing['wall_seconds']/1e6,'proxy_cpu_seconds':after['seconds']-before['seconds'],'receipts':receipts,**timing}
 row['cgroup_cpu_seconds_per_gib']=row['cgroup_cpu_seconds']/(size/1024**3);WINDOWS.append(row);(OUT/'windows.json').write_text(json.dumps(WINDOWS,indent=2));print('WINDOW',count,engine,round_id,row['profile'],round(row['mbps'],2),'Mbps',flush=True)
try:
 topology();server=http.server.ThreadingHTTPServer(('10.204.3.1',8000),Sink);server.daemon_threads=True;server.leases={};threading.Thread(target=server.serve_forever,daemon=True).start()
 for count in [3,10000]:
  for index in range(3):
   order=['iptables','iptables_p1'] if index%2==0 else ['iptables_p1','iptables']
   for engine in order:
    round_id=50000+count*10+index;p=setup(engine,count,round_id)
    try:
     program(engine,count,round_id)
     window(engine,count,round_id,p,False);window(engine,count,round_id,p,True)
     measure(engine,count,round_id,'tcp_paced',p)
     latency(engine,count,round_id,p,True)
    finally:stop(p)
 assert artifacts=={path:hashlib.sha256(Path(path).read_bytes()).hexdigest() for path in artifacts}
 for row in ROWS+WINDOWS+LATENCY:row['release']={'iptables':'baseline_v5','iptables_p1':'candidate_v51'}[row['engine']]
 (OUT/'p2-next-window.json').write_text(json.dumps({'success':True,'artifactSHA256':artifacts,'programs':PROGRAMS,'throughput':WINDOWS,'paced':ROWS,'latency':LATENCY,'payloadBytes':TOTAL_BYTES,'byteLimit':BYTE_LIMIT,'allTargetsPrivate':True,'externalForwardTestTargets':[],'statsIntervalSeconds':1,'pacedSeconds':20,'persistentSamplesPerProbe':5000,'windowBytes':8*1024**3,'roundsPerReleasePerCount':3},indent=2))
finally:
 for p in reversed(PROCESSES):stop(p)
