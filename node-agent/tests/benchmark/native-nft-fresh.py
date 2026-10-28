"""Longer fresh-connection confirmation across five reporting cycles/case."""
from pathlib import Path
source=Path('/code/native-nft-window.py').read_text();exec(compile(source[:source.index('\ntry:\n topology();')],'/code/native-nft-window.py','exec'))
FRESH=[];PROGRAMS={}
def program(engine):
 import shlex
 tables={}
 for table in ['mangle','nat','filter']:
  lines=[]
  for line in router('iptables-save','-t',table).splitlines():
   if line.startswith('-A '):lines.append(shlex.split(line))
  tables[table]=lines
 return hashlib.sha256(json.dumps(tables,sort_keys=True).encode()).hexdigest()
try:
 topology();server=http.server.ThreadingHTTPServer(('10.204.3.1',8000),Sink);server.daemon_threads=True;server.leases={};threading.Thread(target=server.serve_forever,daemon=True).start()
 for index,order in enumerate([['iptables','iptables_v2','iptables_p1'],['iptables_p1','iptables','iptables_v2'],['iptables_v2','iptables_p1','iptables']]):
  for engine in order:
   # Isolate the ephemeral-port/TIME_WAIT space for every case. Otherwise
   # 54k successive connects can measure allocator pressure from prior cases.
   client='10.204.1.'+str(10+index*3+['iptables','iptables_v2','iptables_p1'].index(engine))
   run(['ip','-n','client','addr','add',client+'/32','dev','c0']);run(['ip','-n','client','route','replace','10.204.1.0/24','dev','c0','src',client])
   p=setup(engine,10000,80000+index)
   try:
    if engine!='iptables_p1':PROGRAMS[engine]=program(engine)
    args=['/build/bench-peer','-host','10.204.1.1','-port','18001','-protocol','tcp','-fresh','-pace-us','1000']
    warm=json.loads(run(ns('client','taskset','-c',str(CPU),*args,'-samples','1000'),timeout=10));assert warm['lost']==0
    a=snapshot();v=json.loads(run(ns('client','taskset','-c',str(CPU),*args,'-samples','5000'),timeout=25));b=snapshot();assert v['samples']==5000 and v['lost']==0
    v.update(engine=engine,release=labels[engine],round=index,forwards=10000,clientIP=client,cpu=delta(a,b));FRESH.append(v);(OUT/'fresh-progress.json').write_text(json.dumps(FRESH,indent=2));print('FRESH',labels[engine],index,v['p50_us'],v['p95_us'],v['p99_us'],flush=True)
   finally:stop(p)
 assert PROGRAMS['iptables']==PROGRAMS['iptables_v2'],'retained iptables kernel rules differ from the frozen baseline'
 (OUT/'native-nft-fresh.json').write_text(json.dumps({'success':True,'artifactSHA256':artifacts,'fresh':FRESH,'iptablesProgramSHA256':PROGRAMS,'samplesPerProbe':5000,'warmupSamples':1000,'allTargetsPrivate':True,'externalForwardTestTargets':[]},indent=2))
finally:
 for p in reversed(PROCESSES):stop(p)
