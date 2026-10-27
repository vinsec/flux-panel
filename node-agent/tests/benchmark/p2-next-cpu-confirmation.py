"""Longer fixed-rate CPU windows for the small-rule-count signal."""
from pathlib import Path
import os
os.environ.update(FLUX_BENCH_PACED_SECONDS='40',FLUX_BENCH_BYTE_LIMIT=str(8*1024**3))
source=Path('/code/p2-next-regression.py').read_text()
exec(compile(source[:source.index('\ntry:\n topology();')],'/code/p2-next-regression.py','exec'))
try:
 topology();server=http.server.ThreadingHTTPServer(('10.204.3.1',8000),Sink);server.daemon_threads=True;server.leases={};threading.Thread(target=server.serve_forever,daemon=True).start()
 for index,order in enumerate([['iptables','iptables_p1'],['iptables_p1','iptables'],['iptables','iptables_p1']]):
  for engine in order:
   for namespace in ['client','router','target']:run(ns(namespace,'ip','tcp_metrics','flush','all'))
   p=setup(engine,3,60000+index)
   try:measure(engine,3,60000+index,'tcp_paced',p)
   finally:stop(p)
 assert artifacts=={path:hashlib.sha256(Path(path).read_bytes()).hexdigest() for path in artifacts}
 for row in ROWS:row['release']={'iptables':'baseline_v5','iptables_p1':'candidate_v51'}[row['engine']]
 (OUT/'cpu-confirmation.json').write_text(json.dumps({'success':True,'artifactSHA256':artifacts,'paced':ROWS,'payloadBytes':TOTAL_BYTES,'byteLimit':BYTE_LIMIT,'allTargetsPrivate':True,'externalForwardTestTargets':[],'cpuAffinity':1,'statsIntervalSeconds':1,'pacedSeconds':40,'tcpMetricsFlushed':True,'physicalPMU':False},indent=2))
finally:
 for p in reversed(PROCESSES):stop(p)
