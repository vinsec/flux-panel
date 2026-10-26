"""Isolated four-stream scaling; shared guest vCPUs, not a physical PMU claim."""
from pathlib import Path
source=Path('/code/benchmark.py').read_text();exec(compile(source[:source.rindex('\ntry:main()')],'/code/benchmark.py','exec'))
try:
 topology();server=http.server.ThreadingHTTPServer(('10.204.3.1',8000),Sink);server.daemon_threads=True;server.leases={};threading.Thread(target=server.serve_forever,daemon=True).start()
 for affinity in os.getenv('FLUX_BENCH_AFFINITIES','1;0,1').split(';'):
  CPU=affinity
  for round_id,order in enumerate([['iptables','iptables_v2','iptables_p1'],['iptables_p1','iptables','iptables_v2'],['iptables_v2','iptables_p1','iptables']],91 if affinity=='1' else 101):
   for engine in order:
    p=setup(engine,10000,round_id)
    try:
     measure(engine,10000,round_id,'strict_parallel',p);ROWS[-1]['cpuAffinity']=affinity
    finally:stop(p)
 metadata={'success':True,'rows':ROWS,'byteLimit':BYTE_LIMIT,'sentPayloadBytesIncludingPrior':TOTAL_BYTES,'cpuQuota':Path('/sys/fs/cgroup/cpu.max').read_text().strip(),'kernel':run(['uname','-a']),'allTargetsPrivate':True,'externalForwardTestTargets':[],'physicalPMU':False,'note':'Use cgroup CPU for both affinities; test_core fields observe CPU1 only and are partial in the two-vCPU phase.'}
 (OUT/'multicore.json').write_text(json.dumps(metadata,indent=2))
finally:
 for p in reversed(PROCESSES):stop(p)
