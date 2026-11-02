"""Confirm remaining download / persistent-RTT signals, no external data path."""
from pathlib import Path
import os
os.environ.update(FLUX_BENCH_FOUNDATION_CREDIT_ONLY='1',FLUX_BENCH_P1='1',FLUX_BENCH_V2='1',FLUX_BENCH_STRICT='1',FLUX_BENCH_STRICT_BYTES=str(1024**3),FLUX_BENCH_BYTE_LIMIT=str(64*1024**3))
source=Path('/code/p2-regression.py').read_text()
exec(compile(source[:source.index('\ntry:\n topology();')],'/code/p2-regression.py','exec'))
original_latency=latency
# Full benchmark's 500 samples may alias a one-second collector. Each
# persistent probe spans several reporting intervals in this confirmation.
source=Path('/code/benchmark.py').read_text()
start=source.index('\ndef latency(');end=source.index('\ndef collection(',start)
source=source[start:end].replace("[('tcp',False,500),('tcp',True,100),('udp',False,500)]", "[('tcp',False,5000),('udp',False,5000)]")
exec(compile(source,'/code/benchmark.py','exec'))
try:
 topology();server=http.server.ThreadingHTTPServer(('10.204.3.1',8000),Sink);server.daemon_threads=True;server.leases={};threading.Thread(target=server.serve_forever,daemon=True).start()
 for count in [3,10000]:
  for index in range(5):
   order=['iptables','iptables_p1'] if index%2==0 else ['iptables_p1','iptables']
   for engine in order:
    round_id=30000+count*10+index;p=setup(engine,count,round_id)
    try:
     for _ in range(3):measure(engine,count,round_id,'strict_down',p)
     latency(engine,count,round_id,p,True)
    finally:stop(p)
 assert artifacts=={path:hashlib.sha256(Path(path).read_bytes()).hexdigest() for path in artifacts}
 for row in ROWS+LATENCY:row['release']={'iptables':'frozen_p1','iptables_p1':'p2_current'}[row['engine']]
 (OUT/'p2-confirmation.json').write_text(json.dumps({'success':True,'artifactSHA256':artifacts,'throughput':ROWS,'latency':LATENCY,'payloadBytes':TOTAL_BYTES,'byteLimit':BYTE_LIMIT,'allTargetsPrivate':True,'externalForwardTestTargets':[],'statsIntervalSeconds':1,'persistentSamplesPerProbe':5000,'roundsPerReleasePerCount':5,'downloadsPerRound':3},indent=2))
finally:
 for p in reversed(PROCESSES):stop(p)
