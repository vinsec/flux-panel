"""Longer, ABBA confirmation for noisy native-only CPU and paced latency results."""
from pathlib import Path
confirmation_source=Path(__file__).with_name('native-only-regression.py').read_text()
exec(compile(confirmation_source[:confirmation_source.index('\ntry:\n topology();')],'<native-comparison-functions>','exec'))
duration=40
start=confirmation_source.index('\ndef steady(');end=confirmation_source.index('\ndef delays(',start)
exec(compile(confirmation_source[start:end].replace("'-t','20'","'-t','40'").replace('timeout=30','timeout=55'),'<long-steady>','exec'))
start=confirmation_source.index('\ndef delays(');end=confirmation_source.index('\ndef bulk(',start)
exec(compile(confirmation_source[start:end].replace('1000)]','3000)]'),'<long-latency>','exec'))
try:
 topology();server=http.server.ThreadingHTTPServer(('10.204.3.1',8000),Sink);server.daemon_threads=True;server.leases={}
 threading.Thread(target=server.serve_forever,daemon=True).start()
 for index,engine in enumerate(['baseline','native','native','baseline']):
  p=setup_case(engine,index)
  try:
   policy_proof(engine,p)
   # Identical TCP metric state and a real warm-up, before the longer measured window.
   for where in ['client','router','target']:run(ns(where,'ip','tcp_metrics','flush','all'))
   run(ns('client','taskset','-c',str(CPU),'iperf3','-c','10.204.1.1','-p','30000','-t','10','-b','150M','-J'),timeout=20)
   steady(engine,index,p,150)
   for where in ['client','router','target']:run(ns(where,'ip','tcp_metrics','flush','all'))
   delays(engine,index,p)
  finally:stop(p)
 assert ARTIFACTS=={p:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in ARTIFACTS}
 (OUT/'confirmation.json').write_text(json.dumps({'success':True,'artifactSHA256':ARTIFACTS,'logicalRules':COUNT,
  'order':['baseline','native','native','baseline'],'steadySeconds':duration,'warmupSeconds':10,
  'tcpMetricsFlushed':True,'nativeProgramHashes':PROGRAMS,'policyProof':PROOF,'steady':STEADY,'latency':DELAYS,
  'externalForwardTestTargets':[]},indent=2))
finally:
 for p in reversed(PROCESSES):stop(p)
