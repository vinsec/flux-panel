"""ABBA cold-connection confirmation; optional software profiles are separate runs."""
from pathlib import Path
import shutil,signal,statistics
confirmation_source=Path(__file__).with_name('native-only-regression.py').read_text()
exec(compile(confirmation_source[:confirmation_source.index('\ntry:\n topology();')],'<native-comparison-functions>','exec'))
profiles=[]
try:
 topology();server=http.server.ThreadingHTTPServer(('10.204.3.1',8000),Sink);server.daemon_threads=True;server.leases={}
 threading.Thread(target=server.serve_forever,daemon=True).start()
 for index,engine in enumerate(['baseline','native','native','baseline']):
  p=setup_case(engine,index)
  try:
   policy_proof(engine,p)
   for where in ['client','router','target']:run(ns(where,'ip','tcp_metrics','flush','all'))
   run(ns('client','taskset','-c',str(CPU),'iperf3','-c','10.204.1.1','-p','30000','-t','10','-b','150M','-J'),timeout=20)
   continuous(engine,index,p)
  finally:stop(p)
 base=statistics.median(x['cps'] for x in CASES if x['engine']=='baseline')
 candidate=statistics.median(x['cps'] for x in CASES if x['engine']=='native')
 if candidate/base<.95 and shutil.which('perf'):
  # Profiling must never be mixed into the throughput observations above.
  for index,engine in enumerate(['baseline','native']):
   p=setup_case(engine,10+index);data=OUT/(engine+'-cpu.data')
   perf=subprocess.Popen(['perf','record','-e','cpu-clock','-F','99','--call-graph','fp','-o',str(data),'-p',str(p.pid)],stdout=open(OUT/(engine+'-perf.log'),'w'),stderr=subprocess.STDOUT)
   try:
    continuous(engine,10+index,p)
   finally:
    if perf.poll() is None:perf.send_signal(signal.SIGINT)
    perf.wait(timeout=10);stop(p)
   report=subprocess.run(['perf','report','--stdio','--percent-limit','1','--sort','symbol','-i',str(data)],capture_output=True,text=True)
   (OUT/(engine+'-cpu.txt')).write_text(report.stdout+report.stderr)
   profiles.append({'engine':engine,'available':report.returncode==0,'report':engine+'-cpu.txt'})
 assert ARTIFACTS=={p:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in ARTIFACTS}
 (OUT/'cold-confirmation.json').write_text(json.dumps({'success':True,'artifactSHA256':ARTIFACTS,'logicalRules':COUNT,
  'order':['baseline','native','native','baseline'],'nativeProgramHashes':PROGRAMS,'policyProof':PROOF,
  'continuous':[x for x in CASES if x['round']<10],'profiles':profiles,'candidateRatio':candidate/base,
  'externalForwardTestTargets':[]},indent=2))
finally:
 for p in reversed(PROCESSES):stop(p)
