"""Software-event perf attribution inside an offline Fusion Linux guest."""
from pathlib import Path
import os,json,subprocess,time,signal,http.server,threading
os.environ.update(FLUX_BENCH_P1='1',FLUX_BENCH_V2='1',FLUX_BENCH_FOUNDATION='1')
source=Path('/opt/flux-p1/tests/benchmark/benchmark.py').read_text().replace('mount -o remount,rw /proc/sys &&','(mount -o remount,rw /proc/sys 2>/dev/null || true);');exec(compile(source[:source.rindex('\ntry:main()')],'/code/benchmark.py','exec'))
try:
 topology();server=http.server.ThreadingHTTPServer(('10.204.3.1',8000),Sink);server.daemon_threads=True;server.leases={};threading.Thread(target=server.serve_forever,daemon=True).start()
 pmu=subprocess.run(['perf','stat','-e','cycles,instructions','--','true'],capture_output=True,text=True);(OUT/'hardware-pmu.txt').write_text(pmu.stdout+pmu.stderr)
 Path('/proc/sys/kernel/kptr_restrict').write_text('0');Path('/proc/sys/kernel/perf_event_paranoid').write_text('-1')
 p=setup('iptables_p1',10000,201)
 profiling=subprocess.Popen(['perf','record','-a','-e','cpu-clock','-F','99','--call-graph','fp','-o',str(OUT/'perf.data'),'--','sleep','25'],stdout=open(OUT/'perf-record.txt','w'),stderr=subprocess.STDOUT)
 time.sleep(.5);a=snapshot();result=json.loads(run(ns('client','iperf3','-c','10.204.1.1','-p','18000','-t','20','-b','150M','-J'),timeout=30));b=snapshot();profiling.wait(timeout=15);assert profiling.returncode==0
 env=os.environ.copy();env['DEBUGINFOD_URLS']='';r=subprocess.run(['perf','report','--stdio','--header','--percent-limit','0.5','-i',str(OUT/'perf.data')],capture_output=True,text=True,env=env,timeout=30);(OUT/'perf-report.txt').write_text(r.stdout+r.stderr);assert r.returncode==0
 receiver=result['end']['sum_received'];assert receiver['bytes']>0
 (OUT/'perf-result.json').write_text(json.dumps({'success':True,'forwards':10000,'seconds':20,'event':'cpu-clock software sampling','hardwarePmuAvailable':pmu.returncode==0 and '<not supported>' not in pmu.stderr and '<not counted>' not in pmu.stderr,'receiverMbps':receiver['bits_per_second']/1e6,'receiverBytes':receiver['bytes'],'cpu':delta(a,b),'physicalExclusiveAttribution':False,'externalForwardTestTargets':[]},indent=2))
finally:
 for p in reversed(PROCESSES):stop(p)
