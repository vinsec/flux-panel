"""AB/BA regression against frozen P2 v5, entirely inside private namespaces."""
from pathlib import Path
import os
os.environ.update(FLUX_BENCH_FOUNDATION_CREDIT_ONLY='1',FLUX_BENCH_P1='1',FLUX_BENCH_V2='1',FLUX_BENCH_STRICT='1')
os.environ.setdefault('FLUX_BENCH_PACED_SECONDS','20')
os.environ.setdefault('FLUX_BENCH_STRICT_BYTES',str(1024**3))
os.environ.setdefault('FLUX_BENCH_BYTE_LIMIT',str(32*1024**3))
source=Path('/code/benchmark.py').read_text().replace('/build/flux-agent-v2','/build/flux-agent-v51')
source=source.replace("else '/build/flux-agent'", "else '/build/flux-agent-v5'")
source=source.replace(" args=['iperf3','-c',ip,'-p',port,'-J']"," if profile=='tcp_paced':port='30000'\n args=['iperf3','-c',ip,'-p',port,'-J']")
source=source.replace("timeout=15)\n b=snapshot()", "timeout=max(15,int(os.environ['FLUX_BENCH_PACED_SECONDS'])+8))\n b=snapshot()")
source=source.replace("mount -o remount,rw /proc/sys && sysctl", "(mount -o remount,rw /proc/sys || true); sysctl")
exec(compile(source[:source.rindex('\ntry:main()')],'/code/benchmark.py','exec'))
original_specs=specs
def specs(count):
 rules=original_specs(count)
 for s in rules.values():
  s.update(schemaVersion=3,listen={'host':s['listenIP'],'port':s['listenPort']},targets=[{'endpoint':{'host':s['targetIP'],'port':s['targetPort']},'weight':1}])
  s['runtime']={'status':'ready','targets':[{'host':s['targetIP'],'port':s['targetPort'],'family':'ipv4','origin':s['targetIP']+':'+str(s['targetPort']),'weight':1,'healthy':True,'acceptNew':True}]}
 return rules
artifacts={path:hashlib.sha256(Path(path).read_bytes()).hexdigest() for path in ['/build/flux-agent-v5','/build/flux-agent-v51','/build/bench-peer']}
original_setup=setup
def setup(engine,count,round_id):
 p=original_setup(engine,count,round_id)
 expected='/build/flux-agent-v51' if engine=='iptables_p1' else '/build/flux-agent-v5'
 actual=hashlib.sha256(Path('/proc/'+str(p.pid)+'/exe').read_bytes()).hexdigest()
 assert actual==artifacts[expected],('wrong running binary',engine,actual,artifacts[expected])
 return p

try:
 topology();server=http.server.ThreadingHTTPServer(('10.204.3.1',8000),Sink);server.daemon_threads=True;server.leases={};threading.Thread(target=server.serve_forever,daemon=True).start()
 for count in [3,10000]:
  for round_id,order in enumerate([['iptables','iptables_p1'],['iptables_p1','iptables'],['iptables','iptables_p1']],201+count):
   for engine in order:
    p=setup(engine,count,round_id)
    try:
     measure(engine,count,round_id,'strict_up',p)
     measure(engine,count,round_id,'strict_down',p)
     measure(engine,count,round_id,'tcp_paced',p)
     latency(engine,count,round_id,p,True)
    finally:stop(p)
 assert artifacts=={path:hashlib.sha256(Path(path).read_bytes()).hexdigest() for path in artifacts},'benchmark inputs changed'
 labels={'iptables':'baseline_v5','iptables_p1':'candidate_v51'}
 for row in ROWS+LATENCY:row['release']=labels[row['engine']]
 (OUT/'p2-performance.json').write_text(json.dumps({'success':True,'artifactSHA256':artifacts,'kernel':run(['uname','-r']),'throughput':ROWS,'latency':LATENCY,'payloadBytes':TOTAL_BYTES,'allTargetsPrivate':True,'externalForwardTestTargets':[],'cpuAffinity':1,'statsIntervalSeconds':1,'pacedSeconds':int(os.environ['FLUX_BENCH_PACED_SECONDS']),'agentGOMAXPROCS':1,'physicalPMU':False,'note':'Same guest, AB/BA order. CPU1 includes endpoint and softirq; VM results are not physical PMU attribution.'},indent=2))
finally:
 for p in reversed(PROCESSES):stop(p)
