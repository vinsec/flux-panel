"""Three-way, rotated-order v5.2 / v5.3 xtables / v5.3 native nft regression.
Same private VM topology and 8GiB windows as the accepted v5.2 experiment.
"""
from pathlib import Path
import os
os.environ.update(FLUX_BENCH_FOUNDATION_CREDIT_ONLY='1',FLUX_BENCH_P1='1',FLUX_BENCH_V2='1',FLUX_BENCH_STRICT='1',FLUX_BENCH_BYTE_LIMIT=str(512*1024**3),FLUX_BENCH_PACED_SECONDS='20')
source=Path('/code/benchmark.py').read_text()
source=source.replace('/build/flux-agent-v2','/build/flux-agent-native').replace("else '/build/flux-agent'","else '/build/flux-agent-v52-baseline'")
source=source.replace("if os.getenv('FLUX_BENCH_FOUNDATION_CREDIT_ONLY')=='1' and engine=='iptables_v2':","if False:")
source=source.replace(" clean_rules();path=", " clean_rules();router('iptables','-P','FORWARD','ACCEPT' if engine=='iptables_p1' else 'DROP');path=")
source=source.replace(" state={'epoch':", " state={'kernelBackend':'nftables' if engine=='iptables_p1' else 'iptables','epoch':")
source=source.replace("'statePath':str(path/'state.json'),'apply':True", "'statePath':str(path/'state.json'),'kernelBackend':'nftables' if engine=='iptables_p1' else 'iptables','apply':True")
source=source.replace("def clean_rules():", "def clean_rules():\n subprocess.run(ns('router','nft','delete','table','inet','FP_NATIVE'),capture_output=True)")
source=source.replace(" args=['iperf3','-c',ip,'-p',port,'-J']"," if profile=='tcp_paced':port='30000'\n args=['iperf3','-c',ip,'-p',port,'-J']")
source=source.replace("timeout=15)\n b=snapshot()", "timeout=max(15,int(os.environ['FLUX_BENCH_PACED_SECONDS'])+8))\n b=snapshot()")
source=source.replace("mount -o remount,rw /proc/sys && sysctl", "(mount -o remount,rw /proc/sys || true); sysctl").replace('deadline=time.monotonic()+20','deadline=time.monotonic()+90')
exec(compile(source[:source.rindex('\ntry:main()')],'/code/benchmark.py','exec'))
original_specs=specs
def specs(count):
 rules=original_specs(count)
 for s in rules.values():
  s.update(schemaVersion=3,listen={'host':s['listenIP'],'port':s['listenPort']},targets=[{'endpoint':{'host':s['targetIP'],'port':s['targetPort']},'weight':1}])
  s['runtime']={'status':'ready','targets':[{'host':s['targetIP'],'port':s['targetPort'],'family':'ipv4','origin':s['targetIP']+':'+str(s['targetPort']),'weight':1,'healthy':True,'acceptNew':True}]}
 return rules
artifacts={p:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in ['/build/flux-agent-v52-baseline','/build/flux-agent-native','/build/bench-peer']}
original_setup=setup
def setup(engine,count,round_id):
 p=original_setup(engine,count,round_id)
 expected='/build/flux-agent-v52-baseline' if engine=='iptables' else '/build/flux-agent-native'
 actual=hashlib.sha256(Path('/proc/'+str(p.pid)+'/exe').read_bytes()).hexdigest();assert actual==artifacts[expected]
 state=json.loads(Path(f'/tmp/{engine}-{count}-{round_id}/state.json').read_text());expected_backend='nftables' if engine=='iptables_p1' else 'iptables';assert state.get('kernelBackend','iptables')==expected_backend
 if expected_backend=='nftables':assert state['formatVersion']==6 and 'FP_NATIVE' in router('nft','list','tables') and not router('ipset','list','-name')
 return p
start=source.index('\ndef latency(');end=source.index('\ndef collection(',start)
exec(compile(source[start:end].replace("[('tcp',False,500),('tcp',True,100),('udp',False,500)]", "[('tcp',False,5000),('tcp',True,1000),('udp',False,5000)]"),'/code/benchmark.py','exec'))
WINDOWS=[]
window_source=Path('/code/p2-security-window.py').read_text()
start=window_source.index('\ndef window(');end=window_source.index('\ntry:\n topology();',start)
exec(compile(window_source[start:end],'/code/p2-security-window.py','exec'))
labels={'iptables':'baseline_v52','iptables_v2':'candidate_iptables','iptables_p1':'candidate_native_nft'}
try:
 topology();server=http.server.ThreadingHTTPServer(('10.204.3.1',8000),Sink);server.daemon_threads=True;server.leases={};threading.Thread(target=server.serve_forever,daemon=True).start()
 for count in [3,10000]:
  for index,order in enumerate([['iptables','iptables_v2','iptables_p1'],['iptables_p1','iptables','iptables_v2'],['iptables_v2','iptables_p1','iptables']]):
   for engine in order:
    round_id=70000+count*10+index;p=setup(engine,count,round_id)
    try:
     window(engine,count,round_id,p,False);window(engine,count,round_id,p,True)
     measure(engine,count,round_id,'tcp_paced',p);latency(engine,count,round_id,p,True)
    finally:stop(p)
 assert artifacts=={p:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in artifacts}
 for row in ROWS+WINDOWS+LATENCY:row['release']=labels[row['engine']]
 (OUT/'native-nft-window.json').write_text(json.dumps({'success':True,'artifactSHA256':artifacts,'throughput':WINDOWS,'paced':ROWS,'latency':LATENCY,'payloadBytes':TOTAL_BYTES,'byteLimit':BYTE_LIMIT,'allTargetsPrivate':True,'externalForwardTestTargets':[],'statsIntervalSeconds':1,'pacedSeconds':20,'persistentSamplesPerProbe':5000,'freshTCPSamplesPerProbe':1000,'windowBytes':8*1024**3,'roundsPerBackendPerCount':3},indent=2))
finally:
 for p in reversed(PROCESSES):stop(p)
