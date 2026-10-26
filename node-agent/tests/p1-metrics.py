"""Compare actual agent metrics with independent Linux kernel observations."""
from foundation_fixture import *
DONE=False
try:
 topology();server=http.server.ThreadingHTTPServer(('10.205.4.1',8000),Handler);server.daemon_threads=True;threading.Thread(target=server.serve_forever,daemon=True).start()
 CONFIG.write_text(json.dumps({'addr':'http://10.205.4.1:8000','secret':SECRET,'statePath':str(STATE),'apply':True,'allowInsecure':True,'intervalSeconds':1}))
 def cpu():
  a=[int(x) for x in pathlib.Path('/proc/stat').read_text().splitlines()[0].split()[1:9]];return sum(a),a[3]+a[4]
 before=cpu();a=agent();connected=cpu();apply(spec());assert probe(size=4000)
 spin=spawn(ns('router','python3','-c','import time;end=time.monotonic()+2\nwhile time.monotonic()<end:pass'),'cpu-load.log');assert spin.wait(timeout=6)==0
 wait(lambda:bool(getattr(PANEL,'metrics',[])),25);after=cpu();metric=PANEL.metrics[-1]
 rates=[(1-(after[1]-base[1])/(after[0]-base[0]))*100 for base in [before,connected]]
 check('CPU usage agrees with independent /proc sample brackets',metric['cpu_usage'] is not None and min(rates)-5<=metric['cpu_usage']<=max(rates)+5)
 memory={line.split(':')[0]:int(line.split()[1]) for line in pathlib.Path('/proc/meminfo').read_text().splitlines() if len(line.split())>=2}
 expected=(memory['MemTotal']-memory['MemAvailable'])/memory['MemTotal']*100
 check('memory usage agrees with MemAvailable instead of fabricated zero',abs(metric['memory_usage']-expected)<5 and metric['memoryTotalBytes']==memory['MemTotal']*1024)
 link=json.loads(router('ip','-s','-j','link','show','dev','r0'))[0];stats=link.get('stats64',link.get('stats'));nic=metric['network']['r0']
 check('per-interface cumulative bytes agree with independent netlink counters',abs(nic['rxBytes']-stats['rx']['bytes'])<4096 and abs(nic['txBytes']-stats['tx']['bytes'])<4096 and nic['rxBytes']>0)
 check('rates have a real sample interval and conntrack uses the actual namespace',metric['intervalSeconds']>10 and nic['rxBytesPerSecond'] is not None and abs(metric['conntrackCount']-int(router('cat','/proc/sys/net/netfilter/nf_conntrack_count')))<8)
 (OUT/'metric-comparison.json').write_text(json.dumps({'agent':metric,'independentCpuPercentRange':rates,'independentMemoryPercent':expected,'netlink':stats},indent=2));DONE=True
except Exception:
 traceback.print_exc();raise
finally:
 for p in reversed(PROCS):stop(p)
 (OUT/'metrics-result.json').write_text(json.dumps({'success':DONE,'count':len(CHECKS),'passed':CHECKS,'externalForwardTestTargets':[]},indent=2))
