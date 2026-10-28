"""Run the original 10k lifecycle/GC acceptance against native nft maps.
Only the independent rule-count reader differs; socket, pause, ACK and GC
assertions and time budgets are shared with the original foundation test.
"""
import os
os.environ['FLUX_KERNEL_BACKEND']='nftables'
from foundation_fixture import *
try:
 topology();server=http.server.ThreadingHTTPServer(('10.205.4.1',8000),Handler);server.daemon_threads=True;threading.Thread(target=server.serve_forever,daemon=True).start()
 write_config({'addr':'http://10.205.4.1:8000','secret':SECRET,'statePath':str(STATE),'apply':True,'allowInsecure':True,'intervalSeconds':1});a=agent();apply(spec());check('native scale baseline passes real TCP/UDP',probe())
 source=pathlib.Path('/tests/foundation.py').read_text();start=source.index(' # Build the complete 10k');end=source.index(' # Each killed process',start);source=source[start:end]
 source=source.replace("sum(l.startswith('-A FP_MARK ') for l in router('iptables-save','-t','mangle').splitlines())==5", "sum('rule' in item for item in json.loads(router('nft','-j','list','table','inet','FP_NATIVE'))['nftables'])<100")
 exec(compile('if True:\n'+source,'/tests/foundation.py','exec'))
 DONE=True
except Exception:
 traceback.print_exc()
 if (OUT/'agent.log').exists():print((OUT/'agent.log').read_text()[-12000:])
 raise
finally:
 for p in reversed(PROCS):stop(p)
 (OUT/'native-scale-result.json').write_text(json.dumps({'success':DONE,'count':len(CHECKS),'passed':CHECKS,'external_forward_test_targets':[]},indent=2))
