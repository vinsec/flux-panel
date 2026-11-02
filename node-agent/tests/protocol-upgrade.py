"""v5.4 <-> v5.5 takeover keeps checkpoint schema, accounting and policy."""
from foundation_fixture import *
try:
 topology();server=http.server.ThreadingHTTPServer(('10.205.4.1',8000),Handler);server.daemon_threads=True;threading.Thread(target=server.serve_forever,daemon=True).start()
 write_config({'addr':'http://10.205.4.1:8000','secret':SECRET,'statePath':str(STATE),'apply':True,'allowInsecure':True,'intervalSeconds':1})
 def old():
  serial=PANEL.serial;p=spawn(ns('router','/build/flux-agent-v54-baseline','--config',str(CONFIG)),'v54.log');wait(lambda:PANEL.serial>serial and p.poll() is None);return p
 a=old();s={'schemaVersion':5,'id':'1_1_0','revision':1,'enabled':True,'listen':{'host':'10.205.1.1','port':18000},'targets':[{'endpoint':{'host':'10.205.3.2','port':19000},'weight':1}],'protocolFilter':{'http':True,'tls':True,'socks':True,'unknown':'allow'}};apply(s);check('frozen v5.4 forwards TCP/UDP before upgrade',probe());time.sleep(1.2)
 original=state();stop(a);a=agent();check('v5.5 takes over old protocol table and checkpoint',probe() and 'empty4' in router('nft','list','table','inet','FP_PROTOCOL'));time.sleep(1.2)
 upgraded=state();check('upgrade preserves epoch and monotonic ledger',upgraded['epoch']==original['epoch'] and all(upgraded['totals']['1_1_0'][k]>=original['totals']['1_1_0'][k] for k in ['up','down']))
 code="import socket;s=socket.create_connection(('10.205.1.1',18000),timeout=2);s.settimeout(.3);s.sendall(b'GET / HTTP/1.1\\r\\n\\r\\n')\ntry:assert not s.recv(100)\nexcept OSError:pass"
 run(ns('client','python3','-c',code));check('upgraded table still blocks HTTP')
 stop(a);a=old();check('unchanged checkpoint format remains readable by v5.4',probe() and state()['epoch']==original['epoch']);stop(a);a=agent();check('second takeover restores optimized mode',probe())
 DONE=True
except Exception:
 traceback.print_exc()
 for name in ['v54.log','agent.log']:
  if (OUT/name).exists():print(name,(OUT/name).read_text()[-5000:])
 raise
finally:
 for p in reversed(PROCS):stop(p)
 (OUT/'upgrade-result.json').write_text(json.dumps({'success':DONE,'passed':CHECKS,'count':len(CHECKS),'externalForwardTestTargets':[]},indent=2))
