"""Regression for a populated 10k-rule warm restart, with stack on timeout."""
from foundation_fixture import *
DONE=False
try:
 topology();server=http.server.ThreadingHTTPServer(('10.205.4.1',8000),Handler);server.daemon_threads=True;threading.Thread(target=server.serve_forever,daemon=True).start()
 original=PANEL.report
 def bounded(r):
  ack=original(r);PANEL.reports[:]=PANEL.reports[-2:];return ack
 PANEL.report=bounded
 CONFIG.write_text(json.dumps({'addr':'http://10.205.4.1:8000','secret':SECRET,'statePath':str(STATE),'apply':True,'allowInsecure':True,'intervalSeconds':1}));a=agent()
 rules=[{'schemaVersion':3,'id':str(i+1)+'_1_0','revision':1,'enabled':True,'listen':{'host':'10.205.1.1','port':20000+i},'targets':[{'endpoint':{'host':'10.205.3.2','port':19000},'weight':1}]} for i in range(10000)]
 result=job({'id':'restart-10k','specs':rules});assert result['status']=='succeeded',result
 assert probe(29999);time.sleep(3)
 for revision in range(2,5):PANEL.rpc('SetForwardState',{'id':'1_1_0','revision':revision,'enabled':revision%2==0},timeout=40)
 stop(a);(OUT/'restart-state.json').write_text(STATE.read_text());serial=PANEL.serial;start=time.monotonic();a=spawn(ns('router',str(BUILD/'flux-agent'),'--config',str(CONFIG)),'agent.log')
 try:wait(lambda:PANEL.serial>serial and a.poll() is None,60)
 except Exception:
  if a.poll() is None:a.send_signal(signal.SIGQUIT);a.wait(timeout=10)
  raise
 elapsed=time.monotonic()-start;check('populated 10k advanced rules restart within 60 seconds',probe(29999))
 (OUT/'restart.json').write_text(json.dumps({'seconds':elapsed,'rules':10000,'agentSha256':hashlib.sha256((BUILD/'flux-agent').read_bytes()).hexdigest()},indent=2));DONE=True
except Exception:
 traceback.print_exc()
 p=OUT/'agent.log'
 if p.exists():print(p.read_text()[-16000:])
 raise
finally:
 for p in reversed(PROCS):stop(p)
 (OUT/'restart-result.json').write_text(json.dumps({'success':DONE,'count':len(CHECKS),'passed':CHECKS,'externalForwardTestTargets':[]}))
