"""Actual P0 executable -> P1 advanced traffic -> P0 rollback, private only."""
from foundation_fixture import *
DONE=False
try:
 if os.getenv('IPTABLES_BACKEND')=='legacy':run(['update-alternatives','--set','iptables','/usr/sbin/iptables-legacy'])
 topology();server=http.server.ThreadingHTTPServer(('10.205.4.1',8000),Handler);server.daemon_threads=True;threading.Thread(target=server.serve_forever,daemon=True).start()
 CONFIG.write_text(json.dumps({'addr':'http://10.205.4.1:8000','secret':SECRET,'statePath':str(STATE),'apply':True,'allowInsecure':True,'intervalSeconds':1}))
 baseline=BUILD/'agent-v3';assert baseline.is_file()
 def old_agent():
  serial=PANEL.serial;p=spawn(ns('router',str(baseline),'--config',str(CONFIG)),'p0-agent.log');wait(lambda:PANEL.serial>serial);return p
 a=old_agent();apply(spec());assert probe();wait(lambda:state()['totals'].get('1_1_0',{}).get('up',0)>0);prior=state();stop(a)
 backup=OUT/'p0-to-p1'
 run(ns('router',str(BUILD/'flux-agent'),'--config',str(CONFIG),'--maintenance','migrate','--backup-dir',str(backup)))
 check('P0 to P1 maintenance keeps epoch, latest totals and paused state',state()['epoch']==prior['epoch'] and state()['totals']['1_1_0']['up']>=prior['totals']['1_1_0']['up'] and probe(blocked=True))
 a=agent();advanced={'schemaVersion':3,'id':'1_1_0','revision':state()['rules']['1_1_0']['revision']+1,'enabled':True,'listen':{'host':'10.205.1.1','port':18000},'targets':[{'endpoint':{'host':'10.205.3.2','port':19000},'weight':1}],'bandwidth':{'upBitsPerSecond':5000000,'downBitsPerSecond':5000000}}
 apply(advanced);check('upgraded P1 performs actual advanced traffic',probe())
 wait(lambda:state()['formatVersion']==4 and state()['totals']['1_1_0']['up']>prior['totals']['1_1_0']['up']);latest=state();stop(a)
 run(ns('router',str(BUILD/'flux-agent'),'--config',str(CONFIG),'--maintenance','rollback','--backup-dir',str(backup)))
 check('rollback restores old-compatible format and preserves newer P1 accounting',state()['formatVersion']==3 and state()['epoch']==prior['epoch'] and state()['totals']['1_1_0']['up']>=latest['totals']['1_1_0']['up'] and probe(blocked=True))
 a=old_agent();check('actual P0 binary starts after P1 rollback with business paused',probe(blocked=True))
 PANEL.rpc('SetForwardState',{'id':'1_1_0','revision':state()['rules']['1_1_0']['revision']+1,'enabled':True});check('explicit resume on the P0 executable restores TCP/UDP',probe())
 check('upgrade and rollback leave unrelated policy intact','keep-unrelated' in router('iptables-save'))
 DONE=True
except Exception:
 traceback.print_exc()
 for name in ['p0-agent.log','agent.log']:
  p=OUT/name
  if p.exists():print(p.read_text()[-6000:])
 raise
finally:
 for p in reversed(PROCS):stop(p)
 (OUT/'p1-upgrade-result.json').write_text(json.dumps({'success':DONE,'count':len(CHECKS),'passed':CHECKS,'arch':os.uname().machine,'backend':os.getenv('IPTABLES_BACKEND','nft'),'externalForwardTestTargets':[]},indent=2))
