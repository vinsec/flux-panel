"""Crash/recovery of advanced NAT, shaping and ledger; disposable netns only."""
from foundation_fixture import *
DONE=False
try:
 if os.getenv('IPTABLES_BACKEND')=='legacy':run(['update-alternatives','--set','iptables','/usr/sbin/iptables-legacy'])
 topology();server=http.server.ThreadingHTTPServer(('10.205.4.1',8000),Handler);server.daemon_threads=True;threading.Thread(target=server.serve_forever,daemon=True).start()
 write_config({'addr':'http://10.205.4.1:8000','secret':SECRET,'statePath':str(STATE),'apply':True,'allowInsecure':True,'intervalSeconds':1});a=agent()
 s={'schemaVersion':3,'id':'1_1_0','revision':1,'enabled':True,'listen':{'host':'10.205.1.1','port':18000},'targets':[{'endpoint':{'host':'10.205.3.2','port':19000},'weight':1},{'endpoint':{'host':'10.205.3.2','port':19001},'weight':2}],'selection':'round','bandwidth':{'upBitsPerSecond':10000000,'downBitsPerSecond':10000000}}
 apply(s);check('advanced multi-target/shaping baseline forwards TCP/UDP',probe())
 for i,point in enumerate(['prepared','quiesced','kernel','credits','conntrack','counters','checkpoint','committed','activated']):
  stop(a);a=agent(point);prior=state();old=prior['rules']['1_1_0']['revision'];new=dict(s,revision=old+1);new['selection']='random' if prior['rules']['1_1_0']['selection']=='round' else 'round'
  try:PANEL.rpc('ApplyForward',new,timeout=2)
  except AssertionError:pass
  wait(lambda:a.poll()==82);a=agent();after=state();want=old+1 if i>=6 else old
  check('advanced crash recovery at '+point,after['rules']['1_1_0']['revision']==want and after['epoch']==prior['epoch'] and probe())
  for direction in ['up','down']:assert after['totals']['1_1_0'][direction]>=prior['totals']['1_1_0'][direction]
 # A kernel command failure must roll back and keep the original forwarding.
 foreign=router('tc','qdisc','show','dev','r1')
 bad=dict(s,revision=state()['rules']['1_1_0']['revision']+1,egress={'interface':'missing0'})
 check('unavailable typed egress is rejected before touching the live generation',not apply(bad,False)['success'] and probe() and router('tc','qdisc','show','dev','r1')==foreign)
 check('crash transitions preserve unrelated firewall policy','keep-unrelated' in router('iptables-save'))
 DONE=True
except Exception:
 traceback.print_exc()
 p=OUT/'agent.log'
 if p.exists():print(p.read_text()[-6000:])
 raise
finally:
 for p in reversed(PROCS):stop(p)
 (OUT/'p1-fault-result.json').write_text(json.dumps({'success':DONE,'arch':os.uname().machine,'backend':os.getenv('IPTABLES_BACKEND','nft'),'passed':CHECKS,'count':len(CHECKS),'externalForwardTestTargets':[]},indent=2))
