"""Occupied NFQUEUE must fail visibly and never open filtered forwards."""
from foundation_fixture import *
try:
 topology();server=http.server.ThreadingHTTPServer(('10.205.4.1',8000),Handler);server.daemon_threads=True;threading.Thread(target=server.serve_forever,daemon=True).start()
 write_config({'addr':'http://10.205.4.1:8000','secret':SECRET,'statePath':str(STATE),'apply':True,'allowInsecure':True,'intervalSeconds':1})
 code="""import socket,struct,pathlib,time
s=socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,12);s.bind((0,0));cmd=struct.pack('=HH',8,1)+bytes([1,0,0,0]);b=struct.pack('=IHHII',20+len(cmd),0x302,5,1,0)+struct.pack('!BBH',0,0,41600)+cmd;s.sendto(b,(0,0));a=s.recv(4096);assert struct.unpack_from('=i',a,16)[0]==0
pathlib.Path('/tmp/foreign-queue-ready').touch();time.sleep(600)
"""
 occupied=spawn(ns('router','python3','-c',code),'foreign-queue.log');wait(lambda:pathlib.Path('/tmp/foreign-queue-ready').exists());a=agent()
 plain=spec('2_1_0',18001);apply(plain);check('unfiltered forward works with queue owned by another process',probe(18001))
 filtered={'schemaVersion':5,'id':'1_1_0','revision':1,'enabled':True,'listen':{'host':'10.205.1.1','port':18000},'targets':[{'endpoint':{'host':'10.205.3.2','port':19000},'weight':1}],'protocolFilter':{'http':True,'tls':True,'socks':True,'unknown':'allow'}}
 apply(filtered);status=PANEL.rpc('GetForwardStatus',{'id':'1_1_0'})['data'];(OUT/'failed-status.json').write_text(json.dumps(status,indent=2));check('queue conflict surfaces a failed rule with explanation',status['status']=='failed' and 'classifier unavailable' in status.get('error',''))
 check('unavailable classifier closes filtered TCP and UDP',probe(blocked=True));check('no global queue unbind or unrelated-forward outage',occupied.poll() is None and probe(18001))
 stop(occupied);filtered['revision']=2;apply(filtered);check('new revision recovers after queue is released',probe())
 status=PANEL.rpc('GetForwardStatus',{'id':'1_1_0'})['data'];check('recovered classifier is ready',status['protocolInspection']['ready'] and status['status']=='applied')
 DONE=True
except Exception:
 traceback.print_exc()
 for name in ['agent.log','foreign-queue.log']:
  if (OUT/name).exists():print(name,(OUT/name).read_text()[-8000:])
 raise
finally:
 for p in reversed(PROCS):stop(p)
 (OUT/'protocol-unavailable-result.json').write_text(json.dumps({'success':DONE,'count':len(CHECKS),'passed':CHECKS,'externalForwardTestTargets':[]},indent=2))
