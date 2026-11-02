"""Managed GOST local shaping: missing preparation rejects; caps stay bounded.
Disposable private mount+net namespace only, never a host service manager.
"""
from foundation_fixture import *
DONE=False
rows=[]
try:
 topology();server=http.server.ThreadingHTTPServer(('10.205.4.1',8000),Handler);server.daemon_threads=True;threading.Thread(target=server.serve_forever,daemon=True).start()
 shared=pathlib.Path('/tmp/shared');shared.mkdir(mode=0o750);os.chown(shared,0,12345)
 worker=pathlib.Path('/tmp/worker');worker.mkdir(mode=0o750);os.chown(worker,12345,12345);worker.chmod(0o750)
 cfg={'addr':'http://10.205.4.1:8000','secret':SECRET,'statePath':str(STATE),'apply':True,'allowInsecure':True,'intervalSeconds':1,'kernelBackend':'nftables','helperSocket':str(shared/'kernel.sock'),'managedGost':{'binary':'/build/gost','sha256':hashlib.sha256((BUILD/'gost').read_bytes()).hexdigest(),'socket':str(worker/'control.sock')}}
 CONFIG.write_text(json.dumps(cfg));CONFIG.chmod(0o644)
 def start_helper(prepared=False):
  command=['setpriv','--regid=12345','--clear-groups','--bounding-set=-all,+net_admin,+net_raw,+net_bind_service',str(BUILD/'flux-agent'),'--kernel-helper','--helper-user','12345','--config',str(CONFIG)]
  if prepared:
   setup='set -e;mount -t bpf bpf /sys/fs/bpf;install -d -m0700 /run/flux-agent-bpf;/build/flux-agent --prepare-local-shaping >/dev/null;ip link set lo mtu 131072;sysctl -w net.ipv4.conf.lo.accept_local=1 net.ipv4.conf.lo.rp_filter=2 >/dev/null;exec "$@"'
   command=['sh','-c',setup,'sh',*command]
  h=spawn(ns('router',*command),'helper.log');wait(lambda:pathlib.Path(cfg['helperSocket']).exists() and h.poll() is None,40);return h
 def network():
  serial=PANEL.serial;p=spawn(ns('router','setpriv','--reuid=12345','--regid=12345','--clear-groups','--bounding-set=-all',str(BUILD/'flux-agent'),'--config',str(CONFIG)),'network.log');wait(lambda:PANEL.serial>serial and p.poll() is None,40);return p
 def mode(target,ident):
  PANEL.rpc('SubmitModeSwitch',{'id':ident,'mode':target})
  v=wait(lambda:(j if j['status'] in ['succeeded','failed','blocked'] else None) if (j:=PANEL.rpc('GetModeSwitchStatus',{'id':ident})['data']) else None,40)
  assert v['status']=='succeeded',v
  assert probe()
 helper=start_helper();a=network()
 s={'schemaVersion':3,'id':'1_1_0','revision':1,'enabled':True,'listen':{'host':'10.205.1.1','port':18000},'targets':[{'endpoint':{'host':'10.205.3.2','port':19000},'weight':1}],'bandwidth':{'upBitsPerSecond':8000000,'downBitsPerSecond':8000000}}
 apply(s);assert probe();before=state()
 rejected=PANEL.rpc('SubmitModeSwitch',{'id':'without-preparation','mode':'gost'},success=False)
 check('missing local shaping preparation rejects before stopping native traffic',not rejected['success'] and 'GOST local shaping' in rejected['message'] and probe() and state()['epoch']==before['epoch'] and state().get('forwardingMode','kernel')=='kernel')
 # Adding a limit in an already-running unprepared GOST mode must also reject.
 import copy
 unlimited=copy.deepcopy(s);unlimited['revision']=2;unlimited.pop('bandwidth');apply(unlimited);mode('gost','unlimited-without-preparation')
 proposed=copy.deepcopy(s);proposed['revision']=3;denied=apply(proposed,False)
 check('unprepared GOST rejects a new bandwidth policy without disabling the live rule',not denied['success'] and probe() and state()['rules']['1_1_0']['revision']==2)
 mode('kernel','restore-before-preparation');s['revision']=3;apply(s)
 stop(a);stop(helper);wait(lambda:not pathlib.Path(cfg['helperSocket']).exists())
 helper=start_helper(True);a=network()
 caps=pathlib.Path('/proc/'+str(helper.pid)+'/status').read_text();check('prepared shaping helper still lacks SYS_ADMIN and SETUID',all(int(line.split()[1],16)&((1<<21)|(1<<7))==0 for line in caps.splitlines() if line.startswith(('CapEff:','CapBnd:'))))
 mode('gost','with-preparation');check('prepared node switches to GOST with rate policy intact',state()['forwardingMode']=='gost' and state()['epoch']==before['epoch'])
 def bulk(port):
  code=f"import socket,threading,time;s=socket.create_connection(('10.205.1.1',{port}),timeout=3);s.settimeout(15);b=b'b'*1048576;t=time.monotonic();threading.Thread(target=lambda:s.sendall(b),daemon=True).start();out=0\nwhile out<len(b):\n p=s.recv(65536);assert p and p==b'b'*len(p);out+=len(p)\nprint(time.monotonic()-t)"
  return float(run(ns('client','python3','-c',code),30))
 elapsed=bulk(18000);rows.append({'profile':'gost-single-8Mbps','seconds':elapsed});check('GOST 8 Mbps bidirectional cap shapes actual TCP transfer',.65<elapsed<5)
 # Separate forwards share one user ceiling in managed mode.
 import copy
 s['revision']=4;s['bandwidth']={'user':{'id':'u7','upBitsPerSecond':8000000,'downBitsPerSecond':8000000}};apply(s)
 second=copy.deepcopy(s);second['id']='2_1_0';second['revision']=1;second['listen']['port']=18001;apply(second);time.sleep(1)
 values=[];errors=[]
 def transfer(port):
  try:values.append(bulk(port))
  except Exception as e:errors.append(str(e))
 ts=[threading.Thread(target=transfer,args=(p,)) for p in [18000,18001]];started=time.monotonic()
 for t in ts:t.start()
 for t in ts:t.join()
 elapsed=time.monotonic()-started;rows.append({'profile':'gost-shared-user-8Mbps','seconds':elapsed,'individualSeconds':values});check('two managed GOST forwards share the same user HTB ceiling',not errors and len(values)==2 and 1.5<elapsed<7)
 mode('kernel','back-native');check('shaped rules return to native mode without changing epoch',state()['epoch']==before['epoch'])
 DONE=True
except Exception:
 traceback.print_exc()
 for name in ['helper.log','network.log']:
  if (OUT/name).exists():print((OUT/name).read_text()[-8000:])
 raise
finally:
 for p in reversed(PROCS):stop(p)
 (OUT/'managed-shaping-result.json').write_text(json.dumps({'success':DONE,'count':len(CHECKS),'passed':CHECKS,'transfers':rows,'externalForwardTestTargets':[]},indent=2))
