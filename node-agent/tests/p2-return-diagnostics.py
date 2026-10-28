"""P2 hook/NAT verification using real sockets and independent kernel counters.
All data lives in four private network namespaces; no public routes exist.
"""
from foundation_fixture import *
import copy

def v4spec(ident,port,target='10.205.3.2',target_port=19000,traffic=None):
 return {'schemaVersion':4,'id':ident,'revision':1,'enabled':True,'listen':{'host':'10.205.1.1','port':port},'targets':[{'endpoint':{'host':target,'port':target_port},'weight':1}],'traffic':traffic or {}}
def exchange(where,host,port,blocked=False,protocols=('tcp','udp')):
 code='''import socket
for proto in PROTOCOLS:
 print('probe',proto,flush=True)
 s=socket.socket(socket.AF_INET6 if ':' in HOST else socket.AF_INET,socket.SOCK_STREAM if proto=='tcp' else socket.SOCK_DGRAM);s.settimeout(.3 if BLOCKED else 2)
 try:
  s.connect((HOST,PORT));s.sendall(b'p2-traffic');r=s.recv(1024);assert r==b'p2-traffic' and not BLOCKED
 except (TimeoutError,OSError):assert BLOCKED
 finally:s.close()
print('ok')'''.replace('PROTOCOLS',repr(protocols)).replace('HOST',repr(host)).replace('PORT',str(port)).replace('BLOCKED',str(blocked))
 return run(ns(where,'python3','-c',code)).splitlines()[-1]=='ok'
def counters(ident):
 result=[0,0]
 for family in ['FP4','FP6']:
  for index,direction in enumerate(['UP','DOWN']):
   try:text=router('ipset','save',family+'_'+direction)
   except Exception:continue
   for line in text.splitlines():
    if 'flux:v2:'+ident+':'+direction.lower()+'"' in line:
     fields=line.split();result[index]+=int(fields[fields.index('bytes')+1])
 return result

def exact_udp(where,host,port,ident,ipv6=False):
 # Only a single UDP request/response, so headers+payload are deterministic;
 # compare raw independent ipset snapshots, without asynchronous reporting.
 before=counters(ident);payload=b'd'*123
 code=f"import socket;s=socket.socket(socket.AF_INET6 if {ipv6!r} else socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(2);s.sendto({payload!r},({host!r},{port}));assert s.recv(2048)=={payload!r};s.close()"
 run(ns(where,'python3','-c',code));after=counters(ident)
 expected=123+(48 if ipv6 else 28)
 assert [b-a for a,b in zip(before,after)]==[expected,expected],(before,after,expected)
try:
 topology()
 server=http.server.ThreadingHTTPServer(('10.205.4.1',8000),Handler);server.daemon_threads=True;threading.Thread(target=server.serve_forever,daemon=True).start()
 # Dual stack is provisioned entirely inside the same disposable topology.
 for n in ['client','router','transit','target']:
  run(ns(n,'sysctl','-w','net.ipv6.conf.all.disable_ipv6=0'))
 for n,i,address in [('client','c0','fd25:1::2/64'),('router','r0','fd25:1::1/64'),('router','r1','fd25:2::1/64'),('transit','m0','fd25:2::2/64'),('transit','m1','fd25:3::1/64'),('target','t0','fd25:3::2/64')]:run(['ip','-n',n,'-6','addr','add',address,'dev',i,'nodad'])
 for n in ['router','transit']:run(ns(n,'sysctl','-w','net.ipv6.conf.all.forwarding=1'))
 for n,route in [('client',['default','via','fd25:1::1']),('target',['default','via','fd25:3::1']),('router',['fd25:3::/64','via','fd25:2::2']),('transit',['fd25:1::/64','via','fd25:2::1'])]:run(['ip','-n',n,'-6','route','add',*route])
 router('ip6tables','-P','FORWARD','DROP')
 echo6="""import socketserver,threading,socket
socketserver.UDPServer.max_packet_size=65535
class T(socketserver.BaseRequestHandler):
 def handle(self):
  while True:
   b=self.request.recv(65536)
   if not b:return
   self.request.sendall(b)
class U(socketserver.BaseRequestHandler):
 def handle(self):
  print('udp-peer',self.client_address,flush=True);self.request[1].sendto(self.request[0],self.client_address)
class V6:
 address_family=socket.AF_INET6
 def server_bind(self):
  self.socket.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1);super().server_bind()
class TS(V6,socketserver.ThreadingTCPServer):pass
class US(V6,socketserver.ThreadingUDPServer):pass
for klass,handler in [(TS,T),(US,U)]:
 s=klass(('::',19000),handler);s.daemon_threads=True;threading.Thread(target=s.serve_forever,daemon=True).start()
threading.Event().wait()
"""
 for where in ['target','router']:spawn(ns(where,'python3','-c',echo6),where+'-echo6.log')
 time.sleep(.2)
 run(['sh','-c','mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf; mount -o remount,rw /sys/fs/bpf; mkdir -p /sys/fs/bpf/tc/globals /sys/fs/bpf/ip/globals /sys/fs/bpf/xdp/globals'])
 cfg={'addr':'http://10.205.4.1:8000','secret':SECRET,'statePath':str(STATE),'apply':True,'allowInsecure':True,'intervalSeconds':1};helper=None
 if os.getenv('FLUX_P2_HELPER')=='1':
  directory=pathlib.Path('/tmp/flux-p2-helper');directory.mkdir(mode=0o750);os.chown(directory,0,12345);cfg['helperSocket']=str(directory/'kernel.sock')
 CONFIG.write_text(json.dumps(cfg));CONFIG.chmod(0o644)
 BPF_PREP='mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf; mount -o remount,rw /sys/fs/bpf; mkdir -p /sys/fs/bpf/tc/globals /sys/fs/bpf/ip/globals /sys/fs/bpf/xdp/globals; mkdir -p /run/flux-agent-bpf; mount -t tmpfs -o mode=0700 tmpfs /run/flux-agent-bpf; /build/flux-agent --prepare-local-shaping > /dev/null; mount --bind /sys/fs/bpf /sys/fs/bpf; mount -o remount,bind,ro /sys/fs/bpf; exec "$@"'
 def start_helper():
  p=spawn(ns('router','sh','-c',BPF_PREP,'sh','setpriv','--regid=12345','--clear-groups','--bounding-set=-all,+net_admin,+net_raw,+net_bind_service',str(BUILD/'flux-agent'),'--kernel-helper','--helper-user','12345','--config',str(CONFIG)),'helper.log');wait(lambda:pathlib.Path(cfg['helperSocket']).exists());return p
 if cfg.get('helperSocket'):
  helper=start_helper()
  def agent(fault='',timeout=20):
   serial=PANEL.serial;p=spawn(ns('router','setpriv','--reuid=12345','--regid=12345','--clear-groups','--bounding-set=-all',str(BUILD/'flux-agent'),'--config',str(CONFIG)),'network.log');wait(lambda:PANEL.serial>serial and p.poll() is None,timeout);return p
 router('ip','link','set','lo','mtu','131072');router('sysctl','-w','net.ipv4.conf.lo.accept_local=1','net.ipv4.conf.lo.rp_filter=2')
 if helper is None:
  def agent(fault='',timeout=20):
   serial=PANEL.serial;args=[str(BUILD/'flux-agent'),'--config',str(CONFIG)]
   if fault:args+=['--test-fault',fault]
   p=spawn(ns('router','sh','-c',BPF_PREP,'sh',*args),'agent.log');wait(lambda:PANEL.serial>serial and p.poll() is None,timeout);return p
 a=agent()
 # Let the initial address-watcher synchronization settle before probing an
 # otherwise immutable topology. Transient transaction drops are intentional.
 time.sleep(1.5)
 if helper:
  status=pathlib.Path('/proc/'+str(a.pid)+'/status').read_text();check('P2 typed policy travels through dedicated UID with zero capabilities','Uid:\t12345' in status and 'CapEff:\t0000000000000000' in status)

 spawn(ns('router','python3','-c',"import socketserver;socketserver.UDPServer.max_packet_size=65535;exec(open('/tests/echo_server.py').read())"),'local-target.log');time.sleep(.2)
 # Observe accepted connections independently; a route-only diagnosis must not dial.
 counter=pathlib.Path('/tmp/diagnostic-connections');counter.write_text('0')
 code="""import socket,threading,pathlib
p=pathlib.Path('/tmp/diagnostic-connections');lock=threading.Lock()
def handle(c):
 try:
  with lock:p.write_text(str(int(p.read_text())+1))
  c.settimeout(.2)
  try:
   data=c.recv(128)
   if data:c.sendall(c.getpeername()[0].encode())
  except OSError:pass
 finally:c.close()
s=socket.socket(socket.AF_INET6);s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,0);s.bind(('::',19006));s.listen(32)
while True:
 c,_=s.accept();threading.Thread(target=handle,args=(c,),daemon=True).start()
"""
 spawn(ns('target','python3','-c',code),'diagnostic-target.log');run(['ip','-n','target','addr','add','10.205.3.3/24','dev','t0']);time.sleep(.2)
 s={'schemaVersion':4,'id':'130_1_0','revision':1,'enabled':True,'listeners':[{'host':'10.205.1.1','port':18530,'protocol':'tcp'},{'host':'fd25:1::1','port':18530,'protocol':'tcp'}],'targets':[{'endpoint':{'host':h,'port':19006},'weight':1} for h in ['10.205.3.2','10.205.3.3','fd25:3::2']],'traffic':{'sourceMode':'preserve','returnPathConfirmed':True}};apply(s);time.sleep(1)
 def diagnose(**extra):return PANEL.rpc('DiagnoseForward',dict(id='130_1_0',**extra))['data']
 router('sysctl','-w','net.ipv4.conf.all.rp_filter=0','net.ipv4.conf.r0.rp_filter=1')
 before=counters('130_1_0');connections=int(counter.read_text());d=diagnose(clientIP='10.205.1.2',ingressInterface='r0')
 check('default diagnosis is route-only and creates no target connection',not d['probePerformed'] and d['probeCount']==0 and int(counter.read_text())==connections)
 check('every distinct target is reported instead of dropping same-family alternatives',len(d['routes'])==3 and not d['routesTruncated'])
 r=d['returnPath'];entry=r['ingress'][0]
 check('operator confirmation and local route evidence do not verify remote return path',r['administratorConfirmed'] and not r['remoteReturnVerified'] and r['status']=='unverified')
 check('strict reverse-route evidence names actual ingress and local route',entry['ipv4RPFilterEffective']==1 and entry['clientRouteEvidence']['dev']=='r0' and entry['risk']=='no-obvious-destination-route-conflict')
 check('forwarded route query includes original client and ingress',all(v['forwardRouteEvidence']['available'] for v in d['routes'] if v['family']=='ipv4'))
 router('ip','route','add','10.205.1.2/32','via','10.205.2.2','dev','r1');d=diagnose(clientIP='10.205.1.2',ingressInterface='r0');check('strict asymmetric source-route risk is visible',d['returnPath']['ingress'][0]['risk']=='strict-interface-mismatch-risk')
 router('sysctl','-w','net.ipv4.conf.all.rp_filter=2');d=diagnose(clientIP='10.205.1.2',ingressInterface='r0');check('effective rp_filter uses max(all,interface), not Boolean OR',d['returnPath']['ingress'][0]['ipv4RPFilterEffective']==2 and d['returnPath']['ingress'][0]['risk']=='no-obvious-destination-route-conflict');router('ip','route','del','10.205.1.2/32')
 d=diagnose(clientIP='fd25:1::2',ingressInterface='r0');check('IPv6 is never assigned IPv4 rp_filter semantics',d['returnPath']['ingress'][0]['risk']=='ipv6-no-ipv4-rp-filter' and not d['returnPath']['ingress'][0]['ipv6RPFilterApplicable'])
 d=diagnose(probe=True,clientIP='10.205.1.2',ingressInterface='r0');wait(lambda:int(counter.read_text())==connections+2)
 check('opt-in TCP diagnostic makes at most two bounded connections',d['probeCount']==2 and sum(v['probePerformed'] for v in d['routes'])==2 and all(v.get('reachable',True) for v in d['routes']))
 check('node handshake is never upgraded into client return-path verification',not d['returnPath']['remoteReturnVerified'] and all(not v.get('businessMarkApplied',False) for v in d['routes']))
 check('read-only and opt-in node checks do not consume forward accounting',counters('130_1_0')==before)
 for bad in [{'clientIP':'example.com'},{'clientIP':'224.0.0.1'},{'ingressInterface':'missing0'}]:check('invalid sample rejected without probing '+str(bad),not PANEL.rpc('DiagnoseForward',dict(id='130_1_0',probe=True,**bad),success=False)['success'])
 router('ip','route','del','10.205.3.0/24','via','10.205.2.2');d=diagnose();check('missing target route is reported as unavailable, never verified',any(not v['routeEvidence']['available'] for v in d['routes']) and d['returnPath']['status']=='unverified')
 DONE=True

except Exception:
 traceback.print_exc()
 raise
finally:
 for p in reversed(PROCS):stop(p)
 (OUT/'result.json').write_text(json.dumps({'success':DONE,'checks':CHECKS}))
