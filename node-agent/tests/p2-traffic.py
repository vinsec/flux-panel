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
 s=socket.socket(socket.AF_INET6 if ':' in HOST else socket.AF_INET,socket.SOCK_STREAM if proto=='tcp' else socket.SOCK_DGRAM);s.settimeout(.3 if BLOCKED else 2)
 try:
  s.connect((HOST,PORT));s.sendall(b'p2-traffic');r=s.recv(1024);assert r==b'p2-traffic' and not BLOCKED
 except (TimeoutError,OSError):assert BLOCKED
 finally:s.close()
print('ok')'''.replace('PROTOCOLS',repr(protocols)).replace('HOST',repr(host)).replace('PORT',str(port)).replace('BLOCKED',str(blocked))
 return run(ns(where,'python3','-c',code))=='ok'
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
 cfg={'addr':'http://10.205.4.1:8000','secret':SECRET,'statePath':str(STATE),'apply':True,'allowInsecure':True,'intervalSeconds':1};helper=None
 if os.getenv('FLUX_P2_HELPER')=='1':
  directory=pathlib.Path('/tmp/flux-p2-helper');directory.mkdir(mode=0o750);os.chown(directory,0,12345);cfg['helperSocket']=str(directory/'kernel.sock')
 CONFIG.write_text(json.dumps(cfg));CONFIG.chmod(0o644)
 def start_helper():
  p=spawn(ns('router','setpriv','--regid=12345','--clear-groups',str(BUILD/'flux-agent'),'--kernel-helper','--helper-user','12345','--config',str(CONFIG)),'helper.log');wait(lambda:pathlib.Path(cfg['helperSocket']).exists());return p
 if cfg.get('helperSocket'):
  helper=start_helper()
  def agent(fault='',timeout=20):
   serial=PANEL.serial;p=spawn(ns('router','setpriv','--reuid=12345','--regid=12345','--clear-groups','--bounding-set=-all',str(BUILD/'flux-agent'),'--config',str(CONFIG)),'network.log');wait(lambda:PANEL.serial>serial and p.poll() is None,timeout);return p
 a=agent()
 if helper:
  status=pathlib.Path('/proc/'+str(a.pid)+'/status').read_text();check('P2 typed policy travels through dedicated UID with zero capabilities','Uid:\t12345' in status and 'CapEff:\t0000000000000000' in status)

 # Dual stack is provisioned entirely inside the same disposable topology.
 for n in ['client','router','transit','target']:
  run(ns(n,'sysctl','-w','net.ipv6.conf.all.disable_ipv6=0'))
 for n,i,address in [('client','c0','fd25:1::2/64'),('router','r0','fd25:1::1/64'),('router','r1','fd25:2::1/64'),('transit','m0','fd25:2::2/64'),('transit','m1','fd25:3::1/64'),('target','t0','fd25:3::2/64')]:run(['ip','-n',n,'-6','addr','add',address,'dev',i,'nodad'])
 for n in ['router','transit']:run(ns(n,'sysctl','-w','net.ipv6.conf.all.forwarding=1'))
 for n,route in [('client',['default','via','fd25:1::1']),('target',['default','via','fd25:3::1']),('router',['fd25:3::/64','via','fd25:2::2']),('transit',['fd25:1::/64','via','fd25:2::1'])]:run(['ip','-n',n,'-6','route','add',*route])
 router('ip6tables','-P','FORWARD','DROP')
 echo6="""import socketserver,threading,socket
class T(socketserver.BaseRequestHandler):
 def handle(self):
  while True:
   b=self.request.recv(65536)
   if not b:return
   self.request.sendall(b)
class U(socketserver.BaseRequestHandler):
 def handle(self):self.request[1].sendto(self.request[0],self.client_address)
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
 base=v4spec('1_1_0',18000);apply(base);check('schema4 preserves ordinary external ingress',probe())
 check('local OUTPUT is opt in',exchange('router','10.205.1.1',18000,True))
 out=v4spec('2_1_0',18001,traffic={'localOutput':True});apply(out)
 check('host-initiated OUTPUT TCP/UDP reaches remote target',exchange('router','10.205.1.1',18001))
 exact_udp('router','10.205.1.1',18001,'2_1_0');check('OUTPUT to remote and reply INPUT each meter one network packet')
 local_echo=pathlib.Path('/tests/echo_server.py').read_text().replace("'10.205.3.2'","'0.0.0.0'")
 spawn(ns('router','python3','-c',local_echo),'local-target.log');time.sleep(.2)
 local=v4spec('3_1_0',18002,'10.205.1.1',traffic={'localOutput':True,'localTargets':True});apply(local)
 check('external TCP/UDP can reach an assigned local service',exchange('client','10.205.1.1',18002))
 exact_udp('client','10.205.1.1',18002,'3_1_0');check('local service INPUT and outgoing reply meter exactly once')
 check('local OUTPUT to local service TCP/UDP works',exchange('router','10.205.1.1',18002))
 exact_udp('router','10.205.1.1',18002,'3_1_0');check('local-to-local OUTPUT/INPUT traversal is not double counted')
 loop=v4spec('4_1_0',18003,'127.0.0.1',traffic={'localOutput':True,'localTargets':True});loop['listen']['host']='127.0.0.1';apply(loop)
 check('loopback listener and target support local TCP/UDP',exchange('router','127.0.0.1',18003))
 exact_udp('router','127.0.0.1',18003,'4_1_0');check('loopback traffic has exact network-layer accounting')
 wrong=copy.deepcopy(loop);wrong.update(id='5_1_0');wrong['listen']['host']='10.205.1.1';wrong['listen']['port']=18004
 check('external-to-loopback refuses implicit global route_localnet changes',not apply(wrong,False)['success'])
 # A target on the ingress LAN would return directly without hairpin SNAT.
 spawn(ns('client','python3','-c',local_echo),'hairpin-target.log')
 hairpin=v4spec('6_1_0',18005,'10.205.1.2');apply(hairpin)
 check('same-LAN hairpin TCP/UDP returns through default MASQUERADE',exchange('client','10.205.1.1',18005))
 identity='''import socket,threading
def tcp(c):
 try:c.recv(1024);c.sendall(c.getpeername()[0].encode())
 finally:c.close()
def udp():
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('0.0.0.0',19003))
 while True:
  _,peer=s.recvfrom(1024);s.sendto(peer[0].encode(),peer)
threading.Thread(target=udp,daemon=True).start()
s=socket.socket();s.bind(('0.0.0.0',19003));s.listen(32)
while True:
 c,_=s.accept();threading.Thread(target=tcp,args=(c,),daemon=True).start()
'''
 spawn(ns('target','python3','-c',identity),'source-target.log');time.sleep(.1)
 preserve=v4spec('7_1_0',18006,target_port=19003,traffic={'sourceMode':'preserve'})
 check('source preservation requires explicit return-path confirmation',not apply(preserve,False)['success'])
 preserve['traffic']['returnPathConfirmed']=True;apply(preserve)
 observed=run(ns('client','python3','-c',"import socket\nfor kind in [socket.SOCK_STREAM,socket.SOCK_DGRAM]:\n s=socket.socket(socket.AF_INET,kind);s.settimeout(2);s.connect(('10.205.1.1',18006));s.sendall(b'peer');assert s.recv(1024)==b'10.205.1.2';s.close()\nprint('ok')"))
 check('DNAT-only TCP/UDP preserves actual client address across routed target',observed=='ok')
 PANEL.rpc('SetForwardState',{'id':'3_1_0','revision':2,'enabled':False})
 check('pause blocks existing local service hooks as well as new ingress',exchange('client','10.205.1.1',18002,True) and exchange('router','10.205.1.1',18002,True))
 PANEL.rpc('SetForwardState',{'id':'3_1_0','revision':3,'enabled':True});check('resume restores local paths',exchange('router','10.205.1.1',18002))
 # New user/tunnel caps must stop an old local rule, rather than rejecting
 # reconciliation and allowing its previous unlimited generation to survive.
 capped=copy.deepcopy(local);capped['revision']=4;capped['bandwidth']={'user':{'id':'u1','upBitsPerSecond':1000000}}
 apply(capped);status=PANEL.rpc('GetForwardStatuses',{'ids':['3_1_0']})['data']['3_1_0']
 check('later user cap fails local path closed with a visible failed status',status['status']=='failed' and exchange('router','10.205.1.1',18002,True))
 local['revision']=5;apply(local);check('removing incompatible cap restores local paths',exchange('router','10.205.1.1',18002))
 # Hold a confirmed UDP flow across pause, rather than checking only fresh sockets.
 held_code="""import socket,pathlib,time
connections=[]
for kind in [socket.SOCK_STREAM,socket.SOCK_DGRAM]:
 s=socket.socket(socket.AF_INET,kind);s.settimeout(1);s.connect(('10.205.1.1',18002));s.sendall(b'held');assert s.recv(100)==b'held';connections.append(s)
pathlib.Path('/tmp/p2-held-ready').touch()
while not pathlib.Path('/tmp/p2-held-pause').exists():time.sleep(.01)
for s in connections:
 try:s.sendall(b'held');s.recv(100);raise AssertionError('pause bypass')
 except OSError:pass
 s.close()
pathlib.Path('/tmp/p2-held-ok').touch()
"""
 held=spawn(ns('router','python3','-c',held_code),'held-local.log')
 wait(lambda:pathlib.Path('/tmp/p2-held-ready').exists());PANEL.rpc('SetForwardState',{'id':'3_1_0','revision':6,'enabled':False});pathlib.Path('/tmp/p2-held-pause').touch();assert held.wait(timeout=4)==0
 check('pause blocks already confirmed local TCP and UDP connections',pathlib.Path('/tmp/p2-held-ok').exists());PANEL.rpc('SetForwardState',{'id':'3_1_0','revision':7,'enabled':True})
 def spec6(ident,port,target,traffic):
  rule=v4spec(ident,port,target,traffic=traffic);rule['listen']['host']='fd25:1::1';return rule
 remote6=spec6('9_1_0',18008,'fd25:3::2',{'localOutput':True});apply(remote6)
 check('IPv6 host OUTPUT supports TCP and UDP',exchange('router','fd25:1::1',18008));exact_udp('router','fd25:1::1',18008,'9_1_0',True);check('IPv6 OUTPUT and INPUT accounting is exact')
 local6=spec6('10_1_0',18009,'::1',{'localOutput':True,'localTargets':True});local6['listen']['host']='::1';apply(local6)
 check('IPv6 loopback TCP and UDP supports local service',exchange('router','::1',18009));exact_udp('router','::1',18009,'10_1_0',True);check('IPv6 loopback does not double count bytes')
 local6in=spec6('11_1_0',18010,'fd25:1::1',{'localTargets':True});apply(local6in)
 check('IPv6 external ingress reaches assigned local service',exchange('client','fd25:1::1',18010));exact_udp('client','fd25:1::1',18010,'11_1_0',True);check('IPv6 external-to-local reply accounting is exact')
 # A dedicated IPv6 peer reporter proves what the destination actually observes.
 id6=identity.replace("socket.socket(socket.AF_INET,socket.SOCK_DGRAM)","socket.socket(socket.AF_INET6,socket.SOCK_DGRAM);s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)").replace("socket.socket();s.bind(('0.0.0.0',19003))","socket.socket(socket.AF_INET6);s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1);s.bind(('::',19003))").replace("('0.0.0.0',19003)","('::',19003)")
 spawn(ns('target','python3','-c',id6),'source6-target.log');time.sleep(.1)
 preserve6=spec6('12_1_0',18011,'fd25:3::2',{'sourceMode':'preserve','returnPathConfirmed':True});preserve6['targets'][0]['endpoint']['port']=19003;apply(preserve6)
 observed=run(ns('client','python3','-c',"import socket\nfor kind in [socket.SOCK_STREAM,socket.SOCK_DGRAM]:\n s=socket.socket(socket.AF_INET6,kind);s.settimeout(2);s.connect(('fd25:1::1',18011));s.sendall(b'peer');assert s.recv(1024)==b'fd25:1::2';s.close()\nprint('ok')"))
 check('IPv6 DNAT-only preserves the real client source for TCP/UDP',observed=='ok')
 limited=v4spec('8_2_3',18007,'10.205.1.1',traffic={'localOutput':True,'localTargets':True});limited['leaseRequired']=True;PANEL.quota=8192;apply(limited)
 wait(lambda:'8_2_3' in state().get('leases',{}))
 wait(lambda:exchange('router','10.205.1.1',18007,protocols=('udp',)))
 run(ns('router','python3','-c',"import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(.01)\nfor i in range(30):\n try:s.sendto(b'b'*400,('10.205.1.1',18007));s.recv(1024)\n except (socket.timeout,PermissionError):pass"))
 check('local-to-local quota admits no more than the single shared 8KiB budget',0<sum(counters('8_2_3'))<=8192)
 check('exhaustion blocks local OUTPUT and external INPUT',exchange('router','10.205.1.1',18007,True) and exchange('client','10.205.1.1',18007,True));PANEL.quota=0
 stop(a)
 if helper:stop(helper);helper=start_helper()
 a=agent();check('state5 restart restores hook coverage and source policy',state()['formatVersion']==5 and exchange('router','127.0.0.1',18003) and exchange('router','10.205.1.1',18002))
 run(['ip','-n','router','addr','add','10.205.3.2/32','dev','r1'])
 check('enabling another local rule cannot opt a remote-only rule into INPUT',exchange('client','10.205.1.1',18000,True))
 run(['ip','-n','router','addr','del','10.205.3.2/32','dev','r1'])
 stop(a)
 if helper:stop(helper)
 before=state();run(ns('router',str(BUILD/'flux-agent'),'--config',str(CONFIG),'--maintenance','uninstall','--backup-dir',str(OUT/'backup')))
 check('uninstall removes local hooks, extra sets and quotas while preserving foreign rules','FP4_' not in router('iptables-save') and 'FP4_' not in router('ipset','list','-name') and 'FP4_QUOTA' not in router('nft','list','tables') and 'keep-unrelated' in router('iptables-save'))
 DONE=True
except Exception:
 traceback.print_exc()
 for name,args in [('iptables.txt',['iptables-save','-c']),('ipset.txt',['ipset','save']),('nft.json',['nft','-j','list','ruleset']),('conntrack.txt',['conntrack','-L'])]:
  try:(OUT/name).write_text(router(*args))
  except Exception:pass
 if (OUT/'agent.log').exists():print((OUT/'agent.log').read_text()[-8000:])
 raise
finally:
 for p in reversed(PROCS):stop(p)
 (OUT/'p2-result.json').write_text(json.dumps({'success':DONE,'count':len(CHECKS),'passed':CHECKS,'arch':os.uname().machine,'backend':os.getenv('IPTABLES_BACKEND','nft'),'external_forward_test_targets':[]},indent=2))
