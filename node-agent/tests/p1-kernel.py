"""P1 independent socket/kernel verifier; no external route or DNS server."""
from foundation_fixture import *
import socketserver,ipaddress
DNS_MODE={'drop':False,'address':'10.205.3.2','rcode':0,'truncated':False,'queries':0,'tcp':0}
def dns_reply(data,tcp=False):
 DNS_MODE['queries']+=1
 if tcp:DNS_MODE['tcp']+=1
 offset=12;labels=[]
 while data[offset]:n=data[offset];offset+=1;labels.append(data[offset:offset+n].decode());offset+=n
 offset+=1;qtype=struct.unpack('!H',data[offset:offset+2])[0];question=data[12:offset+4];name='.'.join(labels)
 if DNS_MODE['truncated'] and not tcp:return data[:2]+struct.pack('!5H',0x8380,1,0,0,0)+question
 code=DNS_MODE['rcode'];answers=b'';count=0
 if code==0 and qtype==1:
  if name=='alias.test':
   target=b'\x06origin\x04test\x00';answers=b'\xc0\x0c'+struct.pack('!HHIH',5,1,1,len(target))+target;count=1
  else:answers=b'\xc0\x0c'+struct.pack('!HHIH',1,1,1,4)+ipaddress.ip_address(DNS_MODE['address']).packed;count=1
 return data[:2]+struct.pack('!5H',0x8180|code,1,count,0,0)+question+answers
class DNSUDP(socketserver.BaseRequestHandler):
 def handle(self):
  data,s=self.request
  if not DNS_MODE['drop']:s.sendto(dns_reply(data),self.client_address)
class DNSTCP(socketserver.BaseRequestHandler):
 def handle(self):
  if DNS_MODE['drop']:return
  size=self.request.recv(2)
  if len(size)!=2:return
  need=struct.unpack('!H',size)[0];data=b''
  while len(data)<need:data+=self.request.recv(need-len(data))
  out=dns_reply(data,True);self.request.sendall(struct.pack('!H',len(out))+out)
try:
 if os.getenv('IPTABLES_BACKEND')=='legacy':run(['update-alternatives','--set','iptables','/usr/sbin/iptables-legacy']);run(['update-alternatives','--set','ip6tables','/usr/sbin/ip6tables-legacy'])
 topology()
 for n in ['client','router','transit','target']:
  run(ns(n,'sh','-c','(mount -o remount,rw /proc/sys 2>/dev/null || true); sysctl -w net.ipv6.conf.all.disable_ipv6=0'))
 for n,i,address in [('client','c0','fd25:1::2/64'),('router','r0','fd25:1::1/64'),('router','r1','fd25:2::1/64'),('transit','m0','fd25:2::2/64'),('transit','m1','fd25:3::1/64'),('target','t0','fd25:3::2/64')]:run(['ip','-n',n,'-6','addr','add',address,'dev',i,'nodad'])
 for n in ['router','transit']:run(ns(n,'sh','-c','(mount -o remount,rw /proc/sys 2>/dev/null || true); sysctl -w net.ipv6.conf.all.forwarding=1'))
 for n,route in [('client',['default','via','fd25:1::1']),('target',['default','via','fd25:3::1']),('router',['fd25:3::/64','via','fd25:2::2']),('transit',['fd25:1::/64','via','fd25:2::1'])]:run(['ip','-n',n,'-6','route','add',*route])
 router('ip6tables','-P','FORWARD','DROP')
 code="""import socket,threading,time
def tcp(c):
 try:
  while True:
   b=c.recv(65535)
   if not b:break
   c.sendall(b)
 finally:c.close()
def ts(port):
 s=socket.socket(socket.AF_INET6);s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1);s.bind(('fd25:3::2',port));s.listen(100)
 while True:
  c,_=s.accept();threading.Thread(target=tcp,args=(c,),daemon=True).start()
def us(port):
 s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM);s.bind(('fd25:3::2',port))
 while True:
  b,peer=s.recvfrom(65535);s.sendto(b,peer)
for port in [19000,19001]:
 threading.Thread(target=ts,args=(port,),daemon=True).start();threading.Thread(target=us,args=(port,),daemon=True).start()
time.sleep(600)
"""
 spawn(ns('target','python3','-c',code),'target6.log')
 server=http.server.ThreadingHTTPServer(('10.205.4.1',8000),Handler);server.daemon_threads=True;threading.Thread(target=server.serve_forever,daemon=True).start()
 for server_type,handler in [(socketserver.ThreadingUDPServer,DNSUDP),(socketserver.ThreadingTCPServer,DNSTCP)]:
  srv=server_type(('10.205.4.1',8053),handler);srv.daemon_threads=True;threading.Thread(target=srv.serve_forever,daemon=True).start()
 cfg={'addr':'http://10.205.4.1:8000','secret':SECRET,'statePath':str(STATE),'apply':True,'allowInsecure':True,'intervalSeconds':1,'dnsServers':['10.205.4.1:8053']}
 helper=None
 if os.getenv('FLUX_P1_HELPER')=='1':
  directory=pathlib.Path('/tmp/flux-p1-helper');directory.mkdir(mode=0o750);os.chown(directory,0,12345);cfg['helperSocket']=str(directory/'kernel.sock')
 CONFIG.write_text(json.dumps(cfg));CONFIG.chmod(0o644)
 if cfg.get('helperSocket'):
  helper=spawn(ns('router','setpriv','--regid=12345','--clear-groups',str(BUILD/'flux-agent'),'--kernel-helper','--helper-user','12345','--config',str(CONFIG)),'helper.log');wait(lambda:pathlib.Path(cfg['helperSocket']).exists())
  def agent(fault=''):
   serial=PANEL.serial;p=spawn(ns('router','setpriv','--reuid=12345','--regid=12345','--clear-groups','--bounding-set=-all',str(BUILD/'flux-agent'),'--config',str(CONFIG)),'agent-unprivileged.log');wait(lambda:PANEL.serial>serial and p.poll() is None);return p
 a=agent()
 if helper:
  status=pathlib.Path('/proc/'+str(a.pid)+'/status').read_text();check('network agent has dedicated UID and no effective capabilities','Uid:\t12345' in status and 'CapEff:\t0000000000000000' in status)
  forged=run(ns('router','python3','-c',f"import socket,json;s=socket.socket(socket.AF_UNIX);s.connect({cfg['helperSocket']!r});s.sendall(b'{{\"type\":\"Exec\",\"data\":{{\"cmd\":\"reboot\"}}}}\\n');r=json.loads(s.recv(4096));assert not r['success'];print('denied')"));check('privileged helper refuses arbitrary command methods',forged=='denied')
  denied="import socket,json;s=socket.socket(socket.AF_UNIX);s.connect("+repr(cfg['helperSocket'])+")\ntry:\n s.sendall(json.dumps({'type':'_Info'}).encode()+bytes([10]));assert s.recv(4096)==b''\nexcept (ConnectionResetError,BrokenPipeError):pass\nprint('denied')"
  check('socket peer credentials reject another UID even with socket group access',run(ns('router','setpriv','--reuid=54321','--regid=12345','--clear-groups','python3','-c',denied))=='denied')
 s={'schemaVersion':3,'id':'1_1_0','revision':1,'enabled':True,'listen':{'kind':'ip','host':'::','family':'dual','port':18000},'targets':[{'endpoint':{'host':'10.205.3.2','port':19000},'weight':1},{'endpoint':{'host':'fd25:3::2','port':19000},'weight':1}]}
 apply(s);check('advanced IPv4 data path forwards actual TCP and UDP',probe())
 def v6probe(blocked=False,size=128):
  code="""import socket
target=('fd25:1::1',18000);payload=b'v'*SIZE
for kind in [socket.SOCK_STREAM,socket.SOCK_DGRAM]:
 s=socket.socket(socket.AF_INET6,kind);s.settimeout(.4 if BLOCKED else 2)
 if kind==socket.SOCK_DGRAM:s.setsockopt(socket.IPPROTO_IPV6,23,0)
 try:
  s.connect(target);s.sendall(payload);b=b''
  while len(b)<len(payload):
   chunk=s.recv(65535);assert chunk;b+=chunk
  assert not BLOCKED and b==payload
 except (TimeoutError,OSError):assert BLOCKED
 finally:s.close()
print('ok')""".replace('BLOCKED',str(blocked)).replace('SIZE',str(size))
  return run(ns('client','python3','-c',code))=='ok'
 wait(lambda:v6probe(),8);check('IPv6 direct DNAT/SNAT forwards real TCP and UDP')
 run(['ip','-n','transit','link','set','m1','mtu','1280']);run(['ip','-n','target','link','set','t0','mtu','1280'])
 pmtu6="""import socket,struct
r=socket.socket(socket.AF_INET6,socket.SOCK_RAW,socket.IPPROTO_ICMPV6);r.settimeout(3)
u=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM);u.setsockopt(socket.IPPROTO_IPV6,23,2);u.sendto(b'p'*1400,('fd25:1::1',18000))
while True:
 b,peer=r.recvfrom(4096)
 if b[0]==2:assert struct.unpack('!I',b[4:8])[0]==1280;print(peer[0]);break
"""
 observed6=run(ns('client','python3','-c',pmtu6));check('real ICMPv6 Packet Too Big crosses NAT from an intermediate router',observed6 in ['fd25:2::2','fd25:1::1'])
 check('IPv6 source fragments and TCP segments survive the smaller PMTU',v6probe(size=4000))

 wait(lambda:sum(state()['totals']['1_1_0'].get(x,0) for x in ['up','down'])>0)
 check('two families share one business ledger',len(state()['totals'])==1)
 PANEL.rpc('SetForwardState',{'id':'1_1_0','revision':2,'enabled':False});check('one pause blocks both families',probe(blocked=True) and v6probe(True,4000))
 PANEL.rpc('SetForwardState',{'id':'1_1_0','revision':3,'enabled':True});check('one resume restores both families',probe() and v6probe())
 stop(a);a=agent();check('dual-stack state and counters survive process restart',probe() and v6probe())
 limited=json.loads(json.dumps(s));limited.update(id='2_2_3',leaseRequired=True);limited['listen']['port']=18001;PANEL.quota=65536;apply(limited)
 wait(lambda:'2_2_3' in state().get('leases',{}))
 flood="""import socket,threading
def worker(family,host):
 s=socket.socket(family,socket.SOCK_DGRAM);s.settimeout(.005)
 for _ in range(80):
  s.sendto(b'q'*1000,(host,18001))
  try:s.recv(2048)
  except socket.timeout:pass
threads=[threading.Thread(target=worker,args=x) for x in [(socket.AF_INET,'10.205.1.1'),(socket.AF_INET6,'fd25:1::1')]]
for t in threads:t.start()
for t in threads:t.join()
"""
 run(ns('client','python3','-c',flood));time.sleep(1.2)
 u=state()['totals']['2_2_3'];check('concurrent IPv4/IPv6 share one 64KiB admitted-byte budget',0<u['up']+u['down']<=65536)
 objs=json.loads(router('nft','-j','list','table','inet','FP4_QUOTA'));quotas=[x['quota'] for x in objs['nftables'] if 'quota' in x];check('one quota object covers both address families',len(quotas)==1 and quotas[0]['used']>=quotas[0]['bytes'])
 for host,family in [('10.205.1.1','AF_INET'),('fd25:1::1','AF_INET6')]:
  run(ns('client','python3','-c',f"import socket;s=socket.socket(socket.{family},socket.SOCK_DGRAM);s.settimeout(.3);s.sendto(b'blocked',('{host}',18001))\ntry:s.recv(100);raise AssertionError('quota bypass')\nexcept socket.timeout:pass"))
 check('exhausted shared quota blocks both families without disabling statistics');PANEL.quota=0
 run(['ip','-n','target','addr','add','10.205.3.3/24','dev','t0'])
 identity_server="""import socket,threading,time
def conn(c):
 try:
  while True:
   b=c.recv(4096)
   if not b:return
   c.sendall(c.getsockname()[0].encode()+b'|'+b)
 finally:c.close()
s=socket.socket();s.bind(('0.0.0.0',19002));s.listen(100)
while True:
 c,_=s.accept();threading.Thread(target=conn,args=(c,),daemon=True).start()
"""
 spawn(ns('target','python3','-c',identity_server),'identity-target.log')
 dns={'schemaVersion':3,'id':'3_1_0','revision':1,'enabled':True,'listeners':[{'host':'10.205.1.1','port':18002,'protocol':'tcp'}],'targets':[{'endpoint':{'host':'alias.test','port':19002},'weight':1}]};apply(dns)
 wait(lambda:any(p['host']=='10.205.3.2' and p['acceptNew'] for p in state()['rules']['3_1_0']['runtime'].get('targets',[])))
 def identity():return run(ns('client','python3','-c',"import socket;s=socket.create_connection(('10.205.1.1',18002),timeout=2);s.sendall(b'new');print(s.recv(100).decode());s.close()"))
 check('node-side CNAME/TTL resolution drives actual TCP forwarding',identity()=='10.205.3.2|new')
 held="""import socket,time,pathlib
s=socket.create_connection(('10.205.1.1',18002),timeout=2);s.settimeout(2)
pathlib.Path('/tmp/held-ready').touch()
for _ in range(100):
 s.sendall(b'held');assert s.recv(100)==b'10.205.3.2|held';time.sleep(.05)
s.close();pathlib.Path('/tmp/held-ok').touch()
"""
 client=spawn(ns('client','python3','-c',held),'held-client.log');wait(lambda:pathlib.Path('/tmp/held-ready').exists());DNS_MODE['address']='10.205.3.3'
 wait(lambda:identity()=='10.205.3.3|new',12);assert client.wait(timeout=10)==0
 check('DNS rotation changes new connections while an old TCP connection drains',pathlib.Path('/tmp/held-ok').exists())
 DNS_MODE['truncated']=True;wait(lambda:DNS_MODE['tcp']>0,8);check('truncated UDP DNS response falls back to TCP',identity()=='10.205.3.3|new')
 run(['ip','-n','router','addr','add','10.205.2.9/24','dev','r1'])
 source_server="""import socket,threading
def worker(c):
 try:c.recv(10);c.sendall(c.getpeername()[0].encode())
 finally:c.close()
s=socket.socket();s.bind(('0.0.0.0',19003));s.listen(50)
while True:
 c,_=s.accept();threading.Thread(target=worker,args=(c,),daemon=True).start()
"""
 spawn(ns('target','python3','-c',source_server),'source-target.log')
 routed={'schemaVersion':3,'id':'4_1_0','revision':1,'enabled':True,'listeners':[{'host':'10.205.1.1','port':18003,'protocol':'tcp'}],'targets':[{'endpoint':{'host':'10.205.3.2','port':19003},'weight':1}],'egress':{'interface':'r1','sourceIPv4':'10.205.2.9','gatewayIPv4':'10.205.2.2'}}
 router('ip','route','add','198.18.0.0/15','dev','r1','table',str(0xf2000001))
 check('a foreign route in an otherwise reserved table is preserved and rejected',not apply(routed,False)['success'] and '198.18.0.0/15' in router('ip','route','show','table',str(0xf2000001)))
 router('ip','route','del','198.18.0.0/15','dev','r1','table',str(0xf2000001))
 router('ip','rule','add','pref','18900','from','10.205.99.0/24','lookup',str(0xf2000001))
 check('a foreign rule referencing an empty reserved table is rejected',not apply(routed,False)['success'] and '18900:' in router('ip','rule'))
 router('ip','rule','del','pref','18900','from','10.205.99.0/24','lookup',str(0xf2000001))
 apply(routed)
 observed=run(ns('client','python3','-c',"import socket;s=socket.create_connection(('10.205.1.1',18003),timeout=3);s.sendall(b'x');print(s.recv(100).decode())"))
 check('owned policy routing and explicit SNAT select the requested source',observed=='10.205.2.9' and 'default' not in router('ip','route'))
 run(['ip','-n','router','-6','addr','add','fd25:2::9/64','dev','r1','nodad'])
 source6=source_server.replace("socket.socket();s.bind(('0.0.0.0',19003))","socket.socket(socket.AF_INET6);s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1);s.bind(('::',19003))")
 spawn(ns('target','python3','-c',source6),'source6-target.log')
 routed6=json.loads(json.dumps(routed));routed6['id']='10_1_0';routed6['listeners'][0]['host']='fd25:1::1';routed6['targets'][0]['endpoint']['host']='fd25:3::2';routed6['egress'].update(sourceIPv6='fd25:2::9',gatewayIPv6='fd25:2::2');apply(routed6)
 wait(lambda:run(ns('client','python3','-c',"import socket;s=socket.create_connection(('fd25:1::1',18003),timeout=2);s.sendall(b'x');print(s.recv(100).decode())"))=='fd25:2::9')
 check('IPv6 policy routing and explicit SNAT select the requested IPv6 source')

 shaped={'schemaVersion':3,'id':'5_1_0','revision':1,'enabled':True,'listen':{'host':'10.205.1.1','port':18004},'targets':[{'endpoint':{'host':'10.205.3.2','port':19000},'weight':1}],'bandwidth':{'upBitsPerSecond':5000000,'downBitsPerSecond':5000000,'user':{'id':'u1','upBitsPerSecond':10000000,'downBitsPerSecond':10000000},'tunnel':{'id':'ut1','upBitsPerSecond':8000000,'downBitsPerSecond':8000000}}}
 apply(shaped)
 bulk="import socket,time,threading;s=socket.create_connection(('10.205.1.1',18004),timeout=5);s.settimeout(8);size=1048576;data=b's'*size;t=time.monotonic();threading.Thread(target=lambda:s.sendall(data),daemon=True).start();n=0\nwhile n<size:\n b=s.recv(min(65536,size-n));assert b and b==b's'*len(b);n+=len(b)\nprint(time.monotonic()-t)"
 elapsed=float(run(ns('client','python3','-c',bulk)));check('owned HTB/fq_codel smoothly shapes both directions through IFB',1.1<elapsed<8)
 (OUT/'shaping.json').write_text(json.dumps({'payloadBytes':1048576,'seconds':elapsed,'configuredBitsPerSecond':5000000,'classesText':router('tc','-s','class','show','dev','fp4shape')},indent=2))
 PANEL.rpc('SetForwardState',{'id':'5_1_0','revision':2,'enabled':False});check('pause flushes owned shaping queues and blocks TCP/UDP',probe(18004,True))

 shaped6=json.loads(json.dumps(shaped));shaped6['id']='9_1_0';shaped6['listen']['host']='fd25:1::1';shaped6['targets'][0]['endpoint']['host']='fd25:3::2';apply(shaped6)
 bulk6=bulk.replace("socket.create_connection(('10.205.1.1',18004),timeout=5)","socket.create_connection(('fd25:1::1',18004),timeout=5)")
 elapsed6=float(run(ns('client','python3','-c',bulk6)));check('IPv6 TCP uses the same bidirectional smooth shaping path',1.1<elapsed6<10)
 siblings=[]
 for i in range(2):
  peer=json.loads(json.dumps(shaped));peer['id']=str(11+i)+'_1_0';peer['listen']['port']=18010+i;peer['bandwidth']['user']={'id':'shared','upBitsPerSecond':6000000,'downBitsPerSecond':6000000};peer['bandwidth']['tunnel']={'id':'shared-tunnel'};apply(peer);siblings.append(peer)
 jobs=[spawn(ns('client','python3','-c',bulk.replace('18004',str(18010+i))),'shared-client-'+str(i)+'.log') for i in range(2)]
 t=time.monotonic()
 for j in jobs:assert j.wait(timeout=15)==0
 sharedTime=time.monotonic()-t;check('two forwarding peers cannot multiply one 6 Mbps shared user ceiling',2.1<sharedTime<12)
 (OUT/'shared-shaping.json').write_text(json.dumps({'peers':2,'bytesPerPeer':1048576,'sharedBitsPerSecond':6000000,'seconds':sharedTime}))

 # A replaced link can reuse its name but has no previous tc classifiers.
 for iteration in range(2):
  router('ip','link','add','dyn0','type','dummy');router('ip','addr','add','10.206.0.1/24','dev','dyn0');router('ip','link','set','dyn0','up')
  wait(lambda:'fw' in router('tc','filter','show','dev','dyn0','egress'),10)
  router('ip','link','del','dyn0')
 check('a recreated same-name interface receives fresh owned shaping classifiers')
 # DNS failures must close new connections while allowing explicit recovery.
 dns['revision']=2;dns['dnsPolicy']={'staleMillis':1200,'drainMillis':6000};apply(dns)
 DNS_MODE['drop']=True
 wait(lambda:not any(p.get('acceptNew') for p in state()['rules']['3_1_0']['runtime'].get('targets',[]) if not p.get('retiredAt')),8)
 check('DNS outage closes new admission after finite stale grace without a control request')
 DNS_MODE['drop']=False;DNS_MODE['rcode']=3
 wait(lambda:'NXDOMAIN' in state()['rules']['3_1_0']['runtime'].get('error',''),10)
 check('NXDOMAIN has distinct failure status and cannot reuse stale targets',not any(p.get('acceptNew') for p in state()['rules']['3_1_0']['runtime'].get('targets',[]) if not p.get('retiredAt')))
 DNS_MODE['rcode']=0
 wait(lambda:identity()=='10.205.3.3|new',12);check('DNS recovery reopens new connections')
 # Independent TCP and UDP forwards can own the same physical port.
 tcp_only={'schemaVersion':3,'id':'6_1_0','revision':1,'enabled':True,'listeners':[{'host':'0.0.0.0','port':18005,'protocol':'tcp'}],'targets':[{'endpoint':{'host':'10.205.3.2','port':19000},'weight':1}]}
 udp_only=json.loads(json.dumps(tcp_only));udp_only['id']='7_1_0';udp_only['listeners'][0]['protocol']='udp';apply(tcp_only);apply(udp_only)
 check('separate business IDs can use TCP and UDP on the same listen port',probe(18005))
 PANEL.rpc('SetForwardState',{'id':'6_1_0','revision':2,'enabled':False})
 protocol_probe="""import socket
for kind in [socket.SOCK_STREAM,socket.SOCK_DGRAM]:
 s=socket.socket(socket.AF_INET,kind);s.settimeout(.3)
 try:
  s.connect(('10.205.1.1',18005));s.sendall(b'p');b=s.recv(10);assert kind==socket.SOCK_DGRAM and b==b'p'
 except (OSError,TimeoutError):assert kind==socket.SOCK_STREAM
 finally:s.close()
print('ok')"""
 check('pausing the TCP business leaves its same-port UDP peer working',run(ns('client','python3','-c',protocol_probe))=='ok')
 # Wildcard expansion reacts to netlink events without a business revision.
 run(['ip','-n','router','addr','add','10.205.1.9/24','dev','r0'])
 wait(lambda:'10.205.1.9,udp:18005' in router('ipset','save','FP4_BIND'))
 check('new wildcard address forwards UDP without resuming paused TCP',run(ns('client','python3','-c',protocol_probe.replace('10.205.1.1','10.205.1.9')))=='ok')
 run(['ip','-n','router','addr','del','10.205.1.9/24','dev','r0'])
 wait(lambda:'10.205.1.9,' not in router('ipset','save','FP4_BIND'));check('deleted local address leaves no wildcard binding')
 # Weighted round-robin uses separate new sockets; established sockets stay pinned.
 pool={'schemaVersion':3,'id':'8_1_0','revision':1,'enabled':True,'listeners':[{'host':'10.205.1.1','port':18006,'protocol':'tcp'}],'selection':'round','targets':[{'endpoint':{'host':'10.205.3.2','port':19002},'weight':1},{'endpoint':{'host':'10.205.3.3','port':19002},'weight':3}]};apply(pool)
 distribution="""import socket,json;counts={}
for _ in range(80):
 s=socket.create_connection(('10.205.1.1',18006),timeout=2);s.sendall(b'x');h=s.recv(100).decode().split('|')[0];counts[h]=counts.get(h,0)+1;s.close()
print(json.dumps(counts))"""
 weights=json.loads(run(ns('client','python3','-c',distribution)));check('weighted new-connection selection retains the configured 1:3 distribution',16<=weights.get('10.205.3.2',0)<=24 and 56<=weights.get('10.205.3.3',0)<=64)
 (OUT/'weight-distribution.json').write_text(json.dumps(weights))
 # Explicit health checks exercise rise/fall and stop selecting only the failed target.
 pool['revision']=2;pool['health']={'protocol':'tcp','intervalMillis':1000,'timeoutMillis':200,'rise':1,'fall':2};apply(pool)
 wait(lambda:all(p['healthy'] for p in state()['rules']['8_1_0']['runtime']['targets']))
 run(ns('target','iptables','-I','INPUT','1','-d','10.205.3.2','-p','tcp','--dport','19002','-j','REJECT'))
 wait(lambda:any(p['host']=='10.205.3.2' and not p['healthy'] for p in state()['rules']['8_1_0']['runtime']['targets']),8)
 check('health fall removes a failed target from new selection',json.loads(run(ns('client','python3','-c',distribution)))=={'10.205.3.3':80})
 run(ns('target','iptables','-D','INPUT','-d','10.205.3.2','-p','tcp','--dport','19002','-j','REJECT'))
 wait(lambda:all(p['healthy'] for p in state()['rules']['8_1_0']['runtime']['targets']),8);check('health rise restores recovered targets')

 # Source-IP hashing should keep new connections from each source on one node.
 pool['revision']=3;pool['selection']='hash';pool.pop('health');apply(pool)
 for i in range(10,74):run(['ip','-n','client','addr','add','10.205.1.'+str(i)+'/24','dev','c0'])
 hash_probe="""import socket,json
counts={}
for i in range(10,74):
 selected=set()
 for _ in range(4):
  s=socket.socket();s.settimeout(2);s.bind(('10.205.1.'+str(i),0));s.connect(('10.205.1.1',18006));s.sendall(b'h');selected.add(s.recv(100).decode().split('|')[0]);s.close()
 assert len(selected)==1
 h=next(iter(selected));counts[h]=counts.get(h,0)+1
print(json.dumps(counts))
"""
 hashes=json.loads(run(ns('client','python3','-c',hash_probe)))
 check('source-IP hash is stable across fresh connections and distributes sources',len(hashes)==2 and 6<=hashes.get('10.205.3.2',0)<=32)
 (OUT/'hash-distribution.json').write_text(json.dumps(hashes))
 # Source removal fails closed and address restoration recovers without API apply.
 run(['ip','-n','router','addr','del','10.205.2.9/24','dev','r1'])
 wait(lambda:PANEL.rpc('GetForwardStatus',{'id':'4_1_0'})['data']['status']=='failed',8)
 run(['ip','-n','router','addr','add','10.205.2.9/24','dev','r1'])
 wait(lambda:run(ns('client','python3','-c',"import socket;s=socket.create_connection(('10.205.1.1',18003),timeout=1);s.sendall(b'x');print(s.recv(100).decode())"))=='10.205.2.9',10)
 check('egress source loss fails closed and address restoration recovers')
 # Helper recovery must rebuild shaping and both address families.
 PANEL.rpc('SetForwardState',{'id':'5_1_0','revision':3,'enabled':True})
 if helper:
  stop(a);stop(helper);serial=PANEL.serial
  helper=spawn(ns('router','setpriv','--regid=12345','--clear-groups',str(BUILD/'flux-agent'),'--kernel-helper','--helper-user','12345','--config',str(CONFIG)),'helper.log');time.sleep(.5);a=agent()
 else:stop(a);a=agent()
 check('restart restores dual-stack, policy routing, health and shaping ownership',probe() and v6probe() and 1.1<float(run(ns('client','python3','-c',bulk)))<8)
 # Maintenance must settle once and remove only resources owned by this engine.
 stop(a)
 if helper:stop(helper)
 before=state();backup=OUT/'advanced-backup'
 run(ns('router',str(BUILD/'flux-agent'),'--config',str(CONFIG),'--maintenance','uninstall','--backup-dir',str(backup)))
 after=state()
 check('advanced uninstall preserves epoch and monotonic cumulative ledger',before['epoch']==after['epoch'] and after['totals']['1_1_0']['up']>=before['totals']['1_1_0']['up'])
 check('advanced uninstall removes owned IPv4/IPv6/nft/IFB/routing resources','FP4_' not in router('iptables-save') and 'FP6_' not in router('ip6tables-save') and 'FP4_QUOTA' not in router('nft','list','tables') and 'fp4shape' not in router('ip','link') and '4060086' not in router('ip','rule'))
 check('advanced uninstall preserves unrelated firewall policy','keep-unrelated' in router('iptables-save'))
 DONE=True
except Exception:
 traceback.print_exc()
 for name in ['agent.log','helper.log','agent-unprivileged.log']:
  p=OUT/name
  if p.exists():print(name,p.read_text()[-6000:])
 try:
  (OUT/'tc-failed.json').write_text(router('tc','-j','-s','class','show','dev','fp4shape'));(OUT/'tc-filters-failed.json').write_text(router('tc','-j','-s','filter','show','dev','r1','egress'));(OUT/'nft-failed.json').write_text(router('nft','-j','list','ruleset'))
 except Exception:pass
 try:(OUT/'ipset-failed.txt').write_text(router('ipset','save'));(OUT/'routes6-failed.txt').write_text(router('ip','-6','route'));(OUT/'neigh6-failed.txt').write_text(router('ip','-6','neigh'))
 except Exception:pass
 for binary in ['iptables-save','ip6tables-save']:
  try:(OUT/(binary+'.txt')).write_text(router(binary))
  except Exception:pass
 raise
finally:
 for p in reversed(PROCS):stop(p)
 (OUT/'p1-result.json').write_text(json.dumps({'success':DONE,'arch':os.uname().machine,'backend':os.getenv('IPTABLES_BACKEND','nft'),'count':len(CHECKS),'passed':CHECKS,'external_forward_test_targets':[]},indent=2))
