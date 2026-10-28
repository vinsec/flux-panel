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
 for family,host,target,source,gateway in [('ipv4','10.205.1.1','10.205.3.2','10.205.2.1','10.205.2.2'),('ipv6','fd25:1::1','fd25:3::2','fd25:2::1','fd25:2::2')]:
  ipv6=family=='ipv6';port=18510 if ipv6 else 18509;ident='111_1_0' if ipv6 else '110_1_0'
  rule=v4spec(ident,port,target,traffic={'localOutput':True});rule['listen']['host']=host;rule['bandwidth']={'upBitsPerSecond':8000000,'downBitsPerSecond':8000000};rule['egress']={'interface':'r1','sourceIPv6' if ipv6 else 'sourceIPv4':source,'gatewayIPv6' if ipv6 else 'gatewayIPv4':gateway};apply(rule);time.sleep(1)
  check(family+' local OUTPUT shaping composes with selected source/gateway',exchange('router',host,port));exact_udp('router',host,port,ident,ipv6);check(family+' routed queue retains exact UDP counters')
  for where in ['router','client']:
   code=f"""import socket,time,threading
s=socket.create_connection(({host!r},{port}),timeout=3);s.settimeout(8);b=b'b'*1048576;start=time.monotonic();threading.Thread(target=lambda:s.sendall(b),daemon=True).start();count=0
while count<len(b):
 data=s.recv(65536);assert data and data==b'b'*len(data);count+=len(data)
print(time.monotonic()-start)
"""
   seconds=float(run(ns(where,'python3','-c',code)));check(family+' '+where+' routed direction enters its shared queue only once',.65<seconds<1.7)
   udp=f"""import socket,time
s=socket.socket(socket.AF_INET6 if {ipv6!r} else socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(2);s.connect(({host!r},{port}));b=b'u'*1200;start=time.monotonic()
for i in range(1000):
 s.send(b);assert s.recv(4096)==b
print(time.monotonic()-start)
"""
   seconds=float(run(ns(where,'python3','-c',udp)));check(family+' '+where+' UDP stream is queued at its configured smooth rate',.8<seconds<2)


 run(['ip','-n','transit','link','set','m1','mtu','1280']);run(['ip','-n','target','link','set','t0','mtu','1280'])
 code6="""import socket,struct
r=socket.socket(socket.AF_INET6,socket.SOCK_RAW,socket.IPPROTO_ICMPV6);r.settimeout(3)
u=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM);u.setsockopt(socket.IPPROTO_IPV6,23,2);u.sendto(b'p'*1400,('fd25:1::1',18510))
while True:
 b,peer=r.recvfrom(4096)
 if b[0]==2:assert struct.unpack('!I',b[4:8])[0]==1280;print(peer[0]);break
"""
 observed=run(ns('router','python3','-c',code6));check('locally initiated shaped IPv6 receives real Packet Too Big',observed in ['fd25:2::2','fd25:1::1'])
 code4="""import socket,struct
r=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP);r.settimeout(3)
u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);u.setsockopt(socket.IPPROTO_IP,10,2);u.sendto(b'p'*1400,('10.205.1.1',18509))
while True:
 b,peer=r.recvfrom(4096);off=(b[0]&15)*4
 if b[off:off+2]==b'\x03\x04':assert struct.unpack('!H',b[off+6:off+8])[0]==1280;print(peer[0]);break
"""
 observed=run(ns('router','python3','-c',code4));check('locally initiated shaped IPv4 receives real fragmentation-needed',observed in ['10.205.2.2','10.205.1.1'])
 DONE=True

except Exception:
 traceback.print_exc()
 raise
finally:
 for p in reversed(PROCS):stop(p)
 (OUT/'result.json').write_text(json.dumps({'success':DONE,'checks':CHECKS}))
