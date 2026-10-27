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
 BPF_PREP='mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf; mount -o remount,rw /sys/fs/bpf; mkdir -p /sys/fs/bpf/tc/globals /sys/fs/bpf/ip/globals /sys/fs/bpf/xdp/globals; mount --bind /sys/fs/bpf /sys/fs/bpf; mount -o remount,bind,ro /sys/fs/bpf; exec "$@"'
 def start_helper():
  p=spawn(ns('router','sh','-c',BPF_PREP,'sh','setpriv','--regid=12345','--clear-groups','--bounding-set=-all,+net_admin,+net_raw,+net_bind_service,+bpf,+sys_admin',str(BUILD/'flux-agent'),'--kernel-helper','--helper-user','12345','--config',str(CONFIG)),'helper.log');wait(lambda:pathlib.Path(cfg['helperSocket']).exists());return p
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

 def service(host):
  code=f"import socket;s=socket.socket(socket.AF_INET6 if {':' in host!r} else socket.AF_INET,socket.SOCK_DGRAM);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(({host!r},19004))\nwhile True:\n b,p=s.recvfrom(65535);s.sendto(p[0].encode() if b==b'peer' else b,p)"
  return spawn(ns('router','python3','-c',code),'service-'+host.replace(':','_')+'.log')
 def query(where,host,port,expected=None,blocked=False):
  code=f"""import socket
s=socket.socket(socket.AF_INET6 if {':' in host!r} else socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(.3 if {blocked!r} else 2)
try:
 s.sendto(b'peer',({host!r},{port}));b=s.recv(1024);assert not {blocked!r};assert b=={expected.encode() if expected else b''!r},b
except (OSError,TimeoutError):assert {blocked!r}
s.close();print('ok')
"""
  return run(ns(where,'python3','-c',code))=='ok'
 hosts=['10.205.2.1','fd25:2::1','127.0.0.1','::1'];servers={h:service(h) for h in hosts};time.sleep(.3)
 for i,(listen,target,client_source,host_source) in enumerate([('10.205.1.1','10.205.2.1','10.205.1.2','10.205.1.1'),('fd25:1::1','fd25:2::1','fd25:1::2','fd25:1::1'),('127.0.0.1','127.0.0.1',None,'127.0.0.1'),('::1','::1',None,'::1')]):
  ident=f'{80+i}_1_0';port=18300+i;s=v4spec(ident,port,target,19004,{'localOutput':True,'localTargets':True,'sourceMode':'preserve','returnPathConfirmed':True});s.pop('listen');s['listeners']=[{'host':listen,'port':port,'protocol':'udp'}];apply(s);time.sleep(2)
  check(target+' local UDP sees the actual host source',query('router',listen,port,host_source));exact_udp('router',listen,port,ident,':' in listen);check(target+' source-preserved counters exact')
  if client_source:check(target+' local UDP sees the actual external client source',query('client',listen,port,client_source))
  s['revision']=2;s['bandwidth']={'upBitsPerSecond':8000000,'downBitsPerSecond':8000000};apply(s);time.sleep(2)
  check(target+' source preservation composes with local shaping',query('router',listen,port,host_source))
  if client_source:check(target+' external source survives shared IFB',query('client',listen,port,client_source))
  PANEL.rpc('SetForwardState',{'id':ident,'revision':3,'enabled':False});check(target+' pause blocks preserved local UDP',query('router',listen,port,blocked=True));PANEL.rpc('SetForwardState',{'id':ident,'revision':4,'enabled':True})
  check(target+' resume restores source contract',query('router',listen,port,host_source))
  stop(a)
  if helper:stop(helper);helper=start_helper()
  a=agent();time.sleep(2);check(target+' restart retains source and shaping contract',query('router',listen,port,host_source))
  if i<2:
   stop(servers[target]);wild='::' if ':' in target else '0.0.0.0';w=service(wild);time.sleep(.15)
   wait(lambda:PANEL.rpc('GetForwardStatuses',{'ids':[ident]})['data'][ident]['status']=='failed')
   check(target+' binding change fails closed without SNAT fallback',query('router',listen,port,blocked=True))
   stop(w);servers[target]=service(target);time.sleep(.15);wait(lambda:PANEL.rpc('GetForwardStatuses',{'ids':[ident]})['data'][ident]['status']=='applied')
   check(target+' exact binding recovery restores rule',query('router',listen,port,host_source))
  PANEL.rpc('DeleteForward',{'id':ident,'revision':5})
 # One shared, finite quota covers preserved external and host-local requests.
 s=v4spec('90_2_3',18400,'10.205.2.1',19004,{'localOutput':True,'localTargets':True,'sourceMode':'preserve','returnPathConfirmed':True});s.pop('listen');s['listeners']=[{'host':'10.205.1.1','port':18400,'protocol':'udp'}];s['bandwidth']={'upBitsPerSecond':8000000,'downBitsPerSecond':8000000};s['leaseRequired']=True;PANEL.quota=8192;apply(s)
 wait(lambda:'90_2_3' in state().get('leases',{}));time.sleep(2)
 code="""import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(.02)
for i in range(40):
 try:s.sendto(b'q'*400,('10.205.1.1',18400));s.recv(1024)
 except (OSError,TimeoutError):pass
"""
 run(ns('router','python3','-c',code));run(ns('client','python3','-c',code));check('source preservation plus shaping obeys one shared 8KiB quota',0<sum(counters('90_2_3'))<=8192 and query('router','10.205.1.1',18400,blocked=True) and query('client','10.205.1.1',18400,blocked=True));PANEL.quota=0
 DONE=True

except Exception:
 traceback.print_exc()
 try:print(PANEL.rpc('GetForwardStatuses',{'ids':[f'{i+80}_1_0' for i in range(8)]}),flush=True)
 except Exception:pass
 for file,args in [('rules.txt',['iptables-save','-c']),('ct.txt',['conntrack','-L']),('link.txt',['ip','-d','link']),('tc-lo.txt',['tc','-s','filter','show','dev','lo','egress']),('tc-lo-restore.txt',['tc','-s','filter','show','dev','lo','egress','chain','201']),('classes.txt',['tc','-s','class','show','dev','fp4shape'])]:
  try:(OUT/file).write_text(router(*args))
  except Exception:pass
 raise
finally:
 for p in reversed(PROCS):stop(p)
 (OUT/'result.json').write_text(json.dumps({'success':DONE,'checks':CHECKS}))
