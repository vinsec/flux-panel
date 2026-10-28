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
 if KERNEL_BACKEND=='nftables':return native_counters(ident)
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
 router('ip6tables','-P','FORWARD','ACCEPT' if KERNEL_BACKEND=='nftables' else 'DROP')
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
 write_config(cfg);CONFIG.chmod(0o644)
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
 assert helper is not None
 caps=pathlib.Path('/proc/'+str(helper.pid)+'/status').read_text();values={line.split(':')[0]:int(line.split()[1],16) for line in caps.splitlines() if line.startswith(('CapEff:','CapPrm:','CapBnd:','CapAmb:'))}
 check('long-lived helper effective/permitted/bounding/ambient exclude SYS_ADMIN and BPF',all(v&((1<<21)|(1<<39))==0 for v in values.values()) and values['CapEff']==0x3400)
 root=pathlib.Path('/proc/'+str(helper.pid)+'/root');directory=root/'run/flux-agent-bpf';record_path=next(directory.glob('*.json'));record=json.loads(record_path.read_text());pin=root/'sys/fs/bpf/flux-local-shaping'/('restore_'+record['objectSHA256'])
 s=v4spec('120_1_0',18520,'10.205.2.1',traffic={'localOutput':True,'localTargets':True});s['bandwidth']={'upBitsPerSecond':8000000};apply(s);time.sleep(1);check('prepared pin forwards through base-capability helper',exchange('router','10.205.1.1',18520))
 def status():return PANEL.rpc('GetForwardStatuses',{'ids':['120_1_0']})['data']['120_1_0']['status']
 def write(value):record_path.write_text(json.dumps(value));record_path.chmod(0o600)
 for field,value in [('phase','prepared'),('bootId','previous-boot'),('programId',record['programId']+1),('programTag','not-the-program'),('objectSHA256','untrusted-object')]:
  changed=dict(record);changed[field]=value;write(changed);wait(lambda:status()=='failed');check(field+' mismatch fails capped rule closed',exchange('router','10.205.1.1',18520,True));write(record);wait(lambda:status()=='applied');check(field+' restoration recovers without changing revision',exchange('router','10.205.1.1',18520))
 changed=dict(record);changed['phase']='prepared';write(changed);wait(lambda:status()=='failed')
 invoke=['nsenter','-t',str(helper.pid),'-m','-n']
 same=json.loads(run([*invoke,str(BUILD/'flux-agent'),'--prepare-local-shaping']));check('interrupted preparation commits idempotently without loading another program',same['reused'] and same['programId']==record['programId']);wait(lambda:status()=='applied')
 # Parent administrator removes a pin; the daemon cannot remount or reload it.
 run([*invoke,'mount','-o','remount,bind,rw','/sys/fs/bpf']);pin.unlink();run([*invoke,'mount','-o','remount,bind,ro','/sys/fs/bpf']);wait(lambda:status()=='failed');check('missing pin closes the capped rule',exchange('router','10.205.1.1',18520,True))
 denied=subprocess.run([*invoke,'setpriv','--bounding-set=-all,+net_admin,+net_raw,+net_bind_service',str(BUILD/'flux-agent'),'--prepare-local-shaping'],capture_output=True,text=True)
 check('daemon capabilities cannot perform module-BTF preparation',denied.returncode!=0)
 run([*invoke,'mount','-o','remount,bind,rw','/sys/fs/bpf']);fresh=json.loads(run([*invoke,str(BUILD/'flux-agent'),'--prepare-local-shaping']));run([*invoke,'mount','-o','remount,bind,ro','/sys/fs/bpf']);wait(lambda:status()=='applied');check('short-lived administrator repairs the pin while daemon stays unprivileged',fresh['programId']!=record['programId'] and exchange('router','10.205.1.1',18520))
 check('last preparation leaves no loader device',not router('ip','-j','link','show').find('fp4bpfload')>=0)
 DONE=True

except Exception:
 traceback.print_exc()
 raise
finally:
 for p in reversed(PROCS):stop(p)
 (OUT/'result.json').write_text(json.dumps({'success':DONE,'checks':CHECKS}))
