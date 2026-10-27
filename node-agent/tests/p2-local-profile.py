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
  p=spawn(ns('router','sh','-c',BPF_PREP,'sh','setpriv','--regid=12345','--clear-groups','--bounding-set=-all,+net_admin,+net_raw,+net_bind_service,+bpf,+sys_admin',BINARY,'--kernel-helper','--helper-user','12345','--config',str(CONFIG)),'helper.log');wait(lambda:pathlib.Path(cfg['helperSocket']).exists());return p
 if cfg.get('helperSocket'):
  helper=start_helper()
  def agent(fault='',timeout=20):
   serial=PANEL.serial;p=spawn(ns('router','setpriv','--reuid=12345','--regid=12345','--clear-groups','--bounding-set=-all',BINARY,'--config',str(CONFIG)),'network.log');wait(lambda:PANEL.serial>serial and p.poll() is None,timeout);return p
 router('ip','link','set','lo','mtu','131072');router('sysctl','-w','net.ipv4.conf.lo.accept_local=1','net.ipv4.conf.lo.rp_filter=2')
 if helper is None:
  def agent(fault='',timeout=20):
   serial=PANEL.serial;args=[BINARY,'--config',str(CONFIG)]
   if fault:args+=['--test-fault',fault]
   p=spawn(ns('router','sh','-c',BPF_PREP,'sh','taskset','-c','1',*args),'agent.log');wait(lambda:PANEL.serial>serial and p.poll() is None,timeout);return p
 # Let the initial address-watcher synchronization settle before probing an
 # otherwise immutable topology. Transient transaction drops are intentional.
 if helper:
  status=pathlib.Path('/proc/'+str(a.pid)+'/status').read_text();check('P2 typed policy travels through dedicated UID with zero capabilities','Uid:\t12345' in status and 'CapEff:\t0000000000000000' in status)

 spawn(ns('router','python3','/tests/echo_server.py'),'local-echo.log');spawn(ns('router','taskset','-c','1','iperf3','-s','-B','10.205.2.1','-p','19010'),'iperf-server.log');time.sleep(.2)
 ROWS=[];TOTAL=0
 def cpu():
  rows=pathlib.Path('/proc/stat').read_text().splitlines();v=next(l.split()[1:] for l in rows if l.startswith('cpu1 '));n=list(map(int,v));return {'busy':sum(n[:8])-n[3]-n[4],'total':sum(n[:8])}
 def ticks(p):
  v=pathlib.Path('/proc/'+str(p.pid)+'/stat').read_text().rsplit(')',1)[1].split();return int(v[11])+int(v[12])
 latency_code="""import socket,time,json,statistics
out={}
for proto,kind in [('tcp',socket.SOCK_STREAM),('udp',socket.SOCK_DGRAM)]:
 s=socket.socket(socket.AF_INET,kind);s.settimeout(3)
 if proto=='tcp':s.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
 s.connect(('10.205.1.1',18501));values=[]
 for i in range(2000):
  start=time.monotonic_ns();s.sendall(b'l'*123);assert s.recv(4096)==b'l'*123;values.append((time.monotonic_ns()-start)/1000)
 s.close();v=sorted(values);out[proto]={'samples':len(v),'p50_us':statistics.median(v),'p95_us':v[int(len(v)*.95)],'p99_us':v[int(len(v)*.99)]}
print(json.dumps(out))
"""
 for round_id,order in enumerate([['baseline_v5','candidate_nocap','candidate_200m'],['candidate_200m','candidate_nocap','baseline_v5']]):
  for phase in order:
   BINARY='/build/flux-agent-v5' if phase=='baseline_v5' else '/build/flux-agent-v51'
   config={'addr':'http://10.205.4.1:8000','secret':SECRET,'statePath':f'/tmp/profile-{round_id}-{phase}.json','apply':True,'allowInsecure':True,'intervalSeconds':1};CONFIG.write_text(json.dumps(config));a=agent();time.sleep(1.5)
   for ident,port,targetport in [('100_1_0',18500,19010),('101_1_0',18501,19000)]:
    rule=v4spec(ident,port,'10.205.2.1',targetport,{'localOutput':True,'localTargets':True})
    if phase=='candidate_200m':rule['bandwidth']={'user':{'id':'u1','upBitsPerSecond':200000000,'downBitsPerSecond':200000000}}
    apply(rule)
   time.sleep(2)
   actual=hashlib.sha256(pathlib.Path('/proc/'+str(a.pid)+'/exe').read_bytes()).hexdigest();assert actual==hashlib.sha256(pathlib.Path(BINARY).read_bytes()).hexdigest()
   before=cpu();agent_before=ticks(a);start=time.monotonic();log=OUT/f'iperf-{round_id}-{phase}.json';f=open(log,'w')
   p=subprocess.Popen(ns('router','taskset','-c','1','iperf3','-c','10.205.1.1','-p','18500','-b','150M','-t','20','-J'),stdout=f,stderr=subprocess.STDOUT);PROCS.append(p);time.sleep(1)
   latency=json.loads(run(ns('router','taskset','-c','1','python3','-c',latency_code),30));assert p.wait(timeout=30)==0;f.close();seconds=time.monotonic()-start;after=cpu();agent_after=ticks(a);result=json.loads(log.read_text());received=result['end']['sum_received'];rate=received['bits_per_second']/1e6;TOTAL+=received['bytes'];assert TOTAL<4*1024**3
   check(f'{phase} round {round_id} receives fixed 150Mbps inside local namespace',140<rate<160)
   row={'phase':phase,'round':round_id,'binarySHA256':actual,'receiverMbps':rate,'receiverBytes':received['bytes'],'seconds':seconds,'cpu1BusySeconds':(after['busy']-before['busy'])/os.sysconf('SC_CLK_TCK'),'agentCPUSeconds':(agent_after-agent_before)/os.sysconf('SC_CLK_TCK'),'latency':latency};ROWS.append(row);print('PROFILE',json.dumps(row),flush=True)
   stop(a);run(ns('router',BINARY,'--config',str(CONFIG),'--maintenance','uninstall','--backup-dir',str(OUT/f'backup-{round_id}-{phase}')),40)
 (OUT/'profile.json').write_text(json.dumps({'success':True,'rows':ROWS,'applicationBytes':TOTAL,'allTargetsPrivate':True,'externalForwardTestTargets':[],'cpuAffinity':1,'offeredMbps':150,'capMbps':200,'note':'CPU1 includes endpoints and softirq; queue cost is intentional and separately measured from uncapped baseline.'},indent=2));DONE=True

except Exception:
 traceback.print_exc()
 raise
finally:
 for p in reversed(PROCS):stop(p)
 (OUT/'result.json').write_text(json.dumps({'success':DONE,'checks':CHECKS}))
