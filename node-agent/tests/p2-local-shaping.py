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
  caplines=pathlib.Path('/proc/'+str(helper.pid)+'/status').read_text().splitlines();check('long-lived helper retains only base capabilities',all(int(line.split()[1],16)&((1<<21)|(1<<39))==0 for line in caplines if line.startswith(('CapEff:','CapPrm:','CapBnd:','CapAmb:'))))

 spawn(ns('router','python3','-c',"import socketserver;socketserver.UDPServer.max_packet_size=65535;exec(open('/tests/echo_server.py').read())"),'local-target.log');time.sleep(.2)
 rows=[]
 def bulk(where,host,port,n=1048576):
  code="""import socket,time,threading,json
s=socket.create_connection((HOST,PORT),timeout=4);s.settimeout(15);n=COUNT;payload=b'b'*n;t=time.monotonic();threading.Thread(target=lambda:s.sendall(payload),daemon=True).start();got=0
while got<n:
 b=s.recv(65536);assert b and b==b'b'*len(b);got+=len(b)
s.close();print(time.monotonic()-t)
""".replace('HOST',repr(host)).replace('PORT',str(port)).replace('COUNT',str(n))
  return float(run(ns(where,'python3','-c',code),30))
 paths=[('remote4','10.205.1.1','10.205.3.2','router'),('local4-external','10.205.1.1','10.205.2.1','client'),('local4-host','10.205.1.1','10.205.2.1','router'),('loop4','127.0.0.1','127.0.0.1','router'),('remote6','fd25:1::1','fd25:3::2','router'),('local6-external','fd25:1::1','fd25:2::1','client'),('local6-host','fd25:1::1','fd25:2::1','router'),('loop6','::1','::1','router')]
 for i,(name,listen,target,where) in enumerate(paths):
  ident=f'{i+30}_1_0';port=18100+i;s=v4spec(ident,port,target,traffic={'localOutput':True,'localTargets':True});s['listen']['host']=listen;s['bandwidth']={'upBitsPerSecond':8000000,'downBitsPerSecond':8000000};apply(s);time.sleep(2)
  check(name+' TCP/UDP functional',exchange(where,listen,port));exact_udp(where,listen,port,ident,':' in listen);check(name+' queued UDP accounted exactly once')
  elapsed=bulk(where,listen,port);rows.append({'path':name,'seconds':elapsed,'payloadBytes':1048576,'rateBitsPerSecond':8000000});check(name+' smooth TCP limit sustained',.65<elapsed<5)
  if where=='router' and target in ['10.205.2.1','fd25:2::1','127.0.0.1','::1']:
   for size in [60000,65507 if ':' not in listen else 65527]:
    code=f"import socket;s=socket.socket(socket.AF_INET6 if {':' in listen!r} else socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(5);b=b'g'*{size};s.sendto(b,({listen!r},{port}));assert s.recv(65535)==b"
    run(ns(where,'python3','-c',code));check(name+f' large UDP {size} bytes')
  PANEL.rpc('SetForwardState',{'id':ident,'revision':2,'enabled':False});check(name+' pause closes both protocols',exchange(where,listen,port,True))
  PANEL.rpc('SetForwardState',{'id':ident,'revision':3,'enabled':True});check(name+' resume restores queue',exchange(where,listen,port))
  PANEL.rpc('DeleteForward',{'id':ident,'revision':4})
 # Two distinct rules share the same user cap across local and routed paths.
 for i,target in enumerate(['10.205.2.1','10.205.3.2']):
  s=v4spec(f'{60+i}_7_0',18200+i,target,traffic={'localOutput':True,'localTargets':True});s['bandwidth']={'user':{'id':'u7','upBitsPerSecond':8000000,'downBitsPerSecond':8000000}};apply(s)
 values=[];errors=[]
 def transfer(port):
  try:values.append(bulk('router','10.205.1.1',port))
  except Exception as e:errors.append(str(e))
 t=time.monotonic();jobs=[threading.Thread(target=transfer,args=(p,)) for p in [18200,18201]]
 for j in jobs:j.start()
 for j in jobs:j.join()
 elapsed=time.monotonic()-t;check('local and routed forwards share one user HTB ceiling',not errors and len(values)==2 and 1.5<elapsed<7);rows.append({'path':'shared-local-remote','seconds':elapsed,'payloadBytes':2097152,'rateBitsPerSecond':8000000})
 # A reboot keeps the durable aux manifest but loses lo's clsact. Rebuild
 # from that state instead of treating deletion of absent filters as fatal.
 stop(a)
 if helper:stop(helper)
 router('tc','qdisc','del','dev','lo','clsact')
 if helper:helper=start_helper()
 a=agent();check('cold clsact loss recovers persisted local shaping',exchange('router','10.205.1.1',18200) and .65<bulk('router','10.205.1.1',18200)<5)
 for i in range(2):PANEL.rpc('DeleteForward',{'id':f'{60+i}_7_0','revision':2})
 check('deleting last local cap removes IFB and every owned classifier','fp4shape' not in router('ip','link','show') and all(router('tc','-j','filter','show','dev',dev,'ingress')=='[]' and router('tc','-j','filter','show','dev',dev,'egress')=='[]' for dev in ['lo','r0','r1','r2']))
 # Losing a host prerequisite must close the desired capped rule, and
 # restoring it must recover without deleting its usage or changing revision.
 prepared=v4spec('65_1_0',18205,'10.205.2.1',traffic={'localOutput':True,'localTargets':True});prepared['bandwidth']={'upBitsPerSecond':8000000,'downBitsPerSecond':8000000};apply(prepared);time.sleep(2)
 router('sysctl','-w','net.ipv4.conf.lo.accept_local=0');wait(lambda:PANEL.rpc('GetForwardStatuses',{'ids':['65_1_0']})['data']['65_1_0']['status']=='failed')
 check('lost loopback prerequisite closes capped local rule',exchange('router','10.205.1.1',18205,True))
 router('sysctl','-w','net.ipv4.conf.lo.accept_local=1');wait(lambda:PANEL.rpc('GetForwardStatuses',{'ids':['65_1_0']})['data']['65_1_0']['status']=='applied')
 check('restored loopback prerequisite recovers original desired revision',exchange('router','10.205.1.1',18205))
 before_index=json.loads(router('ip','-j','link','show','dev','fp4shape'))[0]['ifindex'];router('ip','link','del','fp4shape')
 wait(lambda:json.loads(router('ip','-j','link','show','dev','fp4shape'))[0]['ifindex']!=before_index)
 wait(lambda:exchange('router','10.205.1.1',18205));check('external IFB deletion is repaired despite ignoring self link events')
 PANEL.rpc('DeleteForward',{'id':'65_1_0','revision':2})
 # Early tracking refuses foreign ingress classifiers without deleting them.
 router('tc','qdisc','add','dev','r0','clsact');router('tc','filter','add','dev','r0','ingress','protocol','all','pref','1','matchall','action','pass')
 before=router('tc','-j','filter','show','dev','r0','ingress');foreign=v4spec('66_1_0',18206,'10.205.2.1',traffic={'localOutput':True,'localTargets':True});foreign['bandwidth']={'upBitsPerSecond':8000000}
 check('foreign ingress classifier is refused intact',not apply(foreign,False)['success'] and router('tc','-j','filter','show','dev','r0','ingress')==before)
 router('tc','qdisc','del','dev','r0','clsact')
 check('unrelated firewall chain preserved','keep-unrelated' in router('iptables-save'))
 (OUT/'throughput.json').write_text(json.dumps(rows,indent=2));DONE=True

except Exception:
 traceback.print_exc()
 try:print(PANEL.rpc('GetForwardStatuses',{'ids':[f'{i+30}_1_0' for i in range(8)]}),flush=True)
 except Exception:pass
 for file,args in [('rules.txt',['iptables-save','-c']),('ct.txt',['conntrack','-L']),('link.txt',['ip','-d','link']),('tc-lo.txt',['tc','-s','filter','show','dev','lo','egress']),('tc-lo-restore.txt',['tc','-s','filter','show','dev','lo','egress','chain','201']),('classes.txt',['tc','-s','class','show','dev','fp4shape'])]:
  try:(OUT/file).write_text(router(*args))
  except Exception:pass
 raise
finally:
 for p in reversed(PROCS):stop(p)
 (OUT/'result.json').write_text(json.dumps({'success':DONE,'checks':CHECKS}))
