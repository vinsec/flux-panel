"""Real first-data filtering; private namespaces, no external entry traffic."""
from foundation_fixture import *
try:

 if os.getenv('IPTABLES_BACKEND')=='legacy':
  run(['update-alternatives','--set','iptables','/usr/sbin/iptables-legacy']);run(['update-alternatives','--set','ip6tables','/usr/sbin/ip6tables-legacy'])
 topology();server=http.server.ThreadingHTTPServer(('10.205.4.1',8000),Handler);server.daemon_threads=True;threading.Thread(target=server.serve_forever,daemon=True).start()
 write_config({'addr':'http://10.205.4.1:8000','secret':SECRET,'statePath':str(STATE),'apply':True,'allowInsecure':True,'intervalSeconds':1});
 if os.getenv('FLUX_DPI_HELPER')=='1':
  cfg=json.loads(CONFIG.read_text());directory=pathlib.Path('/tmp/dpi-helper');directory.mkdir(mode=0o750);os.chown(directory,0,12345);cfg['helperSocket']=str(directory/'kernel.sock');write_config(cfg);CONFIG.chmod(0o644)
  helper=spawn(ns('router','setpriv','--regid=12345','--clear-groups','--bounding-set=-all,+net_admin,+net_raw,+net_bind_service',str(BUILD/'flux-agent'),'--kernel-helper','--helper-user','12345','--config',str(CONFIG)),'helper.log');wait(lambda:pathlib.Path(cfg['helperSocket']).exists())
  def agent():
   serial=PANEL.serial;p=spawn(ns('router','setpriv','--reuid=12345','--regid=12345','--clear-groups','--bounding-set=-all',str(BUILD/'flux-agent'),'--config',str(CONFIG)),'agent.log');wait(lambda:PANEL.serial>serial and p.poll() is None);return p
  check('classifier helper retains only NET_ADMIN NET_RAW NET_BIND_SERVICE','CapBnd:\t0000000000003400' in pathlib.Path('/proc/'+str(helper.pid)+'/status').read_text())
 a=agent()
 s={'schemaVersion':5,'id':'1_1_0','revision':1,'enabled':True,'listen':{'host':'10.205.1.1','port':18000},'targets':[{'endpoint':{'host':'10.205.3.2','port':19000},'weight':1}],'protocolFilter':{'http':True,'tls':True,'socks':True,'unknown':'allow'}};apply(s)
 def exchange(payload,blocked=False,split=False):
  code=f'''import socket,time
s=socket.create_connection(('10.205.1.1',18000),timeout=3);s.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1);s.settimeout(1.3);b={payload!r}
if {split!r}:s.sendall(b[:2]);time.sleep(.03);s.sendall(b[2:])
else:s.sendall(b)
try:
 r=s.recv(65535);assert not {blocked!r} and r==b,(r,b)
except OSError:assert {blocked!r}
s.close()
'''
  run(ns('client','python3','-c',code))
 # Count queue entries for one serial opaque TCP flow, including handshake.
 for obj in json.loads(router('nft','-j','list','table','inet','FP_PROTOCOL'))['nftables']:
  rule=obj.get('rule',{})
  if rule.get('chain')=='forward' and any('queue' in e for e in rule.get('expr',[])):
   router('nft','replace','rule','inet','FP_PROTOCOL','forward','handle',str(rule['handle']),'ct','direction','original','meta','l4proto','tcp','counter','queue','num','41600')
 def queued():
  for o in json.loads(router('nft','-j','list','chain','inet','FP_PROTOCOL','forward'))['nftables']:
   rule=o.get('rule',{})
   if any('queue' in e for e in rule.get('expr',[])):
    return sum(e.get('counter',{}).get('packets',0) for e in rule['expr'])
 before=queued();exchange(b'cold-cache-check')
 check('SYN and first data are queued, empty ACK and cached packets stay in kernel',queued()-before==2)
 for name,payload in [('HTTP',b'GET / HTTP/1.1\r\nHost: internal.test\r\n\r\n'),('HTTP2',b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'),('TLS',b'\x16\x03\x03\x00\x04\x01\x00\x00\x00'),('SOCKS5',b'\x05\x01\x00'),('SOCKS4',b'\x04\x01\x01\xbb\x7f\x00\x00\x01\x00')]:
  exchange(payload,True);check(name+' detected and blocked')
 exchange(b'GET / '+b'x'*20000,True);check('large coalesced HTTP payload cannot bypass prefix recognition')
 exchange(b'GET / HTTP/1.1\r\n\r\n',True,True);check('segmented TCP prefix is classified before release')
 exchange(b'opaque\x00\x80\xfe-data');check('opaque traffic allowed without alteration')
 exchange(b'\x05\x02\x80\x81opaque-auth-data');check('unknown SOCKS5 authentication methods are allowed and labelled UNKNOWN')
 exchange(b'G');check('bounded incomplete prefix timeout is allowed UNKNOWN')
 code="import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(2);s.sendto(b'GET / udp',('10.205.1.1',18000));assert s.recv(100)==b'GET / udp'";run(ns('client','python3','-c',code));check('UDP preserved and marked UNKNOWN')
 status=PANEL.rpc('GetForwardStatus',{'id':'1_1_0'})['data'];(OUT/'status.json').write_text(json.dumps(status,indent=2));stats=status['protocolInspection']['statistics'];check('blocked and UNKNOWN decisions separately observable',stats['blocked']>=6 and stats['unknown']>=3)
 ct=router('conntrack','-L','-f','ipv4');check('UNKNOWN conntrack decision cached in reserved low bits',any('mark=' in l and int(l.split('mark=')[1].split()[0])&31==17 for l in ct.splitlines()))
 expected=0xf2000000|(state()['rules']['1_1_0']['token']<<8)
 marks=[int(l.split('mark=')[1].split()[0]) for l in ct.splitlines() if l.startswith('tcp ') and 'dport=18000 ' in l and 'mark=' in l]
 check('all classified TCP flows preserve the complete forwarding token',marks and all(m&0xffffff00==expected for m in marks))
 PANEL.rpc('SetForwardState',{'id':'1_1_0','revision':2,'enabled':False});check('pause remains authoritative for classified flows',probe(blocked=True))
 s['revision']=3;s['protocolFilter']={'http':False,'tls':True,'socks':True,'unknown':'allow'};apply(s);exchange(b'GET / HTTP/1.1\r\n\r\n');check('independent switch permits HTTP while TLS/SOCKS remain blocked');exchange(b'\x05\x01\x00',True)
 if os.getenv('FLUX_DPI_HELPER')!='1':
  stop(a)
  code="import socket;s=socket.socket();s.settimeout(.4)\ntry:s.connect(('10.205.1.1',18000));s.sendall(b'opaque');assert not s.recv(100)\nexcept OSError:pass"
  run(ns('client','python3','-c',code));check('absent queue listener never silently opens filtered TCP')
 else:stop(a)
 a=agent();exchange(b'\x05\x01\x00',True);check('policy survives restart and enabled state is not silently weakened')
 # Simulated provider NAT: external documentation address -> guest private NIC.
 s['revision']=4;s['listen']['host']='0.0.0.0';apply(s)
 run(ns('client','iptables','-t','nat','-A','OUTPUT','-d','203.0.113.77','-j','DNAT','--to-destination','10.205.1.1'))
 run(ns('client','python3','-c',"import socket;s=socket.create_connection(('203.0.113.77',18000),timeout=2);s.sendall(b'cloud-nat');assert s.recv(100)==b'cloud-nat';u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);u.settimeout(2);u.sendto(b'cloud-nat',('203.0.113.77',18000));assert u.recv(100)==b'cloud-nat'"))
 check('provider-NAT simulation reaches IPv4 wildcard over TCP and UDP','203.0.113.77' not in router('ip','addr') and '10.205.1.1,tcp:18000' in binding_text('FP4'))
 for n,i,address in [('client','c0','fd25:1::2/64'),('router','r0','fd25:1::1/64'),('router','r1','fd25:2::1/64'),('transit','m0','fd25:2::2/64'),('transit','m1','fd25:3::1/64'),('target','t0','fd25:3::2/64')]:run(['ip','-n',n,'-6','addr','add',address,'dev',i,'nodad'])
 for n in ['router','transit']:run(ns(n,'sysctl','-w','net.ipv6.conf.all.forwarding=1'))
 for n,route in [('client',['default','via','fd25:1::1']),('target',['default','via','fd25:3::1']),('router',['fd25:3::/64','via','fd25:2::2']),('transit',['fd25:1::/64','via','fd25:2::1'])]:run(['ip','-n',n,'-6','route','add',*route])
 router('ip6tables','-P','FORWARD','ACCEPT' if KERNEL_BACKEND=='nftables' else 'DROP')
 code="""import socket,threading,time
def serve():
 s=socket.socket(socket.AF_INET6);s.bind(('fd25:3::2',19000));s.listen()
 while True:
  c,_=s.accept()
  def echo(c):
   try:
    while b:=c.recv(65535):c.sendall(b)
   finally:c.close()
  threading.Thread(target=echo,args=(c,),daemon=True).start()
threading.Thread(target=serve,daemon=True).start();time.sleep(600)
"""
 spawn(ns('target','python3','-c',code),'target6.log')
 six=json.loads(json.dumps(s));six.update(id='3_1_0',revision=1);six['listen']['host']='fd25:1::1';six['targets'][0]['endpoint']['host']='fd25:3::2';six['protocolFilter']['http']=True;apply(six)
 for payload,blocked in [(b'GET / HTTP/1.1\r\n\r\n',True),(b'opaque-v6',False),(b'\x05\x01\x00',True)]:
  code=f"import socket;s=socket.create_connection(('fd25:1::1',18000),timeout=2);s.settimeout(.4);s.sendall({payload!r})\ntry:r=s.recv(100);assert not {blocked!r} and r=={payload!r}\nexcept OSError:assert {blocked!r}"
  run(ns('client','python3','-c',code))
 check('IPv6 shares classification and UNKNOWN allow contract')
 local=json.loads(json.dumps(s));local.update(id='4_1_0',revision=1,traffic={'localOutput':True});local['listen']['host']='10.205.1.1';local['listen']['port']=18002;local['protocolFilter']['http']=True;apply(local)
 for payload,blocked in [(b'GET / HTTP/1.1\r\n\r\n',True),(b'opaque-local-output',False)]:
  code=f"import socket;s=socket.create_connection(('10.205.1.1',18002),timeout=2);s.settimeout(.4);s.sendall({payload!r})\ntry:r=s.recv(100);assert not {blocked!r} and r=={payload!r}\nexcept OSError:assert {blocked!r}"
  run(ns('router','python3','-c',code))
 check('locally initiated OUTPUT traffic respects protocol policy')
 limited=json.loads(json.dumps(s));limited.update(id='2_2_3',revision=1,leaseRequired=True);limited['listen']['host']='10.205.1.1';limited['listen']['port']=18001;limited['protocolFilter']['http']=True;PANEL.quota=8192;apply(limited);wait(lambda:'2_2_3' in state().get('leases',{}));time.sleep(.4)
 code="""import socket
s=socket.create_connection(('10.205.1.1',18001),timeout=2);s.settimeout(.3);s.sendall(b'GET '+b'x'*3000)
try:assert not s.recv(4096)
except OSError:pass
s.close()
"""
 run(ns('client','python3','-c',code));time.sleep(1.2)
 blocked_usage=state()['totals'].get('2_2_3',{});check('blocked request body is excluded from billed bytes',sum(blocked_usage.get(k,0) for k in ['up','down'])<1024)
 code="""import socket
s=socket.create_connection(('10.205.1.1',18001),timeout=2);s.settimeout(.3);received=0
try:
 for _ in range(100):
  s.sendall(b'o'*1000);r=b''
  while len(r)<1000:
   b=s.recv(1000-len(r))
   if not b:raise OSError('closed')
   r+=b
  received+=len(r)
except OSError:pass
assert 0<received<=8192,received
"""
 run(ns('client','python3','-c',code));check('classified UNKNOWN TCP cannot bypass finite credit or billing')
 code="""import socket
u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);u.settimeout(.01)
for _ in range(100):
 u.sendto(b'q'*1000,('10.205.1.1',18001))
 try:u.recv(2048)
 except OSError:pass
"""
 run(ns('client','python3','-c',code));time.sleep(1.2);check('finite quota still closes UNKNOWN traffic with DPI enabled',probe(18001,True));PANEL.quota=0
 before=sum('counter' in o for o in json.loads(router('nft','-j','list','table','inet','FP_PROTOCOL'))['nftables'])
 PANEL.rpc('SetForwardState',{'id':'3_1_0','revision':2,'enabled':False})
 after=sum('counter' in o for o in json.loads(router('nft','-j','list','table','inet','FP_PROTOCOL'))['nftables'])
 check('pausing one rule retires its diagnostic object without affecting peers',after==before-1 and probe())
 stop(a)
 if os.getenv('FLUX_DPI_HELPER')=='1':stop(helper)
 run(ns('router',str(BUILD/'flux-agent'),'--config',str(CONFIG),'--maintenance','uninstall','--backup-dir',str(OUT/'backup')));check('owned classifier table removed on uninstall','FP_PROTOCOL' not in router('nft','list','tables'));check('maintenance discovers and backs up classifier before initialization',(OUT/'backup/protocol-filter.rules').exists())
 DONE=True
except Exception:
 traceback.print_exc()
 for name,args in [('nft.json',['nft','-j','list','ruleset']),('sets.txt',['ipset','save']),('ct.txt',['conntrack','-L']),('rules.txt',['iptables-save','-c'])]:
  try:(OUT/name).write_text(router(*args))
  except Exception:pass
 try:(OUT/'failure-status.json').write_text(json.dumps(PANEL.rpc('GetForwardStatus',{'id':'1_1_0'})['data'],indent=2))
 except Exception:pass
 if (OUT/'agent.log').exists():print((OUT/'agent.log').read_text()[-10000:])
 raise
finally:
 for p in reversed(PROCS):stop(p)
 (OUT/'protocol-result.json').write_text(json.dumps({'success':DONE,'count':len(CHECKS),'passed':CHECKS,'externalForwardTestTargets':[]},indent=2))
