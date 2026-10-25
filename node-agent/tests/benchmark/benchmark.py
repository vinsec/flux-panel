"""Bounded, no-egress, AB/BA forwarding performance experiment.

Only run in the disposable --network none container. No host namespace access.
Process/cgroup CPU is reported alongside test-core CPU including softirq; the
latter includes unrelated host work and is explicitly not a perfect attribution.
"""
import os,json,time,subprocess,pathlib,hashlib,base64,struct,http.server,threading,statistics,random,signal,traceback

OUT=pathlib.Path('/evidence');OUT.mkdir(exist_ok=True);HZ=os.sysconf('SC_CLK_TCK');CPU=1
(OUT/'failed.json').unlink(missing_ok=True)
PROCESSES=[];ROWS=[];LATENCY=[];PHASES=[];COLLECTION=[];TOTAL_BYTES=int(os.getenv('FLUX_BENCH_PRIOR_BYTES','0'));BYTE_LIMIT=int(os.getenv('FLUX_BENCH_BYTE_LIMIT',str(3*1024**3)));START=time.monotonic()
os.sched_setaffinity(0,{0})
def run(args,timeout=15):
 p=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
 if p.returncode:raise RuntimeError(str(args)+': '+p.stderr[-1800:]+p.stdout[-1000:])
 return p.stdout.strip()
def ns(name,*args):return ['ip','netns','exec',name,*args]
def router(*args):return run(ns('router',*args))
def spawn(args,name,cwd=None,env=None):
 f=open(OUT/(name+'.log'),'w');p=subprocess.Popen(args,stdout=f,stderr=subprocess.STDOUT,cwd=cwd,env=env,text=True);PROCESSES.append(p);return p
def stop(p):
 if p and p.poll() is None:
  p.terminate()
  try:p.wait(timeout=3)
  except subprocess.TimeoutExpired:p.kill();p.wait()
def snapshot():
 c={k:int(v) for k,v in (line.split() for line in pathlib.Path('/sys/fs/cgroup/cpu.stat').read_text().splitlines())}
 lines=pathlib.Path('/proc/stat').read_text().splitlines();raw=[int(x) for x in next(x for x in lines if x.startswith('cpu1 ')).split()[1:9]]
 return {'time':time.monotonic(),'cgroup':c,'cpu':raw}
def proc(p):
 if p is None:return {'seconds':0,'rss':0}
 raw=pathlib.Path(f'/proc/{p.pid}/stat').read_text().rsplit(')',1)[1].split()
 return {'seconds':(int(raw[11])+int(raw[12]))/HZ,'rss':int(raw[21])*os.sysconf('SC_PAGE_SIZE')}
def delta(a,b):
 d=[y-x for x,y in zip(a['cpu'],b['cpu'])];dt=b['time']-a['time'];busy=sum(d[i] for i in [0,1,2,5,6])/HZ
 return {'wall_seconds':dt,'cgroup_cpu_seconds':(b['cgroup']['usage_usec']-a['cgroup']['usage_usec'])/1e6,'test_core_cpu_seconds':busy,'softirq_seconds':d[6]/HZ,'steal_seconds':d[7]/HZ,'throttled_seconds':(b['cgroup'].get('throttled_usec',0)-a['cgroup'].get('throttled_usec',0))/1e6}

class Sink(http.server.BaseHTTPRequestHandler):
 protocol_version='HTTP/1.1'
 def log_message(self,*args):pass
 def do_POST(self):
  n=int(self.headers.get('Content-Length','0'));assert n<16*1024*1024;raw=self.rfile.read(n);body=b'ok'
  if os.getenv('FLUX_BENCH_FOUNDATION_CREDIT_ONLY')=='1':
   v=json.loads(raw);grants=[]
   if 'usage' in v:
    for ident in v.get('requests',[]):
     key=v['epoch']+ident
     if key not in self.server.leases:self.server.leases[key]={'id':hashlib.md5(key.encode()).hexdigest(),'serviceId':ident,'epoch':v['epoch'],'bootId':v['bootId'],'generation':1,'totalGranted':2147483648,'windowBytes':2147483648,'requestSequence':v['sequence'],'validForMillis':60000}
     grants.append(self.server.leases[key])
    body=json.dumps({'epoch':v['epoch'],'sequence':v['sequence'],'usage':v['usage'],'counters':v.get('counters',[]),'closedLeases':[x['id'] for x in v.get('leases',[]) if x['closed']],'leaseWatermarks':v.get('leases',[]),'grants':grants}).encode()
  self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
 def do_GET(self):
  if self.headers.get('Upgrade','').lower()!='websocket':self.send_error(404);return
  key=self.headers.get('Sec-WebSocket-Key','');accept=base64.b64encode(hashlib.sha1((key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
  self.send_response(101);self.send_header('Upgrade','websocket');self.send_header('Connection','Upgrade');self.send_header('Sec-WebSocket-Accept',accept);self.end_headers();self.close_connection=True
  try:
   while True:
    h=self.rfile.read(2)
    if len(h)!=2:return
    opcode=h[0]&15;length=h[1]&127
    if length==126:length=struct.unpack('!H',self.rfile.read(2))[0]
    if length==127:length=struct.unpack('!Q',self.rfile.read(8))[0]
    if length>1024*1024:return
    mask=self.rfile.read(4) if h[1]&128 else b'';body=self.rfile.read(length)
    if mask:body=bytes(x^mask[i%4] for i,x in enumerate(body))
    if opcode==8:return
    reply=body if opcode==9 else b'{"type":"call"}';self.wfile.write(bytes([0x8a if opcode==9 else 0x81,len(reply)])+reply);self.wfile.flush()
  except (OSError,ValueError,struct.error):return

def topology():
 for n in ['client','router','target']:run(['ip','netns','add',n]);run(['ip','-n',n,'link','set','lo','up'])
 for a,b,an,bn,aa,ba in [('c0','r0','client','router','10.204.1.2/24','10.204.1.1/24'),('t0','r1','target','router','10.204.2.2/24','10.204.2.1/24')]:
  run(['ip','link','add',a,'type','veth','peer','name',b]);run(['ip','link','set',a,'netns',an]);run(['ip','link','set',b,'netns',bn])
  for n,i,addr in [(an,a,aa),(bn,b,ba)]:run(['ip','-n',n,'addr','add',addr,'dev',i]);run(['ip','-n',n,'link','set',i,'mtu','1500']);run(['ip','-n',n,'link','set',i,'up'])
 run(['ip','link','add','control','type','veth','peer','name','r2']);run(['ip','link','set','r2','netns','router']);run(['ip','addr','add','10.204.3.1/24','dev','control']);run(['ip','link','set','control','up']);run(['ip','-n','router','addr','add','10.204.3.2/24','dev','r2']);run(['ip','-n','router','link','set','r2','up'])
 run(['ip','-n','client','route','add','default','via','10.204.1.1']);run(['ip','-n','target','route','add','default','via','10.204.2.1'])
 router('sh','-c','mount -o remount,rw /proc/sys && sysctl -w net.ipv4.ip_forward=1')
 assert not any('default' in l for l in router('ip','route').splitlines())
 assert not any('default' in l for l in run(['ip','route']).splitlines())
 echo=spawn(ns('target','taskset','-c',str(CPU),'/build/bench-peer','-role','server','-port','9001'),'echo')
 iperf=spawn(ns('target','taskset','-c',str(CPU),'iperf3','-s','-p','5201'),'iperf-server')
 time.sleep(.4);assert echo.poll() is None and iperf.poll() is None

def clean_rules():
 for table in ['mangle','nat','filter']:router('iptables','-t',table,'-F');router('iptables','-t',table,'-X')
 if os.getenv('FLUX_BENCH_V2')=='1':
  for name in router('ipset','list','-name').splitlines():
   assert name.startswith(('FPV2_','FPV3_')),name
   router('ipset','destroy',name)
 router('iptables','-P','FORWARD','DROP');router('sh','-c','conntrack -F >/dev/null 2>&1 || true')
def specs(count):
 out={}
 for i in range(count-2):
  ident=f'{i+1:06d}_1_0';out[ident]={'id':ident,'revision':1,'listenIP':'10.204.1.1','listenPort':30000+i,'targetIP':'10.204.2.2','targetPort':5201,'enabled':True}
 for ident,port,target in ([('000000_1_0',18000,9002 if os.getenv('FLUX_BENCH_STRICT')=='1' else 5201),('000000_1_1',18001,9001)] if os.getenv('FLUX_BENCH_HOT_FIRST')=='1' else [('999998_1_0',18000,9002 if os.getenv('FLUX_BENCH_STRICT')=='1' else 5201),('999999_1_0',18001,9001)]):out[ident]={'id':ident,'revision':1,'listenIP':'10.204.1.1','listenPort':port,'targetIP':'10.204.2.2','targetPort':target,'enabled':True}
 return out
def setup(engine,count,round_id):
 clean_rules();path=pathlib.Path(f'/tmp/{engine}-{count}-{round_id}');path.mkdir();p=None
 data=specs(count)
 if os.getenv('FLUX_BENCH_FOUNDATION_CREDIT_ONLY')=='1' and engine=='iptables_v2':
  for value in data.values():
   if value['listenPort'] in [18000,18001]:value['leaseRequired']=True
 if engine=='direct':
  router('iptables','-A','FORWARD','-i','r0','-o','r1','-j','ACCEPT');router('iptables','-A','FORWARD','-i','r1','-o','r0','-j','ACCEPT')
 elif engine=='gost':
  services=[]
  for s in data.values():
   for proto in ['tcp','udp']:services.append({'name':s['id']+'_'+proto,'addr':f"{s['listenIP']}:{s['listenPort']}",'handler':{'type':proto},'listener':{'type':proto,'metadata':{'keepAlive':True}} if proto=='udp' else {'type':proto},'forwarder':{'nodes':[{'name':'target','addr':f"{s['targetIP']}:{s['targetPort']}"}]}})
  (path/'config.json').write_text(json.dumps({'addr':'ws://10.204.3.1:8000','secret':'isolated-benchmark-only'}));(path/'gost.json').write_text(json.dumps({'services':services}))
  env=os.environ.copy();env.update(GOMAXPROCS='1',GOST_LOGGER_LEVEL='error')
  p=spawn(ns('router','taskset','-c',str(CPU),'/build/gost'),f'gost-{count}-{round_id}',str(path),env)
 else:
  state={'epoch':hashlib.md5(str(path).encode()).hexdigest(),'sequence':0,'rules':data,'totals':{},'last':{}}
  (path/'state.json').write_text(json.dumps(state));(path/'config.json').write_text(json.dumps({'addr':'ws://10.204.3.1:8000','secret':'isolated-benchmark-only','statePath':str(path/'state.json'),'apply':True,'allowInsecure':True,'intervalSeconds':1 if os.getenv('FLUX_BENCH_FOUNDATION_CREDIT_ONLY')=='1' else 5}))
  binary='/build/flux-agent-v2' if engine=='iptables_v2' else '/build/flux-agent'
  env=os.environ.copy();env['GOMAXPROCS']='1';p=spawn(ns('router','taskset','-c',str(CPU),binary,'--config',str(path/'config.json')),f'{engine}-{count}-{round_id}',env=env)
 deadline=time.monotonic()+20
 while True:
  if p and p.poll() is not None:raise RuntimeError(engine+' failed to start: '+(OUT/f'{engine}-{count}-{round_id}.log').read_text()[-1000:])
  try:
   result=json.loads(run(ns('client','taskset','-c',str(CPU),'/build/bench-peer','-host','10.204.2.2' if engine=='direct' else '10.204.1.1','-port','9001' if engine=='direct' else '18001','-samples','1','-pace-us','0'),timeout=3))
   if result['samples']==1:break
  except (RuntimeError,subprocess.TimeoutExpired):pass
  if time.monotonic()>deadline:raise RuntimeError(engine+' readiness deadline')
  time.sleep(.2)
 time.sleep(.4)
 return p

def measure(engine,count,round_id,profile,p):
 global TOTAL_BYTES
 if time.monotonic()-START>(900 if os.getenv('FLUX_BENCH_V2')=='1' else 360):raise RuntimeError('global benchmark deadline')
 a=snapshot();time.sleep(.35);b=snapshot();idle=delta(a,b)
 ip='10.204.2.2' if engine=='direct' else '10.204.1.1';port='5201' if engine=='direct' else '18000'
 if profile.startswith('strict'):
  port='9002' if engine=='direct' else '18000';size=int(os.getenv('FLUX_BENCH_STRICT_BYTES',str(64*1024**2)));args=['/build/bench-peer','-host',ip,'-port',port,'-bulk-bytes',str(size)]
  if profile=='strict_down':args+=['-reverse']
  if profile=='strict_parallel':args+=['-parallel','4']
  before=proc(p);a=snapshot();text=run(ns('client','taskset','-c',str(CPU),*args),timeout=20);b=snapshot();after=proc(p);v=json.loads(text)
  assert v['receiver_acknowledged'] and v['bytes']==size
  TOTAL_BYTES+=v['bytes'];assert TOTAL_BYTES<=BYTE_LIMIT
  d=delta(a,b);row={'engine':engine,'forwards':count,'round':round_id,'profile':profile,'sent_bytes':v['bytes'],'received_bytes':v['bytes'],'mbps':v['bits_per_second']/1e6,'transfer_seconds':v['seconds'],'receiver_acknowledged':True,'proxy_cpu_seconds':after['seconds']-before['seconds'],'idle':idle,**d}
  row['cgroup_cpu_seconds_per_gib']=row['cgroup_cpu_seconds']/(v['bytes']/1024**3);row['core_cpu_seconds_per_gib']=row['test_core_cpu_seconds']/(v['bytes']/1024**3)
  row['core_idle_adjusted_seconds_per_gib']=max(0,row['test_core_cpu_seconds']-idle['test_core_cpu_seconds']/idle['wall_seconds']*d['wall_seconds'])/(v['bytes']/1024**3)
  ROWS.append(row);(OUT/'throughput.json').write_text(json.dumps(ROWS,indent=2));print('STRICT',count,engine,round_id,profile,round(row['mbps'],2),'Mbps',round(row['cgroup_cpu_seconds_per_gib'],3),'CPU-s/GiB',flush=True);return
 args=['iperf3','-c',ip,'-p',port,'-J']
 if profile=='tcp_paced':args+=['-t','5' if os.getenv('FLUX_BENCH_PACED_ONLY')=='1' else '3','-b','150M']
 elif profile.startswith('tcp'):
  args+=['-n',str(64*1024**2)]
  if profile=='tcp_down':args+=['-R']
  if profile=='tcp_parallel':args+=['-P','4']
 elif profile=='udp_1200':args+=['-u','-t','2','-b','50M','-l','1200']
 elif profile=='udp_64':args+=['-u','-t','2','-b','5M','-l','64']
 before=proc(p);a=snapshot()
 text=run(ns('client','taskset','-c',str(CPU),*args),timeout=15)
 b=snapshot();after=proc(p);v=json.loads(text);assert 'error' not in v,v
 d=delta(a,b);end=v['end'];sent=end.get('sum_sent',end.get('sum',{}));received=end.get('sum_received',end.get('sum',{}))
 byte_count=int(sent.get('bytes',0));TOTAL_BYTES+=byte_count
 if TOTAL_BYTES>BYTE_LIMIT:raise RuntimeError('aggregate transfer budget exceeded')
 goodput=float(received.get('bits_per_second',0));delivered=int(received.get('bytes',0))
 assert byte_count>0 and goodput>0
 row={'engine':engine,'forwards':count,'round':round_id,'profile':profile,'sent_bytes':byte_count,'received_bytes':delivered,'mbps':goodput/1e6,'proxy_cpu_seconds':after['seconds']-before['seconds'],'proxy_rss_bytes':after['rss'],'idle':idle,**d}
 row['cgroup_cpu_seconds_per_gib']=row['cgroup_cpu_seconds']/(delivered/1024**3)
 row['core_cpu_seconds_per_gib']=row['test_core_cpu_seconds']/(delivered/1024**3)
 row['core_idle_adjusted_seconds_per_gib']=max(0,row['test_core_cpu_seconds']-idle['test_core_cpu_seconds']/idle['wall_seconds']*d['wall_seconds'])/(delivered/1024**3)
 for k in ['lost_packets','packets','lost_percent','jitter_ms']:row[k]=received.get(k,end.get('sum',{}).get(k))
 ROWS.append(row);(OUT/'throughput.json').write_text(json.dumps(ROWS,indent=2));(OUT/f'iperf-{len(ROWS):02d}.json').write_text(text)
 print('RUN',count,engine,round_id,profile,round(row['mbps'],2),'Mbps',round(row['cgroup_cpu_seconds_per_gib'],3),'cgroup CPU-s/GiB',flush=True)

def latency(engine,count,round_id,p,extended=True):
 modes=[('tcp',False,500),('tcp',True,100),('udp',False,500)] if extended else [('tcp',False,300)]
 for protocol,fresh,n in modes:
  time.sleep(.25);args=['/build/bench-peer','-host','10.204.2.2' if engine=='direct' else '10.204.1.1','-port','9001' if engine=='direct' else '18001','-protocol',protocol,'-samples',str(n),'-pace-us','1000']
  if fresh:args+=['-fresh']
  a=snapshot();v=json.loads(run(ns('client','taskset','-c',str(CPU),*args),timeout=10));b=snapshot()
  v.update(engine=engine,forwards=count,round=round_id,profile='tcp_first_response' if fresh else protocol+'_persistent',cpu=delta(a,b));LATENCY.append(v)
  assert v['samples']==n and v['lost']==0,v
  print('LATENCY',count,engine,round_id,v['profile'],'p50/p95/p99(us)',v['p50_us'],v['p95_us'],v['p99_us'],flush=True)
 (OUT/'latency.json').write_text(json.dumps(LATENCY,indent=2))

def collection(engine,count):
 # Raw kernel exports only, 10 repetitions. This excludes Go parsing, fsync,
 # HTTP delivery and panel SQL; it does not claim to measure the full sampler.
 commands=[['ipset','save','FPV2_UP'],['ipset','save','FPV2_DOWN']] if engine=='iptables_v2' or os.getenv('FLUX_BENCH_FOUNDATION')=='1' else [['iptables-save','-c','-t','filter']]
 values=[];sizes=[]
 for _ in range(10):
  a=snapshot();data=''.join(router(*args) for args in commands);b=snapshot();values.append(delta(a,b));sizes.append(len(data))
 counts={t:sum(l.startswith('-A FP_') for l in router('iptables-save','-t',t).splitlines()) for t in ['mangle','filter','nat']}
 COLLECTION.append({'engine':engine,'forwards':count,'samples':values,'export_bytes':sizes,'owned_rule_counts':counts})
 (OUT/'collection.json').write_text(json.dumps(COLLECTION,indent=2))

def main():
 topology();server=http.server.ThreadingHTTPServer(('10.204.3.1',8000),Sink);server.daemon_threads=True;server.leases={};threading.Thread(target=server.serve_forever,daemon=True).start()
 metadata={'kernel':run(['uname','-a']),'iperf':run(['iperf3','--version']).splitlines()[0],'cpuset':run(['taskset','-pc',str(os.getpid())]),'cpu_max':pathlib.Path('/sys/fs/cgroup/cpu.max').read_text().strip(),'baseline_source_commit':'7ed19550e3e800787f8bbb2c4542758be246582d' if os.getenv('FLUX_BENCH_FOUNDATION')=='1' else '4ea5d7bba4033dcab3b31040a7b16bbeefa65d16','binary_sha256':{n:hashlib.sha256(pathlib.Path('/build/'+n).read_bytes()).hexdigest() for n in (['flux-agent','flux-agent-v2','gost','bench-peer'] if os.getenv('FLUX_BENCH_V2')=='1' else ['flux-agent','gost','bench-peer'])},'topology':'client -> router -> target; veth MTU 1500; no external/default route','byte_limit':BYTE_LIMIT,'case_timeout_seconds':15,'offloads':router('ethtool','-k','r0')}
 (OUT/'metadata.json').write_text(json.dumps(metadata,indent=2))
 metadata['engine_aliases']={'iptables':'iptables_v2_baseline','iptables_v2':'iptables_v3_foundation','gost':'gost'} if os.getenv('FLUX_BENCH_FOUNDATION')=='1' else {}
 metadata['kernel_credit_enabled']=os.getenv('FLUX_BENCH_FOUNDATION_CREDIT_ONLY')=='1'
 if os.getenv('FLUX_BENCH_FOUNDATION_CREDIT_ONLY')=='1':
  for count in [2,1000]:
   for round_id in [41,42,43]:
    p=setup('iptables_v2',count,round_id)
    try:measure('iptables_v2',count,round_id,'strict_up',p);latency('iptables_v2',count,round_id,p,False)
    finally:stop(p)
  os.environ['FLUX_BENCH_STRICT']='0';os.environ['FLUX_BENCH_PACED_ONLY']='1'
  for count in [2,1000]:
   for round_id in [51,52,53]:
    p=setup('iptables_v2',count,round_id)
    try:measure('iptables_v2',count,round_id,'tcp_paced',p)
    finally:stop(p)
 elif os.getenv('FLUX_BENCH_PACED_ONLY')=='1':
  for count in [2,1000]:
   for round_id,order in enumerate([['gost','iptables','iptables_v2'],['iptables_v2','gost','iptables'],['iptables','iptables_v2','gost']],21):
    for engine in order:
     p=setup(engine,count,round_id)
     try:measure(engine,count,round_id,'tcp_paced',p)
     finally:stop(p)
 elif os.getenv('FLUX_BENCH_V2')=='1':
  for count in [2,100,1000]:
   for round_id,order in enumerate([['gost','iptables','iptables_v2'],['iptables_v2','gost','iptables'],['iptables','iptables_v2','gost']],1):
    for engine in order:
     p=setup(engine,count,round_id)
     try:
      profiles=['strict_up']
      if count==2:profiles+=['strict_down','strict_parallel']
      for profile in profiles:measure(engine,count,round_id,profile,p)
      latency(engine,count,round_id,p,count==2)
      if round_id==1 and engine!='gost':collection(engine,count)
     finally:stop(p)
  # UDP iperf uses its own TCP control session. The strict bulk endpoint
  # deliberately implements another protocol, so configure the same two
  # forwards for iperf in separate phases rather than mixing wire protocols.
  os.environ['FLUX_BENCH_STRICT']='0'
  for count in [2,1000]:
   for round_id,order in enumerate([['gost','iptables','iptables_v2'],['iptables_v2','gost','iptables'],['iptables','iptables_v2','gost']],11):
    for engine in order:
     p=setup(engine,count,round_id)
     try:
      for profile in ['udp_1200','udp_64']:measure(engine,count,round_id,profile,p)
     finally:stop(p)
 elif os.getenv('FLUX_BENCH_SCALE_ONLY')=='1':
  for count in [100,1000]:
   for round_id in [2,3]:
    for engine in (['gost','iptables'] if round_id==2 else ['iptables','gost']):
     p=setup(engine,count,round_id)
     try:measure(engine,count,round_id,'strict_up',p)
     finally:stop(p)
 elif os.getenv('FLUX_BENCH_FIRST_ONLY')=='1':
  for engine in ['gost','iptables']:
   p=setup(engine,1000,6)
   try:measure(engine,1000,6,'strict_up',p)
   finally:stop(p)
 elif os.getenv('FLUX_BENCH_STRICT')=='1':
  for round_id,order in enumerate([['direct','gost','iptables'],['iptables','direct','gost'],['gost','iptables','direct']],1):
   for engine in order:
    p=setup(engine,2,round_id)
    try:
     for profile in (['strict_up'] if engine=='direct' else ['strict_up','strict_down','strict_parallel']):measure(engine,2,round_id,profile,p)
    finally:stop(p)
  for count in [100,1000]:
   for engine in ['gost','iptables']:
    p=setup(engine,count,1)
    try:measure(engine,count,1,'strict_up',p)
    finally:stop(p)
 elif os.getenv('FLUX_BENCH_EXTRA')=='1':
  metadata['hot_position']='first';metadata['prior_payload_bytes']=TOTAL_BYTES
  for engine in ['gost','iptables']:
   p=setup(engine,1000,4)
   try:measure(engine,1000,4,'tcp_up',p);latency(engine,1000,4,p,False)
   finally:stop(p)
  for round_id,order in [(4,['gost','iptables']),(5,['iptables','gost'])]:
   for engine in order:
    p=setup(engine,2,round_id)
    try:measure(engine,2,round_id,'tcp_paced',p)
    finally:stop(p)
 else:
  # Confirm the installed iperf's -n/-P semantics before selecting the main budget.
  p=setup('direct',2,0);raw=json.loads(run(ns('client','iperf3','-c','10.204.2.2','-p','5201','-P','4','-n','1048576','-J'),timeout=10));amount=raw['end']['sum_sent']['bytes'];metadata['parallel_n_smoke_bytes']=amount
  if amount>2*1048576:raise RuntimeError('iperf -n is per-stream; adjust benchmark budget first')
  print('SMOKE parallel -n 1MiB sent',amount,flush=True)
  for round_id,order in enumerate([['direct','gost','iptables'],['iptables','direct','gost'],['gost','iptables','direct']],1):
   for engine in order:
    p=setup(engine,2,round_id)
    try:
     for profile in ['tcp_up','tcp_down','tcp_parallel','udp_1200','udp_64']:measure(engine,2,round_id,profile,p)
     latency(engine,2,round_id,p)
    finally:stop(p)
  for count in [100,1000]:
   for round_id in [1,2,3]:
    for engine in (['gost','iptables'] if round_id%2 else ['iptables','gost']):
     p=setup(engine,count,round_id)
     try:measure(engine,count,round_id,'tcp_up',p);latency(engine,count,round_id,p,False)
     finally:stop(p)
 metadata['elapsed_seconds']=time.monotonic()-START;metadata['sent_payload_bytes']=TOTAL_BYTES
 (OUT/'metadata.json').write_text(json.dumps(metadata,indent=2));print('COMPLETE',len(ROWS),'throughput cases;',len(LATENCY),'latency cases;',TOTAL_BYTES,'payload bytes',flush=True)

try:main()
except Exception:
 traceback.print_exc();(OUT/'failed.json').write_text(json.dumps({'rows':len(ROWS),'bytes':TOTAL_BYTES}));raise
finally:
 for p in reversed(PROCESSES):stop(p)
