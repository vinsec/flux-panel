"""Independent kernel/control fault verifier. Disposable --network none only.

No engine imports: ordinary sockets, raw ICMP, real netfilter and the actual
Agent executable. All addresses/routes below are private veths.
"""
import base64,hashlib,http.server,json,os,pathlib,queue,signal,socket,struct,subprocess,threading,time,traceback,urllib.parse
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
OUT=pathlib.Path('/evidence');OUT.mkdir(exist_ok=True);BUILD=pathlib.Path('/build');SECRET='isolated-foundation-only';KEY=hashlib.sha256(SECRET.encode()).digest();CHECKS=[];PROCS=[];DONE=False
STATE=pathlib.Path('/tmp/foundation-state.json');CONFIG=pathlib.Path('/tmp/foundation-config.json')
def check(name,condition=True):
 assert condition,name
 CHECKS.append(name);print('PASS',name,flush=True)
def run(args,timeout=30):
 p=subprocess.run(args,text=True,capture_output=True,timeout=timeout)
 if p.returncode:raise RuntimeError(str(args)+': '+p.stderr[-2500:]+p.stdout[-1000:])
 return p.stdout.strip()
def ns(n,*args):return ['ip','netns','exec',n,*args]
def router(*args):return run(ns('router',*args))
def spawn(args,name):
 f=open(OUT/name,'a');p=subprocess.Popen(args,stdout=f,stderr=subprocess.STDOUT);PROCS.append(p);return p
def stop(p):
 if p.poll() is None:p.terminate()
 try:p.wait(timeout=5)
 except subprocess.TimeoutExpired:p.kill();p.wait()
def wait(fn,timeout=20):
 end=time.monotonic()+timeout;last=None
 while time.monotonic()<end:
  try:
   value=fn()
   if value:return value
  except Exception as e:last=e
  time.sleep(.05)
 raise AssertionError('wait expired: '+str(last))
def encode(data):
 nonce=os.urandom(12);return json.dumps({'encrypted':True,'data':base64.b64encode(nonce+AESGCM(KEY).encrypt(nonce,json.dumps(data).encode(),None)).decode(),'timestamp':int(time.time())}).encode()
def decode(raw):
 obj=json.loads(raw)
 if obj.get('encrypted'):
  b=base64.b64decode(obj['data']);return json.loads(AESGCM(KEY).decrypt(b[:12],b[12:],None))
 return obj
class Panel:
 def __init__(self):self.cv=threading.Condition();self.sendlock=threading.Lock();self.handler=None;self.serial=0;self.responses={};self.hello=None;self.quota=0;self.grant=None;self.generation=1;self.reports=[]
 def rpc(self,method,data=None,timeout=20,success=True):
  request=str(time.monotonic_ns());raw=encode({'type':method,'data':data or {},'requestId':request})
  with self.sendlock:
   h=self.handler;assert h
   head=bytes([0x81,126])+struct.pack('!H',len(raw)) if len(raw)<65536 else bytes([0x81,127])+struct.pack('!Q',len(raw))
   if len(raw)<126:head=bytes([0x81,len(raw)])
   h.wfile.write(head+raw);h.wfile.flush()
  response=wait(lambda:self.responses.pop(request,None),timeout)
  if success:assert response['success'],response
  return response
 def report(self,r):
  self.reports.append(r);ack={'epoch':r['epoch'],'sequence':r['sequence'],'usage':r['usage'],'counters':r.get('counters',[]),'closedLeases':[l['id'] for l in r.get('leases',[]) if l['closed']],'leaseWatermarks':r.get('leases',[]),'grants':[]}
  if self.quota and r.get('requests'):
   if self.grant is None:self.grant={'id':'ab'*16,'serviceId':r['requests'][0],'epoch':r['epoch'],'bootId':r['bootId'],'generation':self.generation,'totalGranted':self.quota,'windowBytes':self.quota,'requestSequence':r['sequence'],'validForMillis':60000}
   ack['grants']=[dict(self.grant)]
  return ack
PANEL=Panel()
class Handler(http.server.BaseHTTPRequestHandler):
 protocol_version='HTTP/1.1'
 def log_message(self,*a):pass
 def do_POST(self):
  size=int(self.headers.get('Content-Length','0'));assert size<16*1024*1024;r=json.loads(self.rfile.read(size));ack=PANEL.report(r)
  if self.path.endswith('/maintenance'):ack['maintenanceAccepted']=True
  body=json.dumps(ack).encode();self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
 def do_GET(self):
  key=self.headers['Sec-WebSocket-Key'];accept=base64.b64encode(hashlib.sha1((key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode();self.send_response(101);self.send_header('Upgrade','websocket');self.send_header('Connection','Upgrade');self.send_header('Sec-WebSocket-Accept',accept);self.end_headers();self.close_connection=True
  PANEL.handler=self;PANEL.serial+=1
  pending=b''
  try:
   while True:
    head=self.rfile.read(2)
    if len(head)!=2:return
    opcode=head[0]&15;size=head[1]&127
    if size==126:size=struct.unpack('!H',self.rfile.read(2))[0]
    if size==127:size=struct.unpack('!Q',self.rfile.read(8))[0]
    assert size<16*1024*1024
    mask=self.rfile.read(4) if head[1]&128 else b'';raw=self.rfile.read(size)
    if mask:raw=bytes(v^mask[i%4] for i,v in enumerate(raw))
    if opcode==8:return
    if opcode==1:pending=raw
    elif opcode==0:pending+=raw
    else:continue
    assert len(pending)<16*1024*1024
    if not head[0]&128:continue
    obj=decode(pending);pending=b''
    if obj.get('type')=='EngineHello':PANEL.hello=obj['info']
    elif obj.get('requestId'):PANEL.responses[obj['requestId']]=obj
  except (OSError,ValueError,struct.error):pass

def topology():
 assert not any('default' in l for l in run(['ip','route']).splitlines())
 for n in ['client','router','transit','target']:run(['ip','netns','add',n]);run(['ip','-n',n,'link','set','lo','up'])
 links=[('c0','r0','client','router','10.205.1.2/24','10.205.1.1/24'),('r1','m0','router','transit','10.205.2.1/24','10.205.2.2/24'),('m1','t0','transit','target','10.205.3.1/24','10.205.3.2/24')]
 for a,b,an,bn,aa,ba in links:
  run(['ip','link','add',a,'type','veth','peer','name',b]);run(['ip','link','set',a,'netns',an]);run(['ip','link','set',b,'netns',bn])
  for n,i,addr in [(an,a,aa),(bn,b,ba)]:run(['ip','-n',n,'addr','add',addr,'dev',i]);run(['ip','-n',n,'link','set',i,'up'])
 run(['ip','link','add','control','type','veth','peer','name','r2']);run(['ip','link','set','r2','netns','router']);run(['ip','addr','add','10.205.4.1/24','dev','control']);run(['ip','link','set','control','up']);run(['ip','-n','router','addr','add','10.205.4.2/24','dev','r2']);run(['ip','-n','router','link','set','r2','up'])
 for n in ['router','transit']:run(ns(n,'sh','-c','(mount -o remount,rw /proc/sys 2>/dev/null || true); sysctl -w net.ipv4.ip_forward=1'))
 run(['ip','-n','router','route','add','10.205.3.0/24','via','10.205.2.2']);run(['ip','-n','transit','route','add','10.205.1.0/24','via','10.205.2.1']);run(['ip','-n','client','route','add','default','via','10.205.1.1']);run(['ip','-n','target','route','add','default','via','10.205.3.1'])
 router('iptables','-P','FORWARD','DROP');router('iptables','-N','UNRELATED_FOUNDATION');router('iptables','-A','UNRELATED_FOUNDATION','-m','comment','--comment','keep-unrelated','-j','RETURN');router('iptables','-A','FORWARD','-m','conntrack','--ctstate','ESTABLISHED,RELATED','-j','ACCEPT')
 assert not any('default' in l for l in router('ip','route').splitlines())
 pathlib.Path('/run/flux-test-disposable').touch()
 spawn(ns('target','env','FLUX_ECHO_ALLOW_FRAGMENT=1','python3','/tests/echo_server.py'),'target.log')
 check('four private netns including an intermediate PMTU router; no external route')
def agent(fault=''):
 serial=PANEL.serial;args=ns('router',str(BUILD/'flux-agent'),'--config',str(CONFIG))
 if fault:args+=['--test-fault',fault]
 p=spawn(args,'agent.log');wait(lambda:PANEL.serial>serial and p.poll() is None);return p

def spec(ident='1_1_0',port=18000,revision=1):return {'id':ident,'revision':revision,'listenIP':'10.205.1.1','listenPort':port,'targetIP':'10.205.3.2','targetPort':19000,'enabled':True}
def probe(port=18000,blocked=False,size=128):
 code='''import socket
addr=('10.205.1.1',PORT);data=b'x'*SIZE
if not BLOCKED:
 s=socket.create_connection(addr,timeout=2);s.sendall(data);out=b''
 while len(out)<len(data):out+=s.recv(len(data)-len(out))
 assert out==data;s.close()
 u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);u.setsockopt(socket.IPPROTO_IP,10,0);u.settimeout(2);u.sendto(data,addr);assert u.recv(65535)==data
else:
 try:s=socket.create_connection(addr,timeout=.4);s.sendall(data);s.recv(1);raise AssertionError('TCP passed')
 except (OSError,TimeoutError):pass
 u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);u.setsockopt(socket.IPPROTO_IP,10,0);u.settimeout(.4);u.sendto(data,addr)
 try:u.recv(65535);raise AssertionError('UDP passed')
 except socket.timeout:pass
print('ok')'''.replace('PORT',str(port)).replace('SIZE',str(size)).replace('BLOCKED',str(blocked))
 return run(ns('client','python3','-c',code))=='ok'
def apply(s,success=True):return PANEL.rpc('ApplyForward',s,success=success)
def state():return json.loads(STATE.read_text())
def job(batch):
 r=PANEL.rpc('SubmitBatch',batch)['data'];assert r['id']==batch['id'];return wait(lambda:(v if v['status'] in ['succeeded','failed'] else None) if (v:=PANEL.rpc('GetBatchStatus',{'id':batch['id']})['data']) else None,80)
