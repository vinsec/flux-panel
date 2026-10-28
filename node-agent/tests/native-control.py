"""Real RELATED ICMP errors: per-token rate, pause and exhausted-credit gate."""
import os
os.environ['FLUX_KERNEL_BACKEND']='nftables'
from foundation_fixture import *

def reader(tag,port,source_port):
 code=f'''import socket,time,pathlib,json
r=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP);r.settimeout(.05)
u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);u.settimeout(2);u.bind(('10.205.1.2',{source_port}));u.connect(('10.205.1.1',{port}));u.send(b'icmp-live');assert u.recv(100)==b'icmp-live'
pathlib.Path('/tmp/{tag}-ready').touch()
while not pathlib.Path('/tmp/{tag}-go').exists():time.sleep(.01)
end=time.monotonic()+1.2;count=0
while time.monotonic()<end:
 try:b,_=r.recvfrom(4096)
 except socket.timeout:continue
 off=(b[0]&15)*4
 if b[off:off+2]==b'\\x03\\x04' and b[off+30:off+32]=={struct.pack('!H',port)!r}:count+=1
pathlib.Path('/tmp/{tag}-result').write_text(json.dumps(count))
'''
 p=spawn(ns('client','python3','-c',code),tag+'.log');wait(lambda:pathlib.Path('/tmp/'+tag+'-ready').exists());return p
def errors(tag,source_port):
 pathlib.Path('/tmp/'+tag+'-go').touch()
 code=f'''import socket,struct
def checksum(b):
 if len(b)%2:b+=b'\\x00'
 n=sum(struct.unpack('!'+str(len(b)//2)+'H',b));n=(n&65535)+(n>>16);n=(n&65535)+(n>>16);return (~n)&65535
h=struct.pack('!BBHHHBBH4s4s',0x45,0,36,0xd431,0x4000,64,17,0,socket.inet_aton('10.205.2.1'),socket.inet_aton('10.205.3.2'));h=h[:10]+struct.pack('!H',checksum(h))+h[12:]
inner=h+struct.pack('!4H',{source_port},19000,16,0)+b'icmp-live'[:8]
b=b'\\x03\\x04\\x00\\x00'+struct.pack('!HH',0,1280)+inner;b=b[:2]+struct.pack('!H',checksum(b))+b[4:]
s=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)
for _ in range(80):s.sendto(b,('10.205.2.1',0))
'''
 run(ns('transit','python3','-c',code))
try:
 topology();server=http.server.ThreadingHTTPServer(('10.205.4.1',8000),Handler);server.daemon_threads=True;threading.Thread(target=server.serve_forever,daemon=True).start()
 write_config({'addr':'http://10.205.4.1:8000','secret':SECRET,'statePath':str(STATE),'apply':True,'allowInsecure':True,'intervalSeconds':1});a=agent();s=spec();apply(s)
 p=reader('control-active',18000,40000);before=native_counters('1_1_0');errors('control-active',40000);assert p.wait(timeout=4)==0;count=json.loads(pathlib.Path('/tmp/control-active-result').read_text());check('related ICMP is limited per token to the existing 10pps/burst10 policy',1<=count<=15);check('control errors do not inflate business counters',native_counters('1_1_0')==before)
 p=reader('control-paused',18000,40001);PANEL.rpc('SetForwardState',{'id':'1_1_0','revision':2,'enabled':False});errors('control-paused',40001);assert p.wait(timeout=4)==0;check('pause blocks already associated ICMP despite external ACCEPT',json.loads(pathlib.Path('/tmp/control-paused-result').read_text())==0)
 limited=spec('2_2_3',18001);limited['leaseRequired']=True;PANEL.quota=8192;apply(limited);wait(lambda:'2_2_3' in state().get('leases',{}));p=reader('control-quota',18001,40002)
 run(ns('client','python3','-c',"import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(.005)\nfor _ in range(80):\n s.sendto(b'q'*1000,('10.205.1.1',18001))\n try:s.recv(2048)\n except socket.timeout:pass"));time.sleep(1.4);errors('control-quota',40002);assert p.wait(timeout=4)==0;check('exhausted credit also closes related ICMP control',json.loads(pathlib.Path('/tmp/control-quota-result').read_text())==0)
 (OUT/'icmp-rate.json').write_text(json.dumps({'attempts':80,'received':count,'ratePerSecond':10,'burst':10}));DONE=True
except Exception:
 traceback.print_exc()
 if (OUT/'agent.log').exists():print((OUT/'agent.log').read_text()[-8000:])
 raise
finally:
 for p in reversed(PROCS):stop(p)
 (OUT/'native-control-result.json').write_text(json.dumps({'success':DONE,'count':len(CHECKS),'passed':CHECKS,'external_forward_test_targets':[]},indent=2))
