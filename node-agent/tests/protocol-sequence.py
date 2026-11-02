"""SYN-data and reordered prefixes must remain classified after empty-ACK bypass."""
from foundation_fixture import *
try:
 topology();server=http.server.ThreadingHTTPServer(('10.205.4.1',8000),Handler);server.daemon_threads=True;threading.Thread(target=server.serve_forever,daemon=True).start()
 write_config({'addr':'http://10.205.4.1:8000','secret':SECRET,'statePath':str(STATE),'apply':True,'allowInsecure':True,'intervalSeconds':1});a=agent()
 s={'schemaVersion':5,'id':'1_1_0','revision':1,'enabled':True,'listen':{'host':'10.205.1.1','port':18000},'targets':[{'endpoint':{'host':'10.205.3.2','port':19000},'weight':1}],'protocolFilter':{'http':True,'tls':True,'socks':True,'unknown':'allow'}};apply(s)
 def http_count():return PANEL.rpc('GetForwardStatus',{'id':'1_1_0'})['data']['protocolInspection']['statistics']['http']
 code="""import socket,struct,time
src=socket.inet_aton('10.205.1.2');dst=socket.inet_aton('10.205.1.1');port=PORT
raw=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_RAW)
def checksum(b):
 if len(b)%2:b+=bytes([0])
 n=sum(struct.unpack('!'+str(len(b)//2)+'H',b));n=(n&65535)+(n>>16);n=(n&65535)+(n>>16);return ~n&65535
def send(seq,ack,flags,payload=b''):
 tcp=struct.pack('!HHIIBBHHH',port,18000,seq,ack,0x50,flags,65535,0,0)+payload
 c=checksum(src+dst+struct.pack('!BBH',0,6,len(tcp))+tcp);tcp=tcp[:16]+struct.pack('!H',c)+tcp[18:]
 ip=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(tcp),port,0x4000,64,6,0,src,dst);ip=ip[:10]+struct.pack('!H',checksum(ip))+ip[12:]
 raw.sendto(ip+tcp,('10.205.1.1',0))
"""
 before=http_count();run(ns('client','python3','-c',code.replace('PORT','47000')+"send(1000,0,2,b'GET / HTTP/1.1\\r\\n\\r\\n');time.sleep(.1)"));wait(lambda:http_count()==before+1);check('SYN carrying HTTP data is inspected and blocked')
 run(ns('client','iptables','-A','OUTPUT','-p','tcp','--tcp-flags','RST','RST','-j','DROP'))
 before=http_count();body="""
r=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_TCP);r.settimeout(3)
send(2000,0,2)
while True:
 b,_=r.recvfrom(65535);off=(b[0]&15)*4
 if b[12:16]==dst and struct.unpack('!HH',b[off:off+4])==(18000,port) and b[off+13]&0x12==0x12:
  ack=struct.unpack('!I',b[off+4:off+8])[0]+1;break
send(2001,ack,0x10);send(2003,ack,0x18,b'T / HTTP/1.1\\r\\n\\r\\n');time.sleep(.03);send(2001,ack,0x18,b'GE');time.sleep(.1)
"""
 run(ns('client','python3','-c',code.replace('PORT','47001')+body));wait(lambda:http_count()==before+1);check('SYN sequence tracking still blocks an out-of-order HTTP prefix')
 DONE=True
except Exception:
 traceback.print_exc()
 if (OUT/'agent.log').exists():print((OUT/'agent.log').read_text()[-5000:])
 raise
finally:
 for p in reversed(PROCS):stop(p)
 (OUT/'sequence-result.json').write_text(json.dumps({'success':DONE,'passed':CHECKS,'count':len(CHECKS),'externalForwardTestTargets':[]},indent=2))
