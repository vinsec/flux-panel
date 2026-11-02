#!/usr/bin/python3
import socket,sys,json
port=int(sys.argv[1]);blocked=len(sys.argv)>2 and sys.argv[2]=='blocked';data=b'fusion-private-payload'*8
for typ in [socket.SOCK_STREAM,socket.SOCK_DGRAM]:
 s=socket.socket(socket.AF_INET,typ);s.settimeout(.5 if blocked else 3)
 try:
  s.connect(('10.230.1.1',port));s.sendall(data);out=b''
  while len(out)<len(data):
   b=s.recv(65536)
   if not b:raise OSError('eof')
   out+=b
  assert not blocked and out==data
 except (OSError,TimeoutError):
  if not blocked:raise
 finally:s.close()
print(json.dumps({'ok':True,'blocked':blocked,'bytesPerProtocol':len(data),'externalTargets':[]}))
