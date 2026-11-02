import urllib.request,urllib.error,json,socket,base64,os
checks=[]
def check(name,ok=True):
 assert ok,name;checks.append(name)
def req(path,data=None,token=None):
 headers={'Content-Type':'application/json'}
 if token:headers['Authorization']=token
 request=urllib.request.Request('http://frontend'+path,data=json.dumps(data).encode() if data is not None else None,headers=headers)
 try:
  r=urllib.request.urlopen(request,timeout=10);return r.status,r.read()
 except urllib.error.HTTPError as e:return e.code,e.read()
check('frontend serves built static application',b'<!doctype html>' in req('/')[1].lower())
check('frontend proxies Go database health',req('/healthz')[0]==200)
check('frontend proxies flow test',req('/flow/test')[0]==200)
status,body=req('/api/v1/user/login',{'username':'admin_user','password':'admin_user'})
login=json.loads(body);check('login through actual nginx to Go backend',status==200 and login['code']==0)
token=login['data']['token']
check('authenticated list through nginx',json.loads(req('/api/v1/forward/list',{},token)[1])['code']==0)
status,body=req('/flow/engine/v3/session',{})
check('native session path reaches Go instead of frontend HTML',isinstance(json.loads(body),dict) and json.loads(body).get('code')!=0)
ticket=json.loads(req('/api/v1/engine/socket-ticket',{},token)[1])['data']['ticket']
s=socket.create_connection(('frontend',80),timeout=10)
key=base64.b64encode(os.urandom(16)).decode()
s.sendall(('GET /system-info?type=admin&ticket='+ticket+' HTTP/1.1\r\nHost: frontend\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: '+key+'\r\n\r\n').encode())
response=s.recv(4096);s.close();check('admin websocket upgrades through actual nginx',response.startswith(b'HTTP/1.1 101'))
json.dump({'success':True,'count':len(checks),'checks':checks,'network':'disposable Docker internal network','public_business_targets':[]},open('/evidence/deployment.json','w'),indent=2)
print('PASS deployment:',len(checks))
