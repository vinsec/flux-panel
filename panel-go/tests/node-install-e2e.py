#!/usr/bin/env python3
"""Real panel -> HTTPS installer -> real node, using disposable internal Docker only.
Requires a prebuilt panel image and the local Linux fixture image. Never uses SSH.
"""
import argparse,json,pathlib,subprocess,tempfile,time,uuid,shutil,os
p=argparse.ArgumentParser();p.add_argument('--panel-image',default='flux-node-install-candidate:local');p.add_argument('--fixture-image',default='flux-foundation-verifier:local');p.add_argument('--evidence',required=True,type=pathlib.Path);a=p.parse_args();out=a.evidence.resolve();out.mkdir(parents=True,exist_ok=True)
for f in ['gost.service.log','flux-agent.service.log','flux-kernel.service.log','systemctl.calls']:
 if (out/f).exists():(out/f).unlink()
name='flux-install-'+uuid.uuid4().hex[:8];network=name+'-net';containers=[];checks=[];repo=pathlib.Path(__file__).resolve().parents[2]
def run(args,timeout=120):
 r=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
 if r.returncode:raise RuntimeError(str(args[:4])+': '+r.stderr[-2000:]+r.stdout[-1500:])
 return r.stdout.strip()
def docker(*args,timeout=120):return run(['docker',*args],timeout)
def start(role,image,extra=(),cmd=()):
 n=name+'-'+role;docker('run','-d','--name',n,'--network',network,*extra,image,*cmd);containers.append(n);return n
def ip(n):return next(iter(json.loads(docker('inspect',n))[0]['NetworkSettings']['Networks'].values()))['IPAddress']
def check(label,condition):
 assert condition,label;checks.append(label);print('PASS',label,flush=True)
try:
 docker('network','create','--internal',network)
 docker('run','--rm','--network','none','-v',str(out)+':/evidence',a.fixture_image,'openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout','/evidence/key.pem','-out','/evidence/cert.pem','-days','1','-subj','/CN=panel.test','-addext','subjectAltName=DNS:panel.test')
 mysql=start('mysql','mysql:8.2',('-e','MYSQL_ALLOW_EMPTY_PASSWORD=yes','-e','MYSQL_DATABASE=flux_go_test_installer','--network-alias','database'))
 for _ in range(60):
  try:docker('exec',mysql,'mysqladmin','--protocol=tcp','-h127.0.0.1','ping','--silent',timeout=3);break
  except Exception:time.sleep(.5)
 env=['-e','DB_HOST=database:3306','-e','DB_NAME=flux_go_test_installer','-e','DB_USER=root','-e','DB_PASSWORD=','-e','JWT_SECRET=isolated-installer-only','-e','TZ=Asia/Shanghai']
 docker('run','--rm','--network',network,*env,a.panel_image,'migrate','--init')
 backend=start('backend',a.panel_image,(*env,'--network-alias','backend'))
 (out/'nginx.conf').write_text('events {}\nhttp {server {listen 443 ssl; ssl_certificate /test/cert.pem; ssl_certificate_key /test/key.pem; location / {proxy_pass http://backend:6365;proxy_http_version 1.1;proxy_set_header Upgrade $http_upgrade;proxy_set_header Connection "upgrade";}}}\n')
 proxy=start('https','nginx:stable-alpine',('--network-alias','panel.test','-v',str(out)+':/test:ro','-v',str(out/'nginx.conf')+':/etc/nginx/nginx.conf:ro'))
 fake='''#!/usr/bin/env python3
import sys,os,pathlib,subprocess,pwd,signal,json
root=pathlib.Path('/tmp/fake-systemd');root.mkdir(exist_ok=True);action=sys.argv[1];unit=sys.argv[-1] if len(sys.argv)>2 else '';key=root/(unit+'.pid');open('/evidence/systemctl.calls','a').write(' '.join(sys.argv[1:])+'\\n')
if action=='stop':
 if key.exists():
  try:os.kill(int(key.read_text()),signal.SIGTERM)
  except ProcessLookupError:pass
  key.unlink()
 sys.exit(0)
if action=='show':
 print(key.read_text() if key.exists() else '0');sys.exit(0)
if action=='is-active':sys.exit(0 if key.exists() else 3)
if action!='start':sys.exit(0)
if key.exists():sys.exit(0)
u=pwd.getpwnam('flux-agent') if unit!='gost.service' else None
if unit=='flux-kernel.service':
 d=pathlib.Path('/run/flux-agent');d.mkdir(exist_ok=True);os.chown(d,0,u.pw_gid);d.chmod(0o750)
 args=['setpriv','--regid='+str(u.pw_gid),'--clear-groups','--bounding-set=-all,+net_admin,+net_raw,+net_bind_service','/usr/local/bin/flux-agent','--kernel-helper','--helper-user','flux-agent','--config','/etc/flux-agent/config.json'];cwd='/'
elif unit=='flux-agent.service':
 d=pathlib.Path('/run/test-credentials');d.mkdir(exist_ok=True);os.chown(d,u.pw_uid,u.pw_gid);d.chmod(0o700);f=d/'config.json';f.write_bytes(pathlib.Path('/etc/flux-agent/config.json').read_bytes());os.chown(f,u.pw_uid,u.pw_gid);f.chmod(0o600)
 d=pathlib.Path('/run/flux-agent-gost');d.mkdir(exist_ok=True);os.chown(d,u.pw_uid,u.pw_gid);d.chmod(0o750)
 args=['setpriv','--reuid='+str(u.pw_uid),'--regid='+str(u.pw_gid),'--clear-groups','--bounding-set=-all','/usr/local/bin/flux-agent','--config',str(f)];cwd='/'
else:args=['/etc/gost/gost'];cwd='/etc/gost'
p=subprocess.Popen(args,cwd=cwd,stdout=open('/evidence/'+unit+'.log','a'),stderr=subprocess.STDOUT);key.write_text(str(p.pid))
'''
 (out/'systemctl').write_text(fake);(out/'systemctl').chmod(0o755)
 (out/'journalctl').write_text('#!/bin/sh\ncat /evidence/gost.service.log 2>/dev/null\n');(out/'journalctl').chmod(0o755)
 node=start('node',a.fixture_image,('--privileged','-v',str(out)+':/evidence','-v',str(out/'cert.pem')+':/tmp/test-ca.pem:ro'),('sleep','infinity'))
 legacy=start('legacy',a.fixture_image,('--privileged','-v',str(out)+':/evidence','-v',str(out/'cert.pem')+':/tmp/test-ca.pem:ro'),('sleep','infinity'))
 target=start('target',a.fixture_image,('-v',str(repo/'node-agent/tests/echo_server.py')+':/echo.py:ro'),('python3','/echo.py'))
 client=start('client',a.fixture_image,('-v',str(out)+':/evidence','-v',str(out/'cert.pem')+':/tmp/test-ca.pem:ro'),('sleep','infinity'))
 for n in [node,legacy]:
  docker('exec',n,'sh','-c','mount -o remount,rw /proc/sys;sysctl -w net.ipv4.ip_forward=0 >/dev/null;mkdir -p /tmp/fake-bin;cp /evidence/systemctl /evidence/journalctl /tmp/fake-bin/;chmod 755 /tmp/fake-bin/*')
 def api(path,data={}):
  code="import urllib.request,ssl,json;d=json.loads("+repr(json.dumps(data))+ ");q=urllib.request.Request('https://panel.test/api/v1/"+path+"',data=json.dumps(d).encode(),headers={'Content-Type':'application/json','Authorization':"+repr(token if 'token' in globals() else '')+"});r=json.load(urllib.request.urlopen(q,context=ssl.create_default_context(cafile='/tmp/test-ca.pem')));print(json.dumps(r))"
  r=json.loads(docker('exec',client,'python3','-c',code));assert r['code']==0,(path,r.get('msg'));return r.get('data')
 for _ in range(30):
  try:login=api('user/login',{'username':'admin_user','password':'admin_user'});break
  except Exception:time.sleep(.5)
 token=login['token'];api('config/update-single',{'name':'ip','value':'https://panel.test'})
 def install(n,engine):
  api('node/create',{'name':n,'engine':engine,'ip':ip(n),'serverIp':ip(n),'portSta':18000,'portEnd':18100})
  row=next(v for v in api('node/list') if v['name']==n);cmd=api('node/install',{'id':row['id']})
  check(engine+' default command uses built-in HTTPS downloads and hashes','/node-install/' in cmd and 'sha256sum --strict -c' in cmd)
  f=out/(engine+'-command.sh');f.write_text(cmd);f.chmod(0o600)
  docker('exec','-e','PATH=/tmp/fake-bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','-e','SSL_CERT_FILE=/tmp/test-ca.pem','-e','CURL_CA_BUNDLE=/tmp/test-ca.pem',n,'bash','/evidence/'+f.name,timeout=120)
  for _ in range(60):
   actual=next(v for v in api('node/list') if v['id']==row['id'])
   if actual['status']==1:break
   time.sleep(.25)
  check(engine+' installed program registers with the real panel',actual['status']==1)
  return row['id']
 nid=install(node,'kernel')
 api('tunnel/create',{'name':'private-install-test','engine':'kernel','inNodeId':nid,'type':1,'flow':1});tid=next(v['id'] for v in api('tunnel/list') if v['name']=='private-install-test')
 api('forward/create',{'name':'private-echo','tunnelId':tid,'inPort':18000,'remoteAddr':ip(target)+':19000'})
 def probe():
  code="import socket\nfor kind in [socket.SOCK_STREAM,socket.SOCK_DGRAM]:\n s=socket.socket(socket.AF_INET,kind);s.settimeout(3);s.connect(("+repr(ip(node))+",18000));s.sendall(b'private-installer-check');assert s.recv(512)==b'private-installer-check';s.close()"
  docker('exec',client,'python3','-c',code)
 passed=False
 for _ in range(30):
  try:probe();passed=True;break
  except Exception:time.sleep(.2)
 check('fresh installed native mode forwards real TCP and UDP',passed)
 jid=str(uuid.uuid4());api('engine/switch-mode',{'nodeId':nid,'id':jid,'mode':'gost'})
 for _ in range(50):
  task=api('engine/mode-switch-status',{'nodeId':nid})
  if task['status'] in ['succeeded','failed','blocked']:break
  time.sleep(.25)
 check('installed managed GOST supports a real same-node switch',task['status']=='succeeded');probe();check('managed GOST forwards real TCP and UDP',True)
 install(legacy,'gost')
 check('test network has no external default route',not any(line.startswith('default') for line in docker('exec',node,'ip','route').splitlines()))
 (out/'result.json').write_text(json.dumps({'success':True,'checks':checks,'count':len(checks),'externalTargets':[],'systemd':'simulated manager, real kernel/helper/network processes'},indent=2));print(json.dumps({'success':True,'checks':len(checks)}))
finally:
 for n in containers:
  if n.endswith('-node'):
   debug=subprocess.run(['docker','exec',n,'sh','-c','ps -eo pid,ppid,uid,gid,args; ls -ld /run/flux-agent /run/flux-agent-gost; ls -l /run/flux-agent; cat /tmp/fake-systemd/*.pid'],capture_output=True,text=True)
   (out/'process-debug.txt').write_text(debug.stdout+debug.stderr)
 for n in reversed(containers):subprocess.run(['docker','rm','-fv',n],capture_output=True)
 subprocess.run(['docker','network','rm',network],capture_output=True)
