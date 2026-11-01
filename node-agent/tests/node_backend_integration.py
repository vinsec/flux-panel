"""Real panel + disposable MySQL, isolated Docker network; never contacts releases.

Requires /build/flux-agent (frozen Linux agent), /repo and writable /evidence.
Use flux-foundation-verifier:local on an --internal network, no published ports.
"""
import base64, hashlib, hmac, json, os, pathlib, subprocess, time, urllib.request
import pymysql

ROOT = pathlib.Path('/repo')
OUT = pathlib.Path('/evidence'); OUT.mkdir(exist_ok=True)
checks = []
panel = None

def check(name, condition=True):
    assert condition, name
    checks.append(name); print('PASS', name, flush=True)

def wait(fn, seconds=90):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            value = fn()
            if value: return value
        except Exception: pass
        time.sleep(.25)
    raise AssertionError('timed out waiting for isolated service')

def token(role=0):
    enc = lambda v: base64.urlsafe_b64encode(json.dumps(v, separators=(',', ':')).encode()).rstrip(b'=')
    head = enc({'alg':'HS256','typ':'JWT'})
    body = enc({'sub':'1','role_id':role,'user':'isolated','name':'isolated','iat':int(time.time()),'exp':int(time.time())+3600})
    signature = base64.urlsafe_b64encode(hmac.new(b'isolated-test-jwt-only',head+b'.'+body,hashlib.sha256).digest()).rstrip(b'=')
    return (head+b'.'+body+b'.'+signature).decode()

def api(path, data=None, expect=True):
    req = urllib.request.Request('http://127.0.0.1:6365/api/v1/'+path,
        data=json.dumps(data or {}).encode(), headers={'Authorization':token(),'Content-Type':'application/json'})
    with urllib.request.urlopen(req, timeout=20) as response: result=json.load(response)
    if expect: assert result['code']==0,(path,result.get('msg'))
    return result

def sql(query, args=()):
    with db.cursor() as cursor:
        cursor.execute(query,args); return cursor.fetchall()

def migration(name):
    with db.cursor() as cursor:
        cursor.execute((ROOT/'springboot-backend/migrations'/name).read_text())
        while cursor.nextset(): pass

def create(name, engine='iptables', **extra):
    data={'name':name,'engine':engine,'ip':'10.203.1.1','serverIp':'10.203.2.1','portSta':18000,'portEnd':18100,**extra}
    api('node/create',data)
    return sql('SELECT * FROM node WHERE name=%s',(name,))[0]

def update(node, **extra):
    return api('node/update',{'id':node['id'],'name':node['name'],'engine':node['engine'],
        'ip':node['ip'],'serverIp':node['server_ip'],'portSta':node['port_sta'],'portEnd':node['port_end'],**extra},expect=False)

success=False
try:
    def connect():
        global db
        db=pymysql.connect(host='mysql',user='root',password='isolated-test-db-only',database='flux_test',
            autocommit=True,cursorclass=pymysql.cursors.DictCursor,client_flag=pymysql.constants.CLIENT.MULTI_STATEMENTS)
        return True
    wait(connect)
    with db.cursor() as cursor:
        cursor.execute((ROOT/'gost.sql').read_text())
        while cursor.nextset(): pass
    for name in ['001-forward-engines.sql','002-engine-foundation.sql','003-engine-p1.sql']:
        migration(name)
    for engine in ['gost','iptables']:
        sql("INSERT INTO node(name,engine,secret,ip,server_ip,port_sta,port_end,created_time,status) VALUES(%s,%s,'isolated-old-key','10.0.0.1','10.0.0.1',18000,18100,0,0)",('old-'+engine,engine))
    before=sql('SELECT id,in_flow,out_flow FROM user ORDER BY id')
    migration('004-node-kernel-backend.sql'); migration('004-node-kernel-backend.sql')
    check('repeatable migration keeps both old node engines and their iptables backend',
        all(n['kernel_backend']=='iptables' and n['name']=='old-'+n['engine'] for n in sql('SELECT * FROM node')))
    check('migration leaves existing user accounting unchanged',before==sql('SELECT id,in_flow,out_flow FROM user ORDER BY id'))
    env=os.environ.copy();env.update(DB_HOST='mysql',DB_NAME='flux_test',DB_USER='root',DB_PASSWORD='isolated-test-db-only',
        JWT_SECRET='isolated-test-jwt-only',LOG_DIR='/tmp/panel-logs')
    jar=ROOT/'springboot-backend/target/admin-0.0.1-SNAPSHOT.jar'
    panel=subprocess.Popen(['java','-Xmx192m','-XX:ActiveProcessorCount=1','-jar',str(jar),
        '--node.release.base-url=https://example.invalid/frozen','--node.release.manifest-sha256='+'a'*64,
        '--node.release.installer-sha256='+'b'*64],stdout=open(OUT/'panel.log','w'),stderr=subprocess.STDOUT,env=env)
    wait(lambda:urllib.request.urlopen('http://127.0.0.1:6365/flow/test',timeout=1).status==200)
    check('real Spring panel starts with the new migration and dependencies')
    native=create('native-default'); legacy=create('explicit-iptables',kernelBackend='iptables'); gost=create('new-gost','gost')
    check('kernel create defaults to native nftables; explicit iptables and GOST survive',
        native['kernel_backend']=='nftables' and legacy['kernel_backend']=='iptables' and gost['engine']=='gost')
    for engine,backend in [('iptables','nft'),('gost','nftables')]:
        result=api('node/create',{'name':'invalid','engine':engine,'kernelBackend':backend,'ip':'10.0.0.1','serverIp':'10.0.0.1','portSta':18000,'portEnd':18100},expect=False)
        check('reject invalid backend combination '+engine+'/'+backend,result['code']!=0)
    check('backend cannot change in place',update(native,kernelBackend='iptables')['code']!=0)
    check('engine cannot change in place',update(native,engine='gost')['code']!=0)
    check('old clients can edit without resetting a native backend',update(native,name='native-edited')['code']==0 and sql('SELECT kernel_backend FROM node WHERE id=%s',(native['id'],))[0]['kernel_backend']=='nftables')
    old=sql("SELECT * FROM node WHERE name='old-iptables'")[0]
    check('old kernel node edits preserve iptables',update(old)['code']==0 and sql('SELECT kernel_backend FROM node WHERE id=%s',(old['id'],))[0]['kernel_backend']=='iptables')
    listed=api('node/list')['data']
    check('admin node API exposes backend without node secrets',all(n.get('secret') is None for n in listed) and {n['id']:n['kernelBackend'] for n in listed}[native['id']]=='nftables')
    sql("UPDATE vite_config SET value='panel.invalid' WHERE name='ip'")
    if not sql("SELECT * FROM vite_config WHERE name='ip'"):
        sql("INSERT INTO vite_config(name,value) VALUES('ip','panel.invalid')")
    for n in [native,legacy]:
        script=api('node/install',{'id':n['id']})['data']
        config=json.loads(script.split("<<'FLUX_NODE_CONFIG'\n",1)[1].split('\nFLUX_NODE_CONFIG',1)[0])
        check('install command pins backend '+n['kernel_backend'],config['kernelBackend']==n['kernel_backend'])
        path=pathlib.Path('/tmp/config-'+n['kernel_backend']+'.json');path.write_text(json.dumps(config));path.chmod(0o600)
        result=subprocess.run(['/build/flux-agent','--check-config','--config',str(path)],capture_output=True,text=True,timeout=10)
        check('existing Go agent accepts generated '+n['kernel_backend']+' config',result.returncode==0)
        path.unlink()
        # Seed online eligibility for this CRUD-only fixture; no data-plane claim.
        sql('UPDATE node SET status=1 WHERE id=%s',(n['id'],))
        # A spurious tunnel backend field is ignored: only the entrance node owns it.
        api('tunnel/create',{'name':'inherits-'+n['kernel_backend'],'engine':'iptables','inNodeId':n['id'],'type':1,'flow':1,'trafficRatio':1,
            'protocol':'tls','tcpListenAddr':'0.0.0.0','udpListenAddr':'0.0.0.0','kernelBackend':'iptables' if n==native else 'nftables'})
    rows=sql("SELECT t.name,t.engine,n.kernel_backend FROM tunnel t JOIN node n ON n.id=t.in_node_id ORDER BY t.id")
    check('tunnels inherit their own entrance node backend despite submitted override',
        len(rows)==2 and all(t['name']=='inherits-'+t['kernel_backend'] and t['engine']=='iptables' for t in rows))
    check('GOST installer remains GOST without kernel fields','kernelBackend' not in api('node/install',{'id':gost['id']})['data'])
    success=True
finally:
    if panel:
        panel.terminate()
        try: panel.wait(timeout=10)
        except subprocess.TimeoutExpired: panel.kill();panel.wait()
    (OUT/'result.json').write_text(json.dumps({'success':success,'passed':checks,'count':len(checks),
        'network':'Docker --internal, no published ports','external_test_targets':[],
        'panel_sha256':hashlib.sha256((ROOT/'springboot-backend/target/admin-0.0.1-SNAPSHOT.jar').read_bytes()).hexdigest()},ensure_ascii=False,indent=2)+'\n')
