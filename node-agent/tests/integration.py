"""Independent black-box verifier: real Java panel, MySQL, agent and kernel.

Run only in the disposable privileged test container. All transfer tests stay
on 10.203.0.0/16 veth links; the Docker network is --internal, never qcloud GZ.
"""
import os,json,time,subprocess,socket,sys,pathlib,urllib.request,urllib.error,base64,hmac,hashlib,signal
import pymysql
import shutil,zipfile,threading

ROOT=pathlib.Path('/repo');OUT=pathlib.Path('/evidence');OUT.mkdir(exist_ok=True)
for name in ['agent.log','panel.log','gost.log','target.log','unmanaged-listener.log']:
    (OUT/name).unlink(missing_ok=True)
checks=[];processes=[];db=None;completed=False;artifacts={}
FROZEN=pathlib.Path("/tmp/verified-build");FROZEN.mkdir(exist_ok=True)
AGENT=FROZEN/"flux-agent";JAR=FROZEN/"panel.jar"
def check(name,condition=True):
    assert condition,name
    checks.append(name);print('PASS',name,flush=True)
def cmd(*args,**kwargs):
    p=subprocess.run(list(args),text=True,capture_output=True,**kwargs)
    if p.returncode:raise RuntimeError(str(args)+': '+p.stderr[-1500:])
    return p.stdout.strip()
def start(args,log,cwd=None):
    f=open(OUT/log,'a');p=subprocess.Popen(args,stdout=f,stderr=subprocess.STDOUT,text=True,cwd=cwd);processes.append(p);return p
def wait(fn,seconds=40):
    end=time.time()+seconds;last=None
    while time.time()<end:
        try:
            value=fn()
            if value:return value
        except Exception as e:last=e
        time.sleep(.25)
    raise AssertionError('condition timed out: '+str(last))
def sql(query,args=()):
    with db.cursor() as c:c.execute(query,args);return c.fetchall()
def jwt(uid=1,role=0):
    enc=lambda v:base64.urlsafe_b64encode(json.dumps(v,separators=(',',':')).encode()).rstrip(b'=')
    h=enc({'alg':'HS256','typ':'JWT'});p=enc({'sub':str(uid),'role_id':role,'user':'test','name':'test','iat':int(time.time()),'exp':int(time.time())+3600})
    sig=base64.urlsafe_b64encode(hmac.new(b'isolated-test-jwt-only',h+b'.'+p,hashlib.sha256).digest()).rstrip(b'=')
    return (h+b'.'+p+b'.'+sig).decode()
def api(path,data=None,uid=1,role=0,expect=True):
    req=urllib.request.Request('http://127.0.0.1:6365/api/v1/'+path,data=json.dumps(data or {}).encode(),headers={'Authorization':jwt(uid,role),'Content-Type':'application/json'})
    with urllib.request.urlopen(req,timeout=30) as r:out=json.load(r)
    if expect:assert out['code']==0,(path,out)
    return out
def node(name,engine='kernel'):
    data={'name':name,'ip':'10.203.1.1','serverIp':'10.203.2.1','portSta':18000,'portEnd':18100}
    if engine!='gost':data.update(engine=engine,kernelBackend='nftables')
    api('node/create',data)
    return sql('SELECT * FROM node WHERE name=%s',(name,))[0]
def tunnel(n,name,engine='kernel',**overrides):
    d={'name':name,'engine':engine,'inNodeId':n['id'],'type':1,'flow':1,'trafficRatio':1,'protocol':'tls','tcpListenAddr':'0.0.0.0','udpListenAddr':'0.0.0.0'};d.update(overrides)
    if engine=='gost':d.pop('engine',None)
    api('tunnel/create',d);return sql('SELECT * FROM tunnel WHERE name=%s',(name,))[0]
def forward(t,name,port=18000,uid=1,role=0,target='10.203.2.2:19000'):
    api('forward/create',{'name':name,'tunnelId':t['id'],'remoteAddr':target,'inPort':port,'strategy':'fifo'},uid,role)
    return sql('SELECT * FROM forward WHERE name=%s',(name,))[0]
def probe(port=18000,action='probe'):
    return cmd('ip','netns','exec','client','python3','/repo/node-agent/tests/traffic_client.py',str(port),action)
def router(*args):return cmd('ip','netns','exec','router',*args)
def native_bindings():
    return [v for item in json.loads(router('nft','-j','list','table','inet','FP_NATIVE'))['nftables'] for kind in ['map'] if kind in item for v in item[kind].get('elem',[]) if item[kind]['name'].startswith('bind')]
def native_bytes(ident,direction):
    return sum(item['counter']['bytes'] for item in json.loads(router('nft','-j','list','table','inet','FP_NATIVE'))['nftables'] if 'counter' in item and item['counter'].get('comment','').split('|')[-1]=='flux:v2:'+ident+':'+direction)
def counted_bytes(text,comment):
    import shlex
    total=0
    for line in text.splitlines():
        fields=shlex.split(line)
        if comment in fields and 'bytes' in fields:total+=int(fields[fields.index('bytes')+1])
    return total
def namespaces():
    cmd('sh','-c','mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf; mkdir -p /sys/fs/bpf/tc/globals /sys/fs/bpf/ip/globals /sys/fs/bpf/xdp/globals')
    for n in ['client','router','target']:cmd('ip','netns','add',n);cmd('ip','-n',n,'link','set','lo','up')
    for a,b,na,nb,ia,ib in [('c0','r0','client','router','10.203.1.2/24','10.203.1.1/24'),('t0','r1','target','router','10.203.2.2/24','10.203.2.1/24')]:
        cmd('ip','link','add',a,'type','veth','peer','name',b);cmd('ip','link','set',a,'netns',na);cmd('ip','link','set',b,'netns',nb)
        for n,i,addr in [(na,a,ia),(nb,b,ib)]:cmd('ip','-n',n,'addr','add',addr,'dev',i);cmd('ip','-n',n,'link','set',i,'up')
    cmd('ip','link','add','control','type','veth','peer','name','r2');cmd('ip','link','set','r2','netns','router');cmd('ip','addr','add','10.203.3.1/24','dev','control');cmd('ip','link','set','control','up');cmd('ip','-n','router','addr','add','10.203.3.2/24','dev','r2');cmd('ip','-n','router','link','set','r2','up')
    cmd('ip','-n','client','route','add','default','via','10.203.1.1');cmd('ip','-n','target','route','add','default','via','10.203.2.1')
    router('sh','-c','(mount -o remount,rw /proc/sys || true); sysctl -w net.ipv4.ip_forward=1')
    router('iptables','-P','FORWARD','DROP')
    router('iptables','-N','UNRELATED_TEST');router('iptables','-A','UNRELATED_TEST','-m','comment','--comment','must-survive','-j','RETURN')
    router('iptables','-A','FORWARD','-m','conntrack','--ctstate','ESTABLISHED,RELATED','-j','ACCEPT')
    # Native ACCEPT cannot override the host's independent default DROP. Explicit lab-only allow.
    router('iptables','-A','FORWARD','-i','r0','-o','r1','-j','ACCEPT')
    check('isolated client/router/target namespaces; forwarding default DROP')
def start_agent(n):
    p=pathlib.Path('/tmp/flux-agent-config.json');p.write_text(json.dumps({'addr':'http://10.203.3.1:6365','secret':n['secret'],'statePath':'/tmp/flux-agent-state.json','apply':True,'allowInsecure':True,'intervalSeconds':1,'useSessions':True}))
    return start(['ip','netns','exec','router','sh','-c','mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf; mkdir -p /run/flux-agent-bpf; mount -t tmpfs -o mode=0700 tmpfs /run/flux-agent-bpf; "$1" --prepare-local-shaping >/dev/null; exec setpriv --bounding-set=-all,+net_admin,+net_raw,+net_bind_service "$@"','sh',str(AGENT),'--config',str(p)],'agent.log')
def usage_total(fid):return sql('SELECT in_flow+out_flow AS total FROM forward WHERE id=%s',(fid,))[0]['total']
try:
    for name,source,destination in [('agent',pathlib.Path('/build/flux-agent'),AGENT),('panel',ROOT/'springboot-backend/target/admin-0.0.1-SNAPSHOT.jar',JAR)]:
        expected=hashlib.sha256(source.read_bytes()).hexdigest();shutil.copyfile(source,destination)
        actual=hashlib.sha256(destination.read_bytes()).hexdigest()
        assert actual==expected==hashlib.sha256(source.read_bytes()).hexdigest(),'artifact changed during snapshot: '+name
        artifacts[name]=actual
    AGENT.chmod(0o755)
    with zipfile.ZipFile(JAR) as jar:assert jar.testzip() is None,'invalid JAR snapshot'
    check('validated immutable agent and JAR snapshots before starting services')
    def connect():
        global db
        db=pymysql.connect(host=os.getenv('FLUX_TEST_DB_HOST','mysql'),port=int(os.getenv('FLUX_TEST_DB_PORT','3306')),user='root',password='isolated-test-db-only',database='flux_test',autocommit=True,cursorclass=pymysql.cursors.DictCursor,client_flag=pymysql.constants.CLIENT.MULTI_STATEMENTS)
        return True
    wait(connect,60)
    with db.cursor() as c:
        c.execute((ROOT/'gost.sql').read_text())
        while c.nextset():pass
        c.execute("INSERT INTO node(name,secret,ip,server_ip,port_sta,port_end,created_time,status) VALUES('legacy-schema','unused-test-key','10.0.0.254','10.0.0.254',18000,18100,0,0)")
        c.execute((ROOT/'springboot-backend/migrations/001-forward-engines.sql').read_text())
        while c.nextset():pass
        c.execute((ROOT/'springboot-backend/migrations/001-forward-engines.sql').read_text())
        while c.nextset():pass
    with db.cursor() as c:
        for migration in ['002-engine-foundation.sql','003-engine-p1.sql','004-node-kernel-backend.sql','005-native-only.sql']:
            for _ in range(2):
                c.execute((ROOT/'springboot-backend/migrations'/migration).read_text())
                while c.nextset():pass
    check('database migration is repeatable; legacy rows default to gost',sql("SELECT engine FROM node WHERE name='legacy-schema'")[0]['engine']=='gost')
    env=os.environ.copy();env.update(DB_HOST='mysql',DB_NAME='flux_test',DB_USER='root',DB_PASSWORD='isolated-test-db-only',JWT_SECRET='isolated-test-jwt-only',LOG_DIR='/tmp/panel-logs',ENGINE_AUTH_SESSION_MILLIS='60000')
    if os.getenv('FLUX_TEST_DB_HOST'):
        env['SPRING_DATASOURCE_URL']='jdbc:mysql://'+os.environ['FLUX_TEST_DB_HOST']+':'+os.getenv('FLUX_TEST_DB_PORT','3306')+'/flux_test?useSSL=false&serverTimezone=Asia/Shanghai'
    log=open(OUT/'panel.log','w');panel=subprocess.Popen(['java','-Xmx192m','-XX:ActiveProcessorCount=1','-jar',str(JAR)],stdout=log,stderr=subprocess.STDOUT,env=env);processes.append(panel)
    wait(lambda:urllib.request.urlopen('http://127.0.0.1:6365/flow/test',timeout=1).status==200,90)
    check('real Spring Boot panel and MySQL started')
    if os.getenv('IPTABLES_BACKEND')=='legacy':cmd('update-alternatives','--set','iptables','/usr/sbin/iptables-legacy')
    namespaces();start(['ip','netns','exec','target','python3','/repo/node-agent/tests/echo_server.py'],'target.log')
    n=node('iptables-test');agent=start_agent(n);wait(lambda:sql('SELECT status FROM node WHERE id=%s',(n['id'],))[0]['status']==1)
    check('independent agent authenticated and registered over encrypted WebSocket frames')
    assert not any('gost' in p.read_text(errors='ignore').replace('\0',' ').split(' ')[0] for p in pathlib.Path('/proc').glob('[0-9]*/cmdline') if p.exists())
    t=tunnel(n,'iptables-test');f=forward(t,'iptables-test')
    check('panel creates IPv4 TCP and UDP DNAT/SNAT forward',probe()=='tcp_udp_ok')
    config=json.loads(pathlib.Path('/tmp/flux-agent-config.json').read_text());config['statePath']='/tmp/missing-state.json';pathlib.Path('/tmp/lost-config.json').write_text(json.dumps(config))
    lost=subprocess.run(['ip','netns','exec','router',str(AGENT),'--config','/tmp/lost-config.json'],capture_output=True,text=True,timeout=8)
    check('a second state path cannot adopt counters from a managed namespace',lost.returncode!=0 and ('persistent state missing' in lost.stderr or 'network namespace is already managed' in lost.stderr) and probe()=='tcp_udp_ok')
    duplicate=subprocess.run(['ip','netns','exec','router',str(AGENT),'--config','/tmp/flux-agent-config.json'],capture_output=True,text=True,timeout=8)
    check('second agent cannot share the active state directory',duplicate.returncode!=0 and 'another agent' in duplicate.stderr)
    wait(lambda:usage_total(f['id'])>0)
    check('kernel traffic reaches persistent panel ledger')
    agent.send_signal(signal.SIGSTOP);time.sleep(.05)
    state=json.loads(pathlib.Path('/tmp/flux-agent-state.json').read_text());key=f"{f['id']}_1_0";u=state['totals'][key]
    # A newer identical cumulative snapshot, followed by an older snapshot,
    # must not add bytes twice even while normal polling continues.
    time.sleep(.2);payload={'epoch':state['epoch'],'sequence':state['sequence'],'usage':[u]}
    def report(data):
        req=urllib.request.Request('http://127.0.0.1:6365/flow/engine/v1/traffic',data=json.dumps(data).encode(),headers={'Authorization':'Bearer '+n['secret'],'Content-Type':'application/json'})
        return urllib.request.urlopen(req,timeout=15).read()
    assert report(payload)==b'ok';before=usage_total(f['id']);assert report(payload)==b'ok';assert report(payload)==b'ok';check('replayed cumulative reports do not double bill',usage_total(f['id'])==before)
    agent.send_signal(signal.SIGCONT)
    p=subprocess.Popen(['ip','netns','exec','client','python3','/repo/node-agent/tests/traffic_client.py','18000','persistent'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True);processes.append(p)
    assert p.stdout.readline().strip()=='ready'
    api('forward/pause',{'id':f['id']});p.stdin.write('blocked\n');p.stdin.flush();assert p.stdout.readline().strip()=='existing_blocked'
    p.stdin.write('quit\n');p.stdin.flush();p.wait(timeout=3)
    check('pause blocks existing TCP and UDP despite external ESTABLISHED ACCEPT')
    check('pause blocks new TCP and UDP',probe(action='blocked')=='tcp_udp_blocked')
    api('forward/resume',{'id':f['id']});check('resume restores TCP/UDP',probe()=='tcp_udp_ok')
    before_pause=native_bytes(key,'up')
    peer=forward(t,'same-target-peer',18005)
    api('forward/pause',{'id':f['id']})
    check('per-forward hash policy isolates two forwards to the same target',probe(action='blocked')=='tcp_udp_blocked' and probe(18005)=='tcp_udp_ok')
    api('forward/resume',{'id':f['id']});probe()
    check('counter entries retain cumulative bytes across pause and resume',before_pause>0 and native_bytes(key,'up')>=before_pause)
    api('forward/delete',{'id':peer['id']})
    agent.terminate();agent.wait(timeout=5);wait(lambda:sql('SELECT status FROM node WHERE id=%s',(n['id'],))[0]['status']==0)
    agent=start_agent(n);wait(lambda:sql('SELECT status FROM node WHERE id=%s',(n['id'],))[0]['status']==1)
    check('agent restart restores rules and ledger epoch',json.loads(pathlib.Path('/tmp/flux-agent-state.json').read_text())['epoch']==state['epoch'] and probe()=='tcp_udp_ok')
    api('forward/update',{'id':f['id'],'userId':1,'name':f['name'],'tunnelId':t['id'],'remoteAddr':'10.203.2.2:19001','inPort':18000,'strategy':'fifo'})
    check('target change succeeds with targeted conntrack cleanup',probe()=='tcp_udp_ok')
    bad=api('forward/create',{'name':'unsupported','tunnelId':t['id'],'remoteAddr':'[fe80::1%eth0]:443','inPort':18009},expect=False)
    check('scoped link-local target is rejected without disturbing existing forward',bad['code']!=0 and probe()=='tcp_udp_ok')
    api('forward/delete',{'id':f['id']});check('delete blocks traffic and removes dispatch and binding entries',probe(action='blocked')=='tcp_udp_blocked' and not native_bindings())
    check('deletion empties native binding maps and retains final accounting',not native_bindings() and native_bytes(key,'up')>0)
    check('unrelated firewall chain and default DROP preserved','must-survive' in router('iptables-save') and '-P FORWARD DROP' in router('iptables','-S','FORWARD'))
    # P2 options travel through the real Java factory, capability negotiation,
    # DB reconciliation and typed agent wire contract.
    traffic={'traffic':{'localOutput':True}}
    api('forward/create',{'name':'p2-local-output','tunnelId':t['id'],'remoteAddr':'10.203.2.2:19000','inPort':18015,'strategy':'fifo','engineOptions':json.dumps(traffic)})
    p2=sql("SELECT * FROM forward WHERE name='p2-local-output'")[0];p2key=str(p2['id'])+'_1_0'
    check('Java API enables actual host OUTPUT TCP/UDP',router('python3','/repo/node-agent/tests/traffic_client.py','18015','probe')=='tcp_udp_ok')
    wait(lambda:usage_total(p2['id'])>0)
    p2state=json.loads(pathlib.Path('/tmp/flux-agent-state.json').read_text())['rules'][p2key]
    check('P2 schema4 and traffic intent survive real panel accounting',p2state['schemaVersion']==4 and p2state['traffic']['localOutput'])
    api('engine/set-bandwidth-group',{'nodeId':n['id'],'scope':'user','ownerId':1,'upBitsPerSecond':6000000,'downBitsPerSecond':6000000})
    wait(lambda:api('engine/forward-states',{'ids':[p2['id']]})['data'][0]['state']['status']=='failed',30)
    check('later shared cap closes unprepared local OUTPUT instead of retaining unlimited traffic',router('python3','/repo/node-agent/tests/traffic_client.py','18015','blocked')=='tcp_udp_blocked')
    router('ip','link','set','lo','mtu','131072');router('sh','-c','mount -o remount,rw /proc/sys; sysctl -w net.ipv4.conf.lo.accept_local=1 net.ipv4.conf.lo.rp_filter=2')
    wait(lambda:api('engine/forward-states',{'ids':[p2['id']]})['data'][0]['state']['status']=='applied',30)
    check('real Java shared-bandwidth reconciliation enables prepared local shaping',router('python3','/repo/node-agent/tests/traffic_client.py','18015','probe')=='tcp_udp_ok')
    api('engine/set-bandwidth-group',{'nodeId':n['id'],'scope':'user','ownerId':1,'upBitsPerSecond':0,'downBitsPerSecond':0})
    wait(lambda:router('python3','/repo/node-agent/tests/traffic_client.py','18015','probe')=='tcp_udp_ok',30)
    check('removing local cap retains OUTPUT and its ledger',usage_total(p2['id'])>0)
    # Hold this service's revision row so deletion stops after taking the
    # physical-host barrier. A limiter reconcile must not snapshot its old DB
    # row and resurrect it with a freshly allocated revision after deletion.
    blocker=pymysql.connect(host=os.getenv('FLUX_TEST_DB_HOST','mysql'),port=int(os.getenv('FLUX_TEST_DB_PORT','3306')),user='root',password='isolated-test-db-only',database='flux_test',autocommit=False)
    with blocker.cursor() as cursor:cursor.execute('SELECT revision FROM engine_revision WHERE node_id=%s AND service_id=%s FOR UPDATE',(n['id'],p2key))
    deleted=[];delete_errors=[]
    def concurrent_delete():
        try:deleted.append(api('forward/delete',{'id':p2['id']}))
        except Exception as error:delete_errors.append(str(error))
    deleting=threading.Thread(target=concurrent_delete);deleting.start()
    try:
        wait(lambda:any('engine_revision' in str(row.get('trx_query','')) and p2key in str(row.get('trx_query','')) for row in sql("SELECT trx_query FROM information_schema.innodb_trx WHERE trx_state='LOCK WAIT'")),10)
        api('engine/set-bandwidth-group',{'nodeId':n['id'],'scope':'user','ownerId':1,'upBitsPerSecond':6000000,'downBitsPerSecond':6000000})
        time.sleep(1.5)
    finally:blocker.commit();blocker.close()
    deleting.join(30);check('concurrent delete finishes while limiter reconciliation is queued',not deleting.is_alive() and not delete_errors and len(deleted)==1)
    for _ in range(12):
        live=json.loads(pathlib.Path('/tmp/flux-agent-state.json').read_text())['rules'].get(p2key,{})
        assert not live or live.get('deleted'),('deleted forward resurrected',p2key,live.get('revision'))
        time.sleep(.25)
    check('limiter reconciliation cannot resurrect a deleted local forward')
    api('engine/set-bandwidth-group',{'nodeId':n['id'],'scope':'user','ownerId':1,'upBitsPerSecond':0,'downBitsPerSecond':0})
    invalid=api('forward/create' ,{'name':'p2-unconfirmed-source','tunnelId':t['id'],'remoteAddr':'10.203.2.2:19000','inPort':18015,'engineOptions':json.dumps({'traffic':{'sourceMode':'preserve'}})},expect=False)
    check('Java rejects DNAT-only without operator confirmation',invalid['code']!=0)
    traffic={'traffic':{'sourceMode':'preserve','returnPathConfirmed':True}}
    api('forward/create',{'name':'p2-source-preserve','tunnelId':t['id'],'remoteAddr':'10.203.2.2:19000','inPort':18015,'strategy':'fifo','engineOptions':json.dumps(traffic)})
    p2=sql("SELECT * FROM forward WHERE name='p2-source-preserve'")[0]
    check('Java API applies routed source-preserving TCP/UDP',probe(18015)=='tcp_udp_ok')
    api('forward/delete',{'id':p2['id']})
    # Real v4 API round trip: typed listener reservations, bounded node status,
    # health and sharing all use the same business owner checks as old forwards.
    opts={'listeners':[{'host':'0.0.0.0','port':18009,'protocol':'tcp'}],'health':{'protocol':'tcp','intervalMillis':1000,'timeoutMillis':200,'rise':1,'fall':1},'bandwidth':{'upBitsPerSecond':10000000,'downBitsPerSecond':10000000}}
    api('forward/create',{'name':'advanced-tcp','tunnelId':t['id'],'remoteAddr':'10.203.2.2:19000','inPort':18009,'strategy':'fifo','engineOptions':json.dumps(opts)})
    adv=sql("SELECT * FROM forward WHERE name='advanced-tcp'")[0]
    opts['listeners'][0]['protocol']='udp';opts.pop('health');opts.pop('bandwidth')
    api('forward/create',{'name':'advanced-udp','tunnelId':t['id'],'remoteAddr':'10.203.2.2:19000','inPort':18009,'strategy':'fifo','engineOptions':json.dumps(opts)})
    advudp=sql("SELECT * FROM forward WHERE name='advanced-udp'")[0]
    wait(lambda:probe(18009)=='tcp_udp_ok');check('real Java API preserves independent same-port TCP/UDP and node health/shaping')
    states=api('engine/forward-states',{'ids':[adv['id'],advudp['id']]})['data']
    check('API returns actual node applied state and distinct business IDs',len(states)==2 and all(row['state']['status']=='applied' for row in states))
    api('engine/set-bandwidth-group',{'nodeId':n['id'],'scope':'user','ownerId':1,'upBitsPerSecond':6000000,'downBitsPerSecond':6000000})
    wait(lambda:json.loads(pathlib.Path('/tmp/flux-agent-state.json').read_text())['rules'][str(adv['id'])+'_1_0'].get('bandwidth',{}).get('user',{}).get('upBitsPerSecond')==6000000,30)
    check('admin bandwidth group changes reach existing forwards through batch reconciliation')
    api('engine/set-bandwidth-group',{'nodeId':n['id'],'scope':'user','ownerId':1,'upBitsPerSecond':0,'downBitsPerSecond':0})
    live=api('engine/capabilities',{'nodeId':n['id']})['data'];check('admin inspection returns current capacity and fresh report acknowledgement',live.get('lastAckAt',0)>0 and live['capacity']['configuredForwards']>=2)
    diagnosis=api('forward/diagnose',{'forwardId':adv['id'],'clientIP':'10.203.1.2','ingressInterface':'r0'})['data'];check('Java diagnostics default to route-only and keep remote return unverified',all(x.get('probeKind')=='routeOnly' for x in diagnosis['results']) and not diagnosis['probePerformed'] and not diagnosis['returnPath']['remoteReturnVerified'])
    diagnosis=api('forward/diagnose',{'forwardId':adv['id'],'probe':True})['data'];check('explicit Java diagnostics identify bounded node TCP handshake without inventing return proof',all(x.get('probeKind')=='tcpHandshake' and 'packetLoss' not in x for x in diagnosis['results']) and not diagnosis['returnPath']['remoteReturnVerified'])
    check('Java diagnostics reject non-Boolean probe',api('forward/diagnose',{'forwardId':adv['id'],'probe':'true'},expect=False)['code']!=0)
    assert sql('SELECT COUNT(*) n FROM engine_session WHERE node_id=%s',(n['id'],))[0]['n']>0
    check('new agent registers with opaque short-lived bearer session stored only by hash')
    serial=(OUT/'agent.log').read_text().count('kernel agent connected')
    api('engine/revoke-sessions',{'nodeId':n['id']})
    wait(lambda:(OUT/'agent.log').read_text().count('kernel agent connected')>serial,15)
    check('session revocation disconnects and bootstrap reauthentication restores forwarding',probe(18009)=='tcp_udp_ok')
    forbidden=api('engine/set-bandwidth-group',{'nodeId':n['id'],'scope':'user','ownerId':1,'upBitsPerSecond':1000.5,'downBitsPerSecond':0},expect=False)
    check('bandwidth API rejects fractional bit rate instead of silently truncating',forbidden['code']!=0)
    api('forward/delete',{'id':adv['id']});api('forward/delete',{'id':advudp['id']})
    # Non-admin accounting and quota fan-out exercise the original business
    # services through the new engine adapter, rather than calling the agent.
    now=int(time.time()*1000)
    sql('INSERT INTO user(user,pwd,role_id,exp_time,flow,num,created_time,status,flow_reset_time) VALUES(%s,%s,1,%s,1000,1000,%s,1,0)',('normal_test','unused',now+3600000,now))
    normal=sql('SELECT id FROM user WHERE user=%s',('normal_test',))[0]['id']
    sql('INSERT INTO user_tunnel(user_id,tunnel_id,speed_id,num,flow,flow_reset_time,exp_time,status) VALUES(%s,%s,NULL,100,1000,0,%s,1)',(normal,t['id'],now+3600000))
    permission=sql('SELECT id FROM user_tunnel WHERE user_id=%s',(normal,))[0]['id']
    nf1=forward(t,'normal-one',18002,normal,1);nf2=forward(t,'normal-two',18003,normal,1)
    wait(lambda:probe(18002)=='tcp_udp_ok');wait(lambda:probe(18003)=='tcp_udp_ok');wait(lambda:usage_total(nf1['id'])>0 and usage_total(nf2['id'])>0);time.sleep(1.5)
    a=sql('SELECT in_flow+out_flow AS total FROM user WHERE id=%s',(normal,))[0]['total'];b=sql('SELECT in_flow+out_flow AS total FROM user_tunnel WHERE id=%s',(permission,))[0]['total']
    check('forward, user and user-tunnel ledgers agree',a==b and a==usage_total(nf1['id'])+usage_total(nf2['id']))
    sql('UPDATE user SET flow=1,in_flow=1073741825,out_flow=0 WHERE id=%s',(normal,))
    wait(lambda:all(x['status']==0 for x in sql('SELECT status FROM forward WHERE user_id=%s',(normal,))),20)
    check('quota pauses every forwarding with its own service id',probe(18002,'blocked')=='tcp_udp_blocked' and probe(18003,'blocked')=='tcp_udp_blocked')
    sql('UPDATE user SET flow=1000,in_flow=0,out_flow=0 WHERE id=%s',(normal,));api('forward/resume',{'id':nf1['id']});api('forward/resume',{'id':nf2['id']})
    wait(lambda:probe(18002)=='tcp_udp_ok' and probe(18003)=='tcp_udp_ok');check('normal forwards recover after quota reset')
    # Two real Agents in different router namespaces share one nearly-empty
    # user budget. Every data packet remains on private veth links.
    for extra in ['client2','router2']:
        cmd('ip','netns','add',extra);cmd('ip','-n',extra,'link','set','lo','up')
    for left,right,ln,rn,la,ra in [('c2','r20','client2','router2','10.203.6.2/24','10.203.6.1/24'),('r21','t2','router2','target','10.203.5.1/24','10.203.5.2/24')]:
        cmd('ip','link','add',left,'type','veth','peer','name',right);cmd('ip','link','set',left,'netns',ln);cmd('ip','link','set',right,'netns',rn)
        for ns_name,interface,address in [(ln,left,la),(rn,right,ra)]:cmd('ip','-n',ns_name,'addr','add',address,'dev',interface);cmd('ip','-n',ns_name,'link','set',interface,'up')
    cmd('ip','link','add','control2','type','veth','peer','name','r22');cmd('ip','link','set','r22','netns','router2');cmd('ip','addr','add','10.203.7.1/24','dev','control2');cmd('ip','link','set','control2','up');cmd('ip','-n','router2','addr','add','10.203.7.2/24','dev','r22');cmd('ip','-n','router2','link','set','r22','up')
    cmd('ip','-n','client2','route','add','default','via','10.203.6.1');cmd('ip','netns','exec','router2','sh','-c','(mount -o remount,rw /proc/sys || true); sysctl -w net.ipv4.ip_forward=1')
    cmd('ip','netns','exec','router2','iptables','-P','FORWARD','DROP')
    cmd('ip','netns','exec','router2','iptables','-A','FORWARD','-i','r20','-o','r21','-j','ACCEPT')
    api('node/create',{'name':'second-lease-node','engine':'kernel','kernelBackend':'nftables','ip':'10.203.6.1','serverIp':'10.203.5.1','portSta':18200,'portEnd':18220})
    n2=sql("SELECT * FROM node WHERE name='second-lease-node'")[0]
    cfg2=pathlib.Path('/tmp/agent2-config.json');cfg2.write_text(json.dumps({'addr':'http://10.203.7.1:6365','secret':n2['secret'],'statePath':'/tmp/agent2-state.json','apply':True,'allowInsecure':True,'intervalSeconds':1,'useSessions':True}))
    agent2=start(['ip','netns','exec','router2',str(AGENT),'--config',str(cfg2)],'agent2.log');wait(lambda:sql('SELECT status FROM node WHERE id=%s',(n2['id'],))[0]['status']==1)
    api('engine/capabilities',{'nodeId':n2['id']})
    lt=tunnel(n2,'shared-credit-second-node')
    sql('INSERT INTO user(user,pwd,role_id,exp_time,flow,num,created_time,status,flow_reset_time,in_flow,out_flow) VALUES(%s,%s,1,%s,1,1000,%s,1,0,%s,0)',('shared_credit','unused',now+3600000,now,1073741824-65536))
    shared=sql("SELECT id FROM user WHERE user='shared_credit'")[0]['id']
    for tid in [t['id'],lt['id']]:sql('INSERT INTO user_tunnel(user_id,tunnel_id,speed_id,num,flow,flow_reset_time,exp_time,status) VALUES(%s,%s,NULL,100,1000,0,%s,1)',(shared,tid,now+3600000))
    sf1=forward(t,'shared-credit-first',18020,shared,1);sf2=forward(lt,'shared-credit-second',18200,shared,1,target='10.203.5.2:19000')
    wait(lambda:sql('SELECT COUNT(*) n FROM engine_credit_lease WHERE user_id=%s',(shared,))[0]['n']>0)
    reserved=sql('SELECT COALESCE(SUM(reserved_bill),0) n FROM engine_credit_lease WHERE user_id=%s AND closed=0',(shared,))[0]['n']
    check('two nodes cannot reserve the same remaining user quota',0<reserved<=65536)
    flood_code="import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(.01)\nfor _ in range(100):\n s.sendto(b'x'*1000,('GATEWAY',PORT))\n try:s.recv(2048)\n except socket.timeout:pass"
    clients=[]
    for namespace,gateway,port in [('client','10.203.1.1',18020),('client2','10.203.6.1',18200)]:
        clients.append(subprocess.Popen(['ip','netns','exec',namespace,'python3','-c',flood_code.replace('GATEWAY',gateway).replace('PORT',str(port))]))
    for client in clients:assert client.wait(timeout=10)==0
    wait(lambda:usage_total(sf1['id'])+usage_total(sf2['id'])>0);time.sleep(1.2)
    total=sql('SELECT in_flow+out_flow n FROM user WHERE id=%s',(shared,))[0]['n']
    check('concurrent bidirectional kernel credit stays within the shared 64 KiB remainder',total<=1073741824 and usage_total(sf1['id'])+usage_total(sf2['id'])<=65536)
    # Consume the sub-datagram tail after the coordinator renews the same
    # cumulative reservation. A denied large packet must not fake extra quota.
    small="import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(.001)\nfor _ in range(100):\n s.sendto(b'x',('GATEWAY',PORT))\n try:s.recv(100)\n except socket.timeout:pass"
    for _ in range(3):
        for namespace,gateway,port in [('client','10.203.1.1',18020),('client2','10.203.6.1',18200)]:cmd('ip','netns','exec',namespace,'python3','-c',small.replace('GATEWAY',gateway).replace('PORT',str(port)))
        time.sleep(1.1)
    check('exhausted shared budget blocks both forwarding nodes',probe(18020,'blocked')=='tcp_udp_blocked' and cmd('ip','netns','exec','client2','python3','-c',"import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(.5);s.sendto(b'test',('10.203.6.1',18200))\ntry:s.recv(100);raise AssertionError('quota bypass')\nexcept socket.timeout:print('blocked')")=='blocked')
    api('forward/delete',{'id':sf1['id']});api('forward/delete',{'id':sf2['id']});agent2.terminate();agent2.wait(timeout=5)
    # Real existing GOST binary regression on a separate logical node/port.
    g=node('legacy-gost','gost');gd=pathlib.Path('/tmp/gost');gd.mkdir();(gd/'config.json').write_text(json.dumps({'addr':'ws://10.203.3.1:6365','secret':g['secret']}));(gd/'gost.json').write_text('{}')
    gost_binary='gost-arm64' if os.uname().machine in ['aarch64','arm64'] else 'gost-amd64'
    gost_path=pathlib.Path('/build/gost') if pathlib.Path('/build/gost').exists() else ROOT/'go-gost'/gost_binary
    gost=start(['ip','netns','exec','router',str(gost_path)],'gost.log',str(gd));wait(lambda:sql('SELECT status FROM node WHERE id=%s',(g['id'],))[0]['status']==1)
    gt=tunnel(g,'legacy-gost','gost')
    sql('INSERT INTO user_tunnel(user_id,tunnel_id,speed_id,num,flow,flow_reset_time,exp_time,status) VALUES(%s,%s,NULL,100,1000,0,%s,1)',(normal,gt['id'],now+3600000))
    mixed=api('forward/create',{'name':'reject-shared-legacy','tunnelId':gt['id'],'remoteAddr':'10.203.2.2:19000','inPort':18012,'strategy':'fifo'},normal,1,expect=False)
    check('a leased shared-quota owner cannot silently add a legacy forwarding peer',mixed['code']!=0 and probe(18002)=='tcp_udp_ok')
    gf=forward(gt,'legacy-regression',18001);check('real legacy GOST adapter still forwards TCP/UDP',probe(18001)=='tcp_udp_ok')
    wait(lambda:usage_total(gf['id'])>0,15);check('legacy GOST traffic reporting still updates the original ledger')
    conflict=api('forward/create',{'name':'occupied-gost-port','tunnelId':t['id'],'remoteAddr':'10.203.2.2:19000','inPort':18001},expect=False)
    check('iptables rejects a port occupied by GOST without shadowing it',conflict['code']!=0 and probe(18001)=='tcp_udp_ok')
    reverse_conflict=api('forward/create',{'name':'occupied-iptables-port','tunnelId':gt['id'],'remoteAddr':'10.203.2.2:19000','inPort':18002},expect=False)
    check('GOST cannot take a port reserved by its co-located iptables peer',reverse_conflict['code']!=0 and probe(18002)=='tcp_udp_ok')
    socket_owner=start(['ip','netns','exec','router','python3','-m','http.server','18010','--bind','0.0.0.0'],'unmanaged-listener.log');time.sleep(.3)
    occupied=api('forward/create',{'name':'unmanaged-listener','tunnelId':t['id'],'remoteAddr':'10.203.2.2:19000','inPort':18010},expect=False)
    check('agent rejects a listener occupied outside the panel',occupied['code']!=0 and probe(18002)=='tcp_udp_ok')
    api('forward/pause',{'id':gf['id']});check('legacy pause uses existing GOST command',probe(18001,'blocked')=='tcp_udp_blocked')
    api('forward/resume',{'id':gf['id']});check('legacy resume remains functional',probe(18001)=='tcp_udp_ok');api('forward/delete',{'id':gf['id']})
    # Wrong engine identity must fail without starting a second rules manager.
    wrong_url='http://127.0.0.1:6365/system-info?type=1&engine=kernel&secret='+g['secret']
    req=urllib.request.Request(wrong_url,headers={'Upgrade':'websocket','Connection':'Upgrade','Sec-WebSocket-Key':base64.b64encode(os.urandom(16)).decode(),'Sec-WebSocket-Version':'13'})
    rejected=False
    try:urllib.request.urlopen(req,timeout=3)
    except urllib.error.HTTPError as e:rejected=e.code==403
    check('engine identity mismatch rejected',rejected)
    if os.getenv('FLUX_TEST_SCALE')=='1':
        # Exercise the actual Java DB-driven reconciler, not only the Go batch
        # API. Together with the two live normal forwards this totals 10k.
        sql('UPDATE node SET port_end=60000 WHERE id=%s',(n['id'],))
        bulk=[(1,'admin','foundation-scale-'+str(i),t['id'],20000+i,'10.203.2.2:19000','fifo',now,now,1) for i in range(9998)]
        with db.cursor() as c:c.executemany('INSERT INTO forward(user_id,user_name,name,tunnel_id,in_port,remote_addr,strategy,created_time,updated_time,status) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)',bulk)
        started=time.monotonic();submitted=api('engine/reconcile',{'nodeId':n['id']})['data'];assert submitted.get('id'),submitted
        wait(lambda:api('engine/batch-status',{'nodeId':n['id'],'id':submitted['id']})['data']['status']=='succeeded',180)
        check('real Java reconciler cold-applies 10k desired forwards through one batch',probe(29997)=='tcp_udp_ok' and len([v for v in json.loads(pathlib.Path('/tmp/flux-agent-state.json').read_text())['rules'].values() if not v.get('deleted')])==10000)
        cold=time.monotonic()-started
        sql("DELETE FROM forward WHERE name LIKE 'foundation-scale-%%'")
        cleanup_started=time.monotonic()
        submitted=api('engine/reconcile',{'nodeId':n['id']})['data'];assert submitted.get('id'),submitted
        cleanup_submit=time.monotonic()-cleanup_started
        wait(lambda:api('engine/batch-status',{'nodeId':n['id'],'id':submitted['id']})['data']['status']=='succeeded',180)
        check('real Java bulk reconciliation removes 9998 orphans and keeps live forwards',probe(18002)=='tcp_udp_ok' and probe(29997,'blocked')=='tcp_udp_blocked')
        cleanup=time.monotonic()-cleanup_started
        (OUT/'panel-scale.json').write_text(json.dumps({'forwards':10000,'cold_seconds':cold,'cleanup_seconds':cleanup,'cleanup_submit_seconds':cleanup_submit,'cleanup_wait_seconds':cleanup-cleanup_submit,'total_seconds':time.monotonic()-started},indent=2))
        time.sleep(1.2)
        live_state=json.loads(pathlib.Path('/tmp/flux-agent-state.json').read_text())
        check('active quota leases continue renewing after 10k reconciliation cleanup',probe(18002)=='tcp_udp_ok' and all(not live_state['leases'][str(f['id'])+'_'+str(normal)+'_'+str(permission)]['closed'] for f in [nf1,nf2]))
    # A new short-lived permission is enforced by the agent while the panel
    # process is completely stopped. Older, still-valid forwards remain live.
    # After the 10k run this namespace retains a large durable settlement
    # outbox. Give creation time to finish before exercising the expiry itself.
    scale_test=os.getenv('FLUX_TEST_SCALE')=='1'
    offline_keeper=forward(t,'offline-unlimited-keeper',18005) if scale_test else None
    et=tunnel(n,'offline-expiration');deadline=int(time.time()*1000)+(30000 if scale_test else 5000)
    sql('INSERT INTO user_tunnel(user_id,tunnel_id,speed_id,num,flow,flow_reset_time,exp_time,status) VALUES(%s,%s,NULL,100,1000,0,%s,1)',(normal,et['id'],deadline))
    ef=forward(et,'offline-expiration',18004,normal,1);probe(18004)
    connections=(OUT/'agent.log').read_text().count('kernel agent connected')
    panel.kill();panel.wait(timeout=5);time.sleep(31 if scale_test else max(0,(deadline-int(time.time()*1000))/1000)+1)
    check('local expiry blocks TCP/UDP while the panel is stopped',probe(18004,'blocked')=='tcp_udp_blocked')
    check('control outage preserves still-valid forwarding',probe(18005 if scale_test else 18002)=='tcp_udp_ok')
    if scale_test:check('expired offline credit closes ordinary forwards despite later permission expiry',probe(18002,'blocked')=='tcp_udp_blocked' and probe(18003,'blocked')=='tcp_udp_blocked')
    log=open(OUT/'panel.log','a');panel=subprocess.Popen(['java','-Xmx192m','-XX:ActiveProcessorCount=1','-jar',str(JAR)],stdout=log,stderr=subprocess.STDOUT,env=env);processes.append(panel)
    wait(lambda:urllib.request.urlopen('http://127.0.0.1:6365/flow/test',timeout=1).status==200,90)
    wait(lambda:(OUT/'agent.log').read_text().count('kernel agent connected')>connections,20)
    wait(lambda:sql('SELECT status FROM forward WHERE id=%s',(ef['id'],))[0]['status']==0,20)
    check('panel restart reconnects and converges the expired forwarding state')
    api('forward/delete',{'id':ef['id']})
    if offline_keeper:api('forward/delete',{'id':offline_keeper['id']})
    completed=True
    print('ALL CHECKS PASSED',len(checks),flush=True)
except Exception:
    import traceback;traceback.print_exc()
    for f in ['agent.log','agent2.log','panel.log','gost.log']:
        p=OUT/f
        if p.exists():print('LOG',f,p.read_text(errors='replace')[-7000:])
    raise
finally:
    link_bytes={}
    try:
        links=json.loads(cmd('ip','-n','router','-s','-j','link','show'))
        for link in links:
            stats=link.get('stats64',link.get('stats',{}));link_bytes[link['ifname']]={'rx':stats.get('rx',{}).get('bytes',0),'tx':stats.get('tx',{}).get('bytes',0)}
    except Exception:pass
    checkpoint=pathlib.Path('/tmp/flux-agent-state.json')
    if checkpoint.exists():shutil.copyfile(checkpoint,OUT/'agent-state.json')
    if not completed:
        for name,args in [('failed-filter.txt',['iptables-save','-t','filter']),('failed-native.json',['nft','-j','list','ruleset']),('failed-conntrack.txt',['conntrack','-L'])]:
            try:(OUT/name).write_text(cmd('ip','netns','exec','router',*args))
            except Exception:pass
    (OUT/'result.json').write_text(json.dumps({'artifact_sha256':artifacts,'virtual_link_bytes':link_bytes,'external_forward_test_targets':[],'success':completed,'backend':os.getenv('IPTABLES_BACKEND','nft'),'passed':checks,'count':len(checks)},ensure_ascii=False,indent=2))
    for p in reversed(processes):
        if p.poll() is None:
            p.terminate()
            try:p.wait(timeout=5)
            except subprocess.TimeoutExpired:p.kill();p.wait()
