#!/usr/bin/env python3
"""Exercise upstream 1.4.3 -> Go using private Docker networks and a real old GOST.

Checks both an existing MySQL 5.7 database and a dump restored into MySQL 8.
All credentials and records are generated for this disposable test.
"""
import argparse
import hashlib
import json
import pathlib
import subprocess
import time
import uuid

parser = argparse.ArgumentParser()
parser.add_argument('--upstream-sql', required=True, type=pathlib.Path)
parser.add_argument('--legacy-gost', required=True, type=pathlib.Path)
parser.add_argument('--panel-image', default='flux-opensource-panel:local')
parser.add_argument('--evidence', required=True, type=pathlib.Path)
args = parser.parse_args()
args.evidence.mkdir(parents=True, exist_ok=True)
repo = pathlib.Path(__file__).resolve().parents[2]
fixture = 'flux-foundation-verifier:local'
password = 'isolated-legacy-migration-only'
checks = []


def run(command, data=None, timeout=150):
    result = subprocess.run(command, input=data, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError('command failed: ' + ' '.join(command[:4]) + '\n' + result.stderr.decode(errors='replace')[-1200:])
    return result.stdout


def docker(*items, **kwargs):
    return run(['docker', *items], **kwargs)


def check(name, condition=True):
    assert condition, name
    checks.append(name)
    print('PASS', name, flush=True)


def wait(fn, timeout=100):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            value = fn()
            if value:
                return value
        except (RuntimeError, AssertionError, ValueError):
            pass
        time.sleep(.4)
    raise AssertionError('timed out waiting for the isolated service')


for mode in ['in-place', 'copy']:
    prefix = 'flux-migration-' + uuid.uuid4().hex[:8]
    containers = []
    network = prefix + '-internal'
    evidence = args.evidence / mode
    evidence.mkdir(exist_ok=True)
    docker('network', 'create', '--internal', network)

    def start(role, image, options=(), command=()):
        name = prefix + '-' + role
        docker('run', '-d', '--name', name, '--network', network, *options, image, *command)
        containers.append(name)
        return name

    def address(name):
        obj = json.loads(docker('inspect', name))[0]
        return obj['NetworkSettings']['Networks'][network]['IPAddress']

    def sql(container, query):
        return docker('exec', '-i', container, 'sh', '-c',
                      'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec mysql -uroot --batch --raw --skip-column-names flux',
                      data=query.encode()).decode().strip()

    try:
        db = start('mysql57', 'mysql:5.7', ('--platform', 'linux/amd64', '-e', 'MYSQL_ROOT_PASSWORD=' + password, '-e', 'MYSQL_DATABASE=flux', '--network-alias', 'database'))
        wait(lambda: sql(db, 'SELECT 1') == '1')
        sql(db, args.upstream_sql.read_text())
        env = ['-e', 'DB_HOST=database', '-e', 'DB_NAME=flux', '-e', 'DB_USER=root', '-e', 'DB_PASSWORD=' + password,
               '-e', 'JWT_SECRET=' + password, '-e', 'TZ=Asia/Shanghai', '-e', 'LOG_DIR=/app/logs']
        old = start('old-panel', 'bqlpfy/springboot-backend:1.4.3', ('--platform', 'linux/amd64', *env, '--network-alias', 'panel'))
        client = start('client', fixture, command=('sleep', 'infinity'))
        token = ''

        def api(path, data=None):
            code = '''import json,sys,urllib.request
path,body,token=sys.argv[1:]
r=urllib.request.Request('http://panel:6365/api/v1/'+path,data=body.encode(),headers={'Content-Type':'application/json','User-Agent':'Flux-isolated-migration-test',**({'Authorization':token} if token else {})})
v=json.load(urllib.request.urlopen(r,timeout=5))
assert v.get('code')==0,(path,v.get('msg'))
print(json.dumps(v.get('data')))
'''
            return json.loads(docker('exec', client, 'python3', '-c', code, path, json.dumps(data or {}), token))

        login = wait(lambda: api('user/login', {'username': 'admin_user', 'password': 'admin_user'}))
        token = login['token']
        check(mode + ': original panel login works')
        target = start('target', fixture, ('-v', str(repo / 'node-agent/tests/echo_server.py') + ':/echo.py:ro'), ('python3', '/echo.py'))
        node = start('old-node', fixture, ('-v', str(args.legacy_gost.resolve()) + ':/legacy-gost:ro', '-v', str(evidence.resolve()) + ':/evidence'), ('sleep', 'infinity'))
        api('node/create', {'name': 'existing-node', 'ip': address(node), 'serverIp': address(node), 'portSta': 18000, 'portEnd': 18099})
        node_id = int(sql(db, "SELECT id FROM node WHERE name='existing-node'"))
        secret = sql(db, 'SELECT secret FROM node WHERE id=' + str(node_id))
        node_config = {'addr': 'panel:6365', 'secret': secret}
        (evidence / 'config.json').write_text(json.dumps(node_config))
        (evidence / 'config.json').chmod(0o600)
        (evidence / 'gost.json').write_text('{}')
        docker('exec', '-d', '-w', '/evidence', node, 'sh', '-c', 'exec /legacy-gost > /evidence/gost.log 2>&1')
        wait(lambda: sql(db, 'SELECT status FROM node WHERE id=' + str(node_id)) == '1')
        api('tunnel/create', {'name': 'existing-tunnel', 'inNodeId': node_id, 'type': 1, 'flow': 1, 'trafficRatio': 1})
        tunnel_id = int(sql(db, "SELECT id FROM tunnel WHERE name='existing-tunnel'"))
        api('forward/create', {'name': 'existing-forward', 'tunnelId': tunnel_id, 'inPort': 18000, 'remoteAddr': address(target) + ':19000'})
        forward_id = int(sql(db, "SELECT id FROM forward WHERE name='existing-forward'"))
        sql(db, "INSERT INTO user(user,pwd,role_id,exp_time,flow,in_flow,out_flow,flow_reset_time,num,created_time,updated_time,status) SELECT 'migration-user',pwd,1,exp_time,500,12345,67890,1,100,created_time,updated_time,1 FROM user WHERE id=1")
        user_id = int(sql(db, "SELECT id FROM user WHERE user='migration-user'"))
        sql(db, f'INSERT INTO user_tunnel(user_id,tunnel_id,num,flow,flow_reset_time,exp_time,status) VALUES({user_id},{tunnel_id},10,50,1,2727251700000,1)')

        def probe():
            code = '''import socket,sys
for kind in [socket.SOCK_STREAM,socket.SOCK_DGRAM]:
 with socket.socket(socket.AF_INET,kind) as s:
  s.settimeout(2);s.connect((sys.argv[1],18000));s.sendall(b'private-migration-check');assert s.recv(1024)==b'private-migration-check'
print('ok')
'''
            return docker('exec', client, 'python3', '-c', code, address(node)).decode().strip() == 'ok'

        wait(probe)
        check(mode + ': original GOST forwards TCP and UDP')
        node_pid = docker('exec', node, 'pgrep', '-x', 'legacy-gost').strip()
        baseline = sql(db, f'SELECT id,user,pwd,role_id,exp_time,flow,in_flow,out_flow,num,status FROM user WHERE id={user_id}')
        identity = sql(db, f'SELECT id,secret,ip,server_ip,port_sta,port_end FROM node WHERE id={node_id}')
        wait(lambda: int(sql(db, f'SELECT in_flow+out_flow FROM forward WHERE id={forward_id}')) > 0)
        docker('stop', old)
        check(mode + ': existing forwarding continues while the panel is stopped', probe())
        dump = docker('exec', db, 'sh', '-c', 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec mysqldump -uroot --single-transaction --no-tablespaces --set-gtid-purged=OFF flux')
        (evidence / 'database.sql').write_bytes(dump)
        (evidence / 'database.sql').chmod(0o600)
        destination = db
        new_env = list(env)
        if mode == 'copy':
            destination = start('mysql8', 'mysql:8.2', ('-e', 'MYSQL_ROOT_PASSWORD=' + password, '-e', 'MYSQL_DATABASE=flux', '--network-alias', 'new-database'))
            wait(lambda: sql(destination, 'SELECT 1') == '1')
            sql(destination, dump.decode())
            new_env[new_env.index('DB_HOST=database')] = 'DB_HOST=new-database'
        docker('run', '--rm', '--network', network, *new_env, args.panel_image, 'migrate')
        # Repeat explicitly to verify a retry does not duplicate or reset data.
        docker('run', '--rm', '--network', network, *new_env, args.panel_image, 'migrate')
        check(mode + ': migration and retry preserve user balances and node identities',
              sql(destination, f'SELECT id,user,pwd,role_id,exp_time,flow,in_flow,out_flow,num,status FROM user WHERE id={user_id}') == baseline and
              sql(destination, f'SELECT id,secret,ip,server_ip,port_sta,port_end FROM node WHERE id={node_id}') == identity)
        new = start('go-panel', args.panel_image, (*new_env, '--network-alias', 'panel'))
        wait(lambda: api('user/list'))
        check(mode + ': the original login token is accepted by the Go panel')
        wait(lambda: sql(destination, f'SELECT status FROM node WHERE id={node_id}') == '1')
        check(mode + ': original GOST reconnects without restart or key replacement', docker('exec', node, 'pgrep', '-x', 'legacy-gost').strip() == node_pid and probe())
        check(mode + ': rules, grants and legacy engine remain usable', len(api('forward/list')) == 1 and
              sql(destination, f'SELECT engine FROM node WHERE id={node_id}') == 'gost' and
              sql(destination, f'SELECT COUNT(*) FROM user_tunnel WHERE user_id={user_id}') == '1')
        before = int(sql(destination, f'SELECT in_flow+out_flow FROM forward WHERE id={forward_id}'))
        probe()
        wait(lambda: int(sql(destination, f'SELECT in_flow+out_flow FROM forward WHERE id={forward_id}')) > before, 30)
        check(mode + ': usage continues increasing after the switch')
        # Roll back only the application, keeping the latest migrated database.
        docker('stop', new)
        rollback_panel = start('rollback-panel', 'bqlpfy/springboot-backend:1.4.3', ('--platform', 'linux/amd64', *new_env, '--network-alias', 'panel'))
        wait(lambda: api('user/list'))
        check(mode + ': original panel can return against the latest database', probe() and
              sql(destination, f'SELECT id,user,pwd,role_id,exp_time,flow,in_flow,out_flow,num,status FROM user WHERE id={user_id}') == baseline)
        (evidence / 'result.json').write_text(json.dumps({'success': True, 'database': '5.7' if mode == 'in-place' else '5.7 -> 8.2', 'originalNodeProcessPreserved': True}))
    finally:
        for container in containers:
            log = docker('logs', container).decode(errors='replace')
            (evidence / (container.rsplit('-', 1)[-1] + '.log')).write_text(log)
        for container in reversed(containers):
            subprocess.run(['docker', 'rm', '-fv', container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['docker', 'network', 'rm', network], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
(args.evidence / 'result.json').write_text(json.dumps({'success': True, 'checks': checks, 'externalForwardTargets': []}, indent=2))
