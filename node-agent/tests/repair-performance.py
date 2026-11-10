"""Paired private-veth regression against the pre-fix executable."""
from foundation_fixture import *
import shutil,statistics
ROWS=[]
CONFIRM=os.getenv('FLUX_REPAIR_LATENCY_CONFIRM')=='1'
def cpu(pid):
 f=pathlib.Path(f'/proc/{pid}/stat').read_text().split();return (int(f[13])+int(f[14]))/os.sysconf('SC_CLK_TCK')
def client(args):return json.loads(run(ns('client','taskset','-c','2',str(BUILD/'bench-peer'),'-host','10.205.1.1')+args,timeout=40))
try:
 topology();spawn(ns('target','taskset','-c','1','iperf3','-s','-p','19102'),'iperf-server.log');spawn(ns('target','taskset','-c','1',str(BUILD/'bench-peer'),'-role','server','-port','19100'),'perf-peer.log')
 server=http.server.ThreadingHTTPServer(('10.205.4.1',8000),Handler);server.daemon_threads=True;threading.Thread(target=server.serve_forever,daemon=True).start()
 write_config({'addr':'http://10.205.4.1:8000','secret':SECRET,'statePath':str(STATE),'apply':True,'allowInsecure':True,'intervalSeconds':1})
 candidate=BUILD/'flux-agent';shutil.copy2(candidate,BUILD/'perf-candidate')
 for policy in [False,True]:
  for round_id,order in enumerate([['baseline','candidate'],['candidate','baseline'],['baseline','candidate']]):
   for version in order:
    shutil.copy2(BUILD/('flux-agent-baseline' if version=='baseline' else 'perf-candidate'),candidate)
    a=agent();os.sched_setaffinity(a.pid,{0});previous=state()['rules'];rules=[]
    for i in range(17):
     ident=f'{i+1}_1_0';s=spec(ident,18000+i,previous.get(ident,{}).get('revision',0)+1);s.update(schemaVersion=5,listen={'host':'10.205.1.1','port':18000+i},targets=[{'endpoint':{'host':'10.205.3.2','port':19100 if i else 19102},'weight':1}],expiresAt=int(time.time()*1000)+138*86400000)
     if policy:s['protocolFilter']={'http':True,'tls':True,'socks':True,'unknown':'allow'}
     rules.append(s)
    start=time.monotonic();j=job({'id':os.urandom(16).hex(),'baseGeneration':state()['generation'],'specs':rules});assert j['status']=='succeeded',j;config_seconds=time.monotonic()-start
    if CONFIRM:client(['-port','18001','-protocol','tcp','-samples','1000','-pace-us','0']);time.sleep(1)
    for fresh,proto in [(False,'tcp'),(False,'udp'),(True,'tcp')]:
     args=['-port','18001','-protocol',proto,'-samples',str(5000 if fresh else 20000) if CONFIRM else '2000','-pace-us',('0' if fresh else '100') if CONFIRM else '0']+(['-fresh'] if fresh else [])
     before=cpu(a.pid);start=time.monotonic();r=client(args);elapsed=time.monotonic()-start;assert r['samples']==(5000 if fresh else 20000) if CONFIRM else r['samples']==2000
     assert r['lost']==0,r;r.pop('values_us',None)
     ROWS.append(dict(version=version,protocol=proto,fresh=fresh,policy=policy,round=round_id,wall_seconds=elapsed,connections_per_second=r['samples']/elapsed if fresh else None,agent_cpu_seconds=cpu(a.pid)-before,config_seconds=config_seconds,**r))
    for reverse in ([] if CONFIRM else [False,True]):
     before=cpu(a.pid);iperf=json.loads(run(ns('client','taskset','-c','2','iperf3','-c','10.205.1.1','-p','18000','-t','4','-P','4','-J')+(['-R'] if reverse else []),timeout=20));assert 'error' not in iperf,iperf;total=iperf['end']['sum_received'];assert total['bytes']>0;r=dict(bits_per_second=total['bits_per_second'],bytes=total['bytes'],seconds=total['seconds'],reverse=reverse)
     ROWS.append(dict(version=version,protocol='bulk',policy=policy,round=round_id,agent_cpu_seconds=cpu(a.pid)-before,**r))
    stop(a);(OUT/'performance-raw.json').write_text(json.dumps(ROWS,indent=2));print('PAIR',version,policy,round_id,flush=True)
 summary=[]
 for policy in [False,True]:
  for profile in (['cold_tcp','tcp','udp'] if CONFIRM else ['cold_tcp','tcp','udp','bulk_up','bulk_down']):
   def select(v):
    return [r for r in ROWS if r['version']==v and r['policy']==policy and ((profile=='cold_tcp' and r['protocol']=='tcp' and r.get('fresh')) or (profile in ['tcp','udp'] and r['protocol']==profile and not r.get('fresh')) or (profile.startswith('bulk') and r['protocol']=='bulk' and r['reverse']==(profile=='bulk_down')))]
   key='connections_per_second' if profile=='cold_tcp' else 'bits_per_second' if profile.startswith('bulk') else 'p95_us'
   b,c=(statistics.median(r[key] for r in select(v)) for v in ['baseline','candidate'])
   summary.append(dict(policy=policy,profile=profile,metric=key,baseline=b,candidate=c,ratio=c/b,baseline_cpu_seconds=statistics.median(r['agent_cpu_seconds'] for r in select('baseline')),candidate_cpu_seconds=statistics.median(r['agent_cpu_seconds'] for r in select('candidate'))))
 (OUT/'performance-summary.json').write_text(json.dumps(summary,indent=2));check('paired three-round TCP/UDP, cold connections and bulk complete without loss',len(ROWS)==(36 if CONFIRM else 60));DONE=True
except Exception:traceback.print_exc();raise
finally:
 for p in reversed(PROCS):stop(p)
 if (BUILD/'perf-candidate').exists():shutil.copy2(BUILD/'perf-candidate',BUILD/'flux-agent')
 (OUT/'performance-result.json').write_text(json.dumps({'success':DONE,'count':len(CHECKS),'passed':CHECKS,'external_forward_test_targets':[]},indent=2))
