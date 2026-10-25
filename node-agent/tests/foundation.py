from foundation_fixture import *
try:
 if os.getenv('IPTABLES_BACKEND')=='legacy':run(['update-alternatives','--set','iptables','/usr/sbin/iptables-legacy'])
 topology();server=http.server.ThreadingHTTPServer(('10.205.4.1',8000),Handler);server.daemon_threads=True;threading.Thread(target=server.serve_forever,daemon=True).start()
 CONFIG.write_text(json.dumps({'addr':'http://10.205.4.1:8000','secret':SECRET,'statePath':str(STATE),'apply':True,'allowInsecure':True,'intervalSeconds':1}));a=agent()
 info=PANEL.rpc('GetCapabilities')['data'];check('negotiated protocol versions and explicit disabled DNS/IPv6',info['capabilities']['protocolVersions']==[1,2] and not info['capabilities']['features']['ipv6'] and not info['capabilities']['features']['dns'])
 s=spec();s.update(schemaVersion=2,listen={'kind':'ip','host':'10.205.1.1','port':18000},target={'kind':'ip','host':'10.205.3.2','port':19000},protocols=['tcp','udp']);apply(s);check('structured endpoint forwards real TCP and UDP',probe())
 bad=spec('2_1_0',18001);bad.update(schemaVersion=2,listen={'kind':'ip','host':'10.205.1.1','port':18001},target={'kind':'hostname','host':'origin.example','port':443});check('unimplemented target capabilities rejected without modifying live forwarding',not apply(bad,False)['success'] and probe())
 # Fragmented UDP crosses a lower-MTU intermediate router and is reassembled.
 run(['ip','-n','transit','link','set','m1','mtu','1280']);run(['ip','-n','target','link','set','t0','mtu','1280'])
 # Capture the natural IPv4 fragmentation-needed response before the client
 # caches the PMTU. The error source is the intermediate router, not target.
 pmtu='''import socket,struct
r=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP);r.settimeout(3)
u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);u.setsockopt(socket.IPPROTO_IP,10,2);u.sendto(b'p'*1400,('10.205.1.1',18000))
while True:
 b,peer=r.recvfrom(4096);off=(b[0]&15)*4
 if b[off:off+2]==b'\\x03\\x04':assert struct.unpack('!H',b[off+6:off+8])[0]==1280;print(peer[0]);break'''
 source=run(ns('client','python3','-c',pmtu));check('PMTU ICMP error from an intermediate router reaches the client',source in ['10.205.2.2','10.205.1.1'])
 (OUT/'pmtu.json').write_text(json.dumps({'intermediateRouter':'10.205.2.2','clientObservedSource':source,'mtu':1280}))
 check('fragmented UDP survives DNAT/SNAT over an intermediate lower MTU',probe(size=4000))
 PANEL.rpc('SetForwardState',{'id':'1_1_0','revision':2,'enabled':False});check('pause blocks TCP and fragmented UDP despite external RELATED ACCEPT',probe(blocked=True,size=4000));PANEL.rpc('SetForwardState',{'id':'1_1_0','revision':3,'enabled':True});check('resume recovers the fragmented data path',probe(size=4000))
 # Build the complete 10k configuration in one transaction, then remove it.
 desired=[spec(str(i+100)+'_1_0',20000+i) for i in range(9999)]
 started=time.monotonic();b={'id':'native-10k','specs':desired};result=job(b);elapsed=time.monotonic()-started;check('10k forwarding cold delta completes as one asynchronous job',result['status']=='succeeded')
 check('10k configuration retains constant regular-packet classifier/filter paths',sum(l.startswith('-A FP_MARK ') for l in router('iptables-save','-t','mangle').splitlines())==5 and probe())
 before=state()['generation'];check('duplicate batch identity returns the same committed generation',job(b)['status']=='succeeded' and state()['generation']==before)
 after='';seen=set();generation=None
 while True:
  data={'after':after,'limit':500}
  if generation is not None:data['generation']=generation
  page=PANEL.rpc('GetEngineStatePage',data)['data'];generation=page['generation'];seen.update(x['id'] for x in page['items']);after=page.get('next','')
  if not after:break
 check('generation-consistent paginated snapshot includes all 10k rules',len(seen)==10000)
 batch_timing={}
 for count in [10000,1000]:
  current=state()['rules'];ids=['1_1_0']+[ident for ident in sorted(current) if ident!='1_1_0'][:count-1]
  paused=[dict(current[ident],revision=current[ident]['revision']+1,enabled=False) for ident in ids]
  tick=time.monotonic();assert job({'id':'native-pause-'+str(count),'specs':paused})['status']=='succeeded';batch_timing[str(count)+'_pause_seconds']=time.monotonic()-tick
  snapshot=state()['rules'];check(str(count)+'-forward atomic pause blocks existing data paths',probe(blocked=True) and all(not snapshot[ident]['enabled'] for ident in ids))
  resumed=[dict(value,revision=value['revision']+1,enabled=True) for value in paused]
  tick=time.monotonic();assert job({'id':'native-resume-'+str(count),'specs':resumed})['status']=='succeeded';batch_timing[str(count)+'_resume_seconds']=time.monotonic()-tick
  snapshot=state()['rules'];check(str(count)+'-forward atomic resume restores TCP and UDP',probe() and all(snapshot[ident]['enabled'] for ident in ids))
 # Populate connection state across several adjacent token prefixes before
 # deletion. Surviving token 1 must retain its original conntrack mapping.
 run(ns('client','python3','-c',"import socket\nfor port in range(20000,20064):\n s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(2);s.sendto(b'bulk-ct',('10.205.1.1',port));assert s.recv(64)==b'bulk-ct';s.close()"))
 current=state()['rules'];removes=[{'id':x['id'],'revision':current[x['id']]['revision']+1,'deleted':True} for x in desired];delete_started=time.monotonic();check('bulk delete reconciles without leaving a live orphan dispatch',job({'id':'native-delete','specs':removes})['status']=='succeeded' and probe())
 cleanup_seconds=time.monotonic()-delete_started
 ct=router('conntrack','-L','-f','ipv4','--mark','0xf1000000/0xff000000')
 check('compressed bulk conntrack cleanup removes revoked flows and preserves the survivor',all('mark=4043309312' in line for line in ct.splitlines() if line.startswith(('tcp ','udp '))) and cleanup_seconds<15)
 wait(lambda:len(state().get('ackCounters',{}))>=19998,15)
 stop(a);retired=state();oldtime=int(time.time()*1000)-120000
 for key in retired.get('counterRetiredAt',{}):retired['counterRetiredAt'][key]=oldtime
 for key in retired.get('retiredAt',{}):retired['retiredAt'][key]=oldtime
 STATE.write_text(json.dumps(retired));a=agent()
 traffic=subprocess.Popen(ns('client','python3','-c',"import socket,time;s=socket.create_connection(('10.205.1.1',18000),timeout=2);s.settimeout(1)\nfor _ in range(1500):\n s.sendall(b'g'*64);b=b''\n while len(b)<64:b+=s.recv(64-len(b))\n assert b==b'g'*64;time.sleep(.001)"))
 gc_started=time.monotonic();collected=PANEL.rpc('CollectCounters',timeout=40)['data']['removed'];gc_seconds=time.monotonic()-gc_started;assert traffic.wait(timeout=10)==0
 check('native batched GC reclaims 9999 retired tokens while other traffic continues',collected==19998 and len(state()['rules'])==1 and len(state().get('freeTokens',[]))>=9999 and probe())
 (OUT/'gc-scale.json').write_text(json.dumps({'removedCounters':collected,'freedTokens':len(state().get('freeTokens',[])),'seconds':gc_seconds},indent=2))
 (OUT/'scale.json').write_text(json.dumps({'forwards':10000,'cold_delta_seconds':elapsed,'cleanup_seconds':cleanup_seconds,'snapshot_count':len(seen),**batch_timing},indent=2))
 # Each killed process leaves only an old or new complete committed revision.
 for i,point in enumerate(['prepared','quiesced','kernel','credits','conntrack','counters','checkpoint','committed','activated']):
  stop(a);a=agent(point);old=state()['rules']['1_1_0']['revision'];new=spec(revision=old+1);new['targetPort']=19001 if state()['rules']['1_1_0']['targetPort']==19000 else 19000
  try:PANEL.rpc('ApplyForward',new,timeout=2)
  except AssertionError:pass
  wait(lambda:a.poll()==82);a=agent();want=old+1 if i>=6 else old;check('native crash recovery at '+point,state()['rules']['1_1_0']['revision']==want and probe())
 # Byte credit is shared by both directions and cannot be reset by replay.
 limited=spec('50_2_3',18001);limited['leaseRequired']=True;PANEL.quota=65536;apply(limited);wait(lambda:'50_2_3' in state().get('leases',{}));check('reserved credit allows bidirectional data',probe(18001))
 time.sleep(.2)
 request=PANEL.rpc('RequestCredit')['data'];grant=dict(PANEL.grant);grant['generation']+=1;grant['requestSequence']=request['sequence'];PANEL.grant=grant
 budget_before=router('ipset','save','FPV3_CREDIT')
 ack={'epoch':request['epoch'],'sequence':request['sequence'],'usage':request['usage'],'counters':request.get('counters',[]),'leaseWatermarks':request.get('leases',[]),'grants':[grant],'serviceId':'50_2_3'}
 PANEL.rpc('InstallCredit',ack)
 budget_after=router('ipset','save','FPV3_CREDIT')
 check('real TTL-only renewal preserves the permanent byte budget',budget_before==budget_after and probe(18001))
 flood="import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(.01)\nfor _ in range(100):\n s.sendto(b'x'*1000,('10.205.1.1',18001))\n try:s.recv(2048)\n except socket.timeout:pass"
 run(ns('client','python3','-c',flood));check('kernel credit exhausts while business desired state is still enabled',probe(18001,True) and state()['rules']['50_2_3']['enabled'])
 time.sleep(1.2);check('duplicate grant cannot reopen exhausted credit',probe(18001,True));wait(lambda:sum(state()['totals'].get('50_2_3',{}).get(k,0) for k in ['up','down'])>0);u=state()['totals']['50_2_3'];check('denied attempts do not overrun or inflate billed credit',u['up']+u['down']<=65536)
 check('foreign firewall policy and chain survive all transitions','keep-unrelated' in router('iptables-save') and '-P FORWARD DROP' in router('iptables','-S','FORWARD'))
 DONE=True
except Exception:
 traceback.print_exc()
 p=OUT/'agent.log'
 if p.exists():print(p.read_text()[-12000:])
 raise
finally:
 for p in reversed(PROCS):stop(p)
 (OUT/'foundation-result.json').write_text(json.dumps({'success':DONE,'backend':os.getenv('IPTABLES_BACKEND','nft'),'arch':os.uname().machine,'count':len(CHECKS),'passed':CHECKS,'external_forward_test_targets':[]},indent=2))
