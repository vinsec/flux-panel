"""ICMP/TCP connectivity through the real restricted helper; private veths only."""
from foundation_fixture import *

try:
 topology()
 server=http.server.ThreadingHTTPServer(('10.205.4.1',8000),Handler);server.daemon_threads=True;threading.Thread(target=server.serve_forever,daemon=True).start()
 shared=pathlib.Path('/tmp/connectivity-helper');shared.mkdir(mode=0o750);os.chown(shared,0,12345)
 cfg={'addr':'http://10.205.4.1:8000','secret':SECRET,'statePath':str(STATE),'apply':True,'allowInsecure':True,'intervalSeconds':1,'kernelBackend':'nftables','helperSocket':str(shared/'kernel.sock')}
 write_config(cfg);CONFIG.chmod(0o644)
 helper=spawn(ns('router','setpriv','--regid=12345','--clear-groups','--bounding-set=-all,+net_admin,+net_raw,+net_bind_service',str(BUILD/'flux-agent'),'--kernel-helper','--helper-user','12345','--config',str(CONFIG)),'helper.log')
 wait(lambda:pathlib.Path(cfg['helperSocket']).exists())
 serial=PANEL.serial;network=spawn(ns('router','setpriv','--reuid=12345','--regid=12345','--clear-groups','--bounding-set=-all',str(BUILD/'flux-agent'),'--config',str(CONFIG)),'network.log');wait(lambda:PANEL.serial>serial and network.poll() is None)
 apply(spec());check('ordinary TCP and UDP forwarding works before probes',probe())
 before=state();count=native_counters('1_1_0')
 def diagnostic(ident='1_1_0'):return PANEL.rpc('ProbeForward',{'id':ident})['data']
 def both(r):
  v=r['results'][0];return v['icmp']['sent']==v['icmp']['received']==4 and v['tcp']['sent']==v['tcp']['received']==2 and v['icmp']['averageTime'] is not None and v['tcp']['averageTime'] is not None
 d=diagnostic();check('default IPv4 checks run four ICMP and two TCP attempts',both(d))
 check('probe capability advertised',PANEL.rpc('GetCapabilities')['data']['capabilities']['features']['connectivityDiagnostics'])
 check('successful ICMP and TCP probes do not consume business accounting',native_counters('1_1_0')==count)
 run(ns('target','nft','add','table','inet','TEST_PROBES'));run(ns('target','nft','add','chain','inet','TEST_PROBES','input','{ type filter hook input priority -5; policy accept; }'))
 run(ns('target','nft','add','rule','inet','TEST_PROBES','input','ip','protocol','icmp','drop'))
 d=diagnostic()['results'][0];check('ICMP timeout retains independently successful TCP data',d['icmp']['received']==0 and d['icmp']['packetLoss']==100 and d['icmp']['averageTime'] is None and d['tcp']['received']==2)
 run(ns('target','nft','flush','chain','inet','TEST_PROBES','input'));run(ns('target','nft','add','rule','inet','TEST_PROBES','input','tcp','dport','19000','reject','with','tcp','reset'))
 d=diagnostic()['results'][0];check('TCP rejection retains independently successful ICMP data',d['icmp']['received']==4 and d['tcp']['received']==0 and d['tcp']['averageTime'] is None)
 run(ns('target','nft','delete','table','inet','TEST_PROBES'))
 for n in ['client','router','transit','target']:run(ns(n,'sysctl','-w','net.ipv6.conf.all.disable_ipv6=0'))
 for n,i,address in [('client','c0','fd25:1::2/64'),('router','r0','fd25:1::1/64'),('router','r1','fd25:2::1/64'),('transit','m0','fd25:2::2/64'),('transit','m1','fd25:3::1/64'),('target','t0','fd25:3::2/64')]:run(['ip','-n',n,'-6','addr','add',address,'dev',i,'nodad'])
 for n in ['router','transit']:run(ns(n,'sysctl','-w','net.ipv6.conf.all.forwarding=1'))
 for n,route in [('client',['default','via','fd25:1::1']),('target',['default','via','fd25:3::1']),('router',['fd25:3::/64','via','fd25:2::2']),('transit',['fd25:1::/64','via','fd25:2::1'])]:run(['ip','-n',n,'-6','route','add',*route])
 spawn(ns('target','python3','-c',"import socket;s=socket.socket(socket.AF_INET6);s.bind(('fd25:3::2',19000));s.listen(32)\nwhile True:c,a=s.accept();c.close()"),'echo6.log');time.sleep(.2)
 s={'schemaVersion':3,'id':'2_1_0','revision':1,'enabled':True,'listeners':[{'host':'fd25:1::1','port':18001,'protocol':'tcp'}],'targets':[{'endpoint':{'host':'fd25:3::2','port':19000},'weight':1}]};apply(s)
 check('IPv6 ICMP checksum and TCP work through restricted helper',both(diagnostic('2_1_0')))
 check('missing rule is rejected',not PANEL.rpc('ProbeForward',{'id':'999_1_0'},success=False)['success'])
 check('arbitrary supplied probe host is rejected',not PANEL.rpc('ProbeForward',{'id':'1_1_0','host':'203.0.113.1'},success=False)['success'])
 check('forwarding and process identity survive connectivity tests',probe() and state()['epoch']==before['epoch'] and helper.poll() is None and network.poll() is None)
 check('network process still has zero capabilities','CapEff:\t0000000000000000' in pathlib.Path('/proc/'+str(network.pid)+'/status').read_text())
 DONE=True
finally:
 for p in reversed(PROCS):stop(p)
 (OUT/'connectivity-result.json').write_text(json.dumps({'success':DONE,'count':len(CHECKS),'checks':CHECKS,'publicTargets':[]},indent=2))
