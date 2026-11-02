"""Basic forwards without advanced options; real helper, private netns only."""
from foundation_fixture import *

try:
 topology()
 server=http.server.ThreadingHTTPServer(('10.205.4.1',8000),Handler);server.daemon_threads=True;threading.Thread(target=server.serve_forever,daemon=True).start()
 shared=pathlib.Path('/tmp/diagnostic-helper');shared.mkdir(mode=0o750);os.chown(shared,0,12345)
 cfg={'addr':'http://10.205.4.1:8000','secret':SECRET,'statePath':str(STATE),'apply':True,'allowInsecure':True,'intervalSeconds':1,'kernelBackend':'nftables','helperSocket':str(shared/'kernel.sock')}
 write_config(cfg);CONFIG.chmod(0o644)
 helper=spawn(ns('router','setpriv','--regid=12345','--clear-groups','--bounding-set=-all,+net_admin,+net_raw,+net_bind_service',str(BUILD/'flux-agent'),'--kernel-helper','--helper-user','12345','--config',str(CONFIG)),'helper.log')
 wait(lambda:pathlib.Path(cfg['helperSocket']).exists())
 serial=PANEL.serial
 network=spawn(ns('router','setpriv','--reuid=12345','--regid=12345','--clear-groups','--bounding-set=-all',str(BUILD/'flux-agent'),'--config',str(CONFIG)),'network.log')
 wait(lambda:PANEL.serial>serial and network.poll() is None)
 apply(spec());check('basic numeric-target forward has no advanced options',not state()['rules']['1_1_0'].get('targets'))
 check('TCP and UDP work before diagnostics',probe())
 before=state();count=native_counters('1_1_0')
 for cycle in range(3):
  d=PANEL.rpc('DiagnoseForward',{'id':'1_1_0','probe':False})['data']
  check('basic route-only diagnostic succeeds without helper crash '+str(cycle),not d['probePerformed'] and d['probeCount']==0 and len(d['routes'])==1 and d['routes'][0]['routeEvidence']['available'] and helper.poll() is None)
 check('read-only diagnostic does not consume business counters',native_counters('1_1_0')==count)
 d=PANEL.rpc('DiagnoseForward',{'id':'1_1_0','probe':True})['data']
 check('opt-in private TCP handshake handles basic egress defaults',d['probeCount']==1 and d['routes'][0]['reachable'])
 check('TCP and UDP continue after diagnostics',probe())
 check('diagnostics retain epoch and rule identity',state()['epoch']==before['epoch'] and set(state()['rules'])==set(before['rules']) and helper.poll() is None and network.poll() is None)
 check('missing forward returns an error without crashing helper',not PANEL.rpc('DiagnoseForward',{'id':'999_1_0','probe':False},success=False)['success'] and helper.poll() is None)
 DONE=True
finally:
 for p in reversed(PROCS):stop(p)
 (OUT/'diagnostics-basic-result.json').write_text(json.dumps({'success':DONE,'count':len(CHECKS),'checks':CHECKS,'publicTargets':[]},indent=2))
