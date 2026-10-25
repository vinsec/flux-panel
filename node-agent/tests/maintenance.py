"""Real executable upgrade/backup/rollback interruption checks, no public route."""
from foundation_fixture import *
DONE=False
try:
 if os.getenv('IPTABLES_BACKEND')=='legacy':run(['update-alternatives','--set','iptables','/usr/sbin/iptables-legacy'])
 topology();server=http.server.ThreadingHTTPServer(('10.205.4.1',8000),Handler);server.daemon_threads=True;threading.Thread(target=server.serve_forever,daemon=True).start()
 CONFIG.write_text(json.dumps({'addr':'http://10.205.4.1:8000','secret':SECRET,'statePath':str(STATE),'apply':True,'allowInsecure':True,'intervalSeconds':1}))
 a=agent();apply(spec());assert probe()
 def maintain(action,backup,extra=(),config=CONFIG,success=True):
  command=ns('router',str(BUILD/'flux-agent'),'--config',str(config),'--maintenance',action,'--backup-dir',str(backup),*extra)
  p=subprocess.run(command,text=True,capture_output=True,timeout=40)
  if success:assert p.returncode==0,(action,p.stdout,p.stderr)
  return p
 for phase in ['prepare','quiesced','checkpoint','backedup','settled','cleanup','installed']:
  stop(a);backup=OUT/('interrupted-'+phase)
  p=maintain('migrate',backup,['--test-fault','maintenance:'+phase],success=False);assert p.returncode==82,(phase,p.returncode,p.stderr)
  blocked=subprocess.run(ns('router',str(BUILD/'flux-agent'),'--config',str(CONFIG)),capture_output=True,text=True,timeout=8)
  check('unfinished '+phase+' cannot silently start an Agent',blocked.returncode!=0 and 'pending maintenance' in blocked.stderr)
  maintain('migrate',backup)
  data=state();check('maintenance retry resumes '+phase+' with durable accounting and paused data',data['formatVersion']==3 and not data['rules']['1_1_0']['enabled'] and probe(blocked=True))
  manifest=json.loads((backup/'manifest.json').read_text())
  for name,want in manifest['files'].items():assert hashlib.sha256((backup/name).read_bytes()).hexdigest()==want
  check('backup checksum and protected config at '+phase,(backup/'config.json').stat().st_mode&0o777==0o600)
  a=agent();PANEL.rpc('SetForwardState',{'id':'1_1_0','revision':state()['rules']['1_1_0']['revision']+1,'enabled':True});assert probe()
 # Roll back after additional traffic, keeping latest cumulative totals.
 stop(a);backup=OUT/'online-backup';maintain('backup',backup);a=agent();PANEL.rpc('SetForwardState',{'id':'1_1_0','revision':state()['rules']['1_1_0']['revision']+1,'enabled':True});assert probe();time.sleep(1.2);before=state()['totals']['1_1_0'];stop(a);maintain('rollback',backup);after=state()['totals']['1_1_0'];check('rollback preserves all later cumulative usage',after['up']>=before['up'] and after['down']>=before['down'] and probe(blocked=True))
 # An offline migration retains its guard until the authenticated panel also
 # acknowledges paused desired state; the fake panel deliberately does that.
 a=agent();PANEL.rpc('SetForwardState',{'id':'1_1_0','revision':state()['rules']['1_1_0']['revision']+1,'enabled':True});stop(a);backup=OUT/'offline';maintain('migrate',backup,['--offline']);check('offline upgrade retains a closed guard',state()['maintenancePending'] and probe(blocked=True));a=agent();wait(lambda:not state().get('maintenancePending',False));check('offline upgrade only completes after panel maintenance acknowledgement',probe(blocked=True));stop(a)
 maintain('uninstall',OUT/'uninstall');check('uninstall removes only owned chains and preserves unrelated policy','-A FP_' not in router('iptables-save') and 'keep-unrelated' in router('iptables-save'))
 # Upgrade real historical implementations; no reconstruction of v1 rules in
 # the verifier is used to manufacture a passing migration result.
 for version in ['v1','v2']:
  old=BUILD/('agent-'+version)
  if not old.exists():continue
  oldstate=pathlib.Path('/tmp/legacy-'+version+'.json');oldconfig=pathlib.Path('/tmp/legacy-'+version+'-config.json');oldconfig.write_text(json.dumps({'addr':'http://10.205.4.1:8000','secret':SECRET,'statePath':str(oldstate),'apply':True,'allowInsecure':True,'intervalSeconds':1}));serial=PANEL.serial
  oldprocess=spawn(ns('router',str(old),'--config',str(oldconfig)),'legacy-'+version+'.log');wait(lambda:PANEL.serial>serial);apply(spec());assert probe();wait(lambda:json.loads(oldstate.read_text()).get('totals',{}).get('1_1_0',{}).get('up',0)>0);prior=json.loads(oldstate.read_text());stop(oldprocess)
  maintain('migrate',OUT/('from-'+version),config=oldconfig);current=json.loads(oldstate.read_text());check('real '+version+' migration keeps epoch, monotonic totals and pause',current['epoch']==prior['epoch'] and current['totals']['1_1_0']['up']>=prior['totals']['1_1_0']['up'] and not current['rules']['1_1_0']['enabled'] and probe(blocked=True))
  # Return to an empty owned dataplane for the next historical executable.
  maintain('uninstall',OUT/('retire-'+version),config=oldconfig)
 DONE=True
except Exception:
 traceback.print_exc()
 p=OUT/'agent.log'
 if p.exists():print(p.read_text()[-10000:])
 raise
finally:
 for p in reversed(PROCS):stop(p)
 (OUT/'maintenance-result.json').write_text(json.dumps({'success':DONE,'backend':os.getenv('IPTABLES_BACKEND','nft'),'arch':os.uname().machine,'count':len(CHECKS),'passed':CHECKS,'external_forward_test_targets':[]},indent=2))
