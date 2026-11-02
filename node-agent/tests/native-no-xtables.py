"""Native lifecycle with an executable PATH containing no iptables/ipset tools."""
from foundation_fixture import *
import foundation_fixture as fixture
import shutil

try:
 topology()
 server=http.server.ThreadingHTTPServer(('10.205.4.1',8000),Handler);server.daemon_threads=True
 threading.Thread(target=server.serve_forever,daemon=True).start()
 tools=pathlib.Path('/tmp/native-tools');tools.mkdir()
 for name in ['ip','nft','tc','conntrack','uname','cat']:
  source=shutil.which(name);assert source,name;(tools/name).symlink_to(source)
 original_spawn=fixture.spawn
 def isolated_spawn(args,name):
  if str(BUILD/'flux-agent') in args:args=['/usr/bin/env','PATH='+str(tools)]+args
  return original_spawn(args,name)
 fixture.spawn=isolated_spawn
 write_config({'addr':'http://10.205.4.1:8000','secret':SECRET,'statePath':str(STATE),'apply':True,'allowInsecure':True,'intervalSeconds':1})
 a=agent();check('native boot identity remains the real kernel boot ID',state()['bootId']==pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()+'-'+state()['kernelId']);apply(spec());check('native TCP/UDP works without any xtables or ipset executable',probe())
 PANEL.rpc('SetForwardState',{'id':'1_1_0','revision':2,'enabled':False});check('pause remains effective without legacy tools',probe(blocked=True))
 PANEL.rpc('SetForwardState',{'id':'1_1_0','revision':3,'enabled':True});check('resume restores both protocols without legacy tools',probe())
 wait(lambda:state()['totals']['1_1_0']['up']>0)
 before=state();stop(a);a=agent();check('restart preserves native epoch and cumulative usage without legacy tools',state()['epoch']==before['epoch'] and state()['totals']['1_1_0']['up']>=before['totals']['1_1_0']['up'] and probe())
 stop(a)
 run(ns('router','/usr/bin/env','PATH='+str(tools),str(BUILD/'flux-agent'),'--config',str(CONFIG),'--maintenance','uninstall','--backup-dir','/tmp/native-no-tools-backup'))
 check('settled uninstall needs no legacy executable and preserves external firewall','FP_NATIVE' not in router('nft','list','tables') and 'keep-unrelated' in router('iptables-save'))
 DONE=True
finally:
 for p in reversed(PROCS):stop(p)
 (OUT/'native-no-xtables-result.json').write_text(json.dumps({'success':DONE,'passed':CHECKS,'count':len(CHECKS),'externalForwardTestTargets':[]},indent=2))
