from foundation_fixture import *
try:
 topology()
 router('iptables','-t','mangle','-A','PREROUTING','-s','10.205.1.2','-d','10.205.3.2','-j','MARK','--set-mark','0xf2000180')
 router('iptables','-t','mangle','-A','PREROUTING','-s','10.205.3.2','-d','10.205.1.2','-j','MARK','--set-mark','0xf2000100')
 router('iptables','-I','FORWARD','1','-m','mark','--mark','0xf2000000/0xff000000','-j','ACCEPT')
 router('ip','link','add','fp4shape','type','ifb');router('ip','link','set','fp4shape','up')
 router('tc','qdisc','add','dev','fp4shape','root','handle','f100:','htb')
 router('tc','class','add','dev','fp4shape','parent','f100:','classid','f100:1','htb','rate','1000mbit')
 for ident in ['64','65']:
  router('tc','class','add','dev','fp4shape','parent','f100:1','classid','f100:'+ident,'htb','rate','10mbit','ceil','10mbit','burst','16000','cburst','16000')
  router('tc','qdisc','add','dev','fp4shape','parent','f100:'+ident,'fq_codel')
 router('tc','filter','add','dev','fp4shape','parent','f100:','protocol','all','pref','9999','matchall','action','drop')
 for iface,mark,ident in [('r1','0xf2000180/0xffffffc0','64'),('r0','0xf2000100/0xffffffc0','65')]:
  router('tc','qdisc','add','dev',iface,'clsact')
  router('tc','filter','add','dev',iface,'egress','protocol','all','pref','49151','handle',mark,'fw','action','skbedit','mark','0x40/0x40','priority','f100:'+ident,'action','mirred','egress','redirect','dev','fp4shape')
 code="import socket,time;s=socket.create_connection(('10.205.3.2',19000),timeout=5);s.settimeout(5);b=b'p'*131072;t=time.monotonic();s.sendall(b);out=b''\nwhile len(out)<len(b):out+=s.recv(len(b)-len(out))\nassert out==b;print(time.monotonic()-t)"
 elapsed=run(ns('client','python3','-c',code));check('owned egress IFB can shape and return TCP without a redirect loop',float(elapsed)<5)
 (OUT/'tc-class.json').write_text(router('tc','-j','-s','class','show','dev','fp4shape'))
 DONE=True
finally:
 for p in reversed(PROCS):stop(p)
 (OUT/'tc-primitive-result.json').write_text(json.dumps({'success':DONE,'passed':CHECKS},indent=2))
