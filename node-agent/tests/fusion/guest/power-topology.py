#!/usr/bin/python3
"""Only task-owned veth/netns in this disposable VMware guest."""
import subprocess,pathlib

def run(*args):return subprocess.run(args,check=True,capture_output=True,text=True).stdout
for name in ['p1client','p1target']:
 run('ip','netns','add',name);run('ip','-n',name,'link','set','lo','up')
for a,b,ns,aa,bb in [('p1c','p1r0','p1client','10.230.1.2/24','10.230.1.1/24'),('p1t','p1r1','p1target','10.230.2.2/24','10.230.2.1/24')]:
 run('ip','link','add',a,'type','veth','peer','name',b);run('ip','link','set',a,'netns',ns)
 run('ip','-n',ns,'addr','add',aa,'dev',a);run('ip','-n',ns,'link','set',a,'up');run('ip','addr','add',bb,'dev',b);run('ip','link','set',b,'up')
run('ip','-n','p1client','route','add','10.230.2.0/24','via','10.230.1.1');run('ip','-n','p1target','route','add','10.230.1.0/24','via','10.230.2.1')
assert 'default' not in run('ip','route')
run('iptables','-P','FORWARD','DROP');run('iptables','-N','P1_UNRELATED');run('iptables','-A','P1_UNRELATED','-m','comment','--comment','fusion-preserve','-j','RETURN')
run('iptables','-A','FORWARD','-m','conntrack','--ctstate','ESTABLISHED,RELATED','-j','ACCEPT')
pathlib.Path('/run/p1-topology-ready').touch()
