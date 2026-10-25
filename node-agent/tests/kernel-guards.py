"""Fail-closed smoke checks, disposable --network none container only.

Run with the same NET_ADMIN/SYS_ADMIN setup as run-local.sh and /build mounted.
No service is contacted: every case must fail before the control client starts.
"""
import json, os, pathlib, subprocess

assert not any('default' in line for line in subprocess.check_output(['ip','route'],text=True).splitlines())
backend=os.getenv('IPTABLES_BACKEND','nft')
if backend=='legacy':subprocess.check_call(['update-alternatives','--set','iptables','/usr/sbin/iptables-legacy'])
def run(*args):return subprocess.check_output(list(args),text=True).strip()
run('ip','netns','add','guard')
def ns(*args):return run('ip','netns','exec','guard',*args)
ns('sh','-c','mount -o remount,rw /proc/sys && sysctl -w net.ipv4.ip_forward=1')
root=pathlib.Path('/tmp/guards');root.mkdir()
config=root/'config.json';config.write_text(json.dumps({'addr':'http://10.205.0.1:9','secret':'isolated-guard-only','statePath':str(root/'state.json'),'apply':True,'allowInsecure':True}))
checks=[]
def reject(name,message):
    p=subprocess.run(['ip','netns','exec','guard','/build/flux-agent','--config',str(config)],capture_output=True,text=True,timeout=6)
    assert p.returncode and message in p.stderr,(name,p.returncode,p.stderr)
    checks.append(name);print('PASS',name,flush=True)

ns('ipset','create','FPV2_BIND','hash:ip')
reject('foreign set is not adopted','exists without v2 ownership/type')
ns('ipset','destroy','FPV2_BIND')
ns('iptables','-t','mangle','-N','FP_MARK')
ns('iptables','-t','mangle','-A','FP_MARK','-m','comment','--comment','flux-owner:v1','-j','RETURN')
reject('live v1 requires explicit migration','live v1 rules detected')
ns('iptables','-t','mangle','-F','FP_MARK');ns('iptables','-t','mangle','-X','FP_MARK')
ns('iptables','-t','mangle','-A','PREROUTING','-m','mark','--mark','0xf1123400/0xffffff00','-j','RETURN')
reject('token-valued external mark conflict is detected','reserved connmark namespace')
ns('iptables','-t','mangle','-F','PREROUTING')
ns('iptables','-t','nat','-N','FP_Nabc')
ns('iptables','-t','nat','-A','FP_Nabc','-p','tcp','-j','DNAT','--to-destination','10.205.2.2:9')
ns('iptables','-t','nat','-A','FP_Nabc','-m','comment','--comment','flux-owner:v2','-j','RETURN')
before=ns('iptables-save','-t','nat')
reject('lost state with zero counters but an owned NAT trie is refused','persistent state missing while owned NAT rules exist')
assert [l for l in before.splitlines() if not l.startswith('#')]==[l for l in ns('iptables-save','-t','nat').splitlines() if not l.startswith('#')]
checks.append('guard failure preserves the existing NAT rules')
result={'backend':backend,'success':True,'count':len(checks),'passed':checks,'external_forward_test_targets':[]}
pathlib.Path('/evidence/guards.json').write_text(json.dumps(result,indent=2))
print(json.dumps(result),flush=True)
