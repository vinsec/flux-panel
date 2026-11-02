"""VMware hard-power-loss verifier; coordinator is on the Mac outside the guest."""
from pathlib import Path
import subprocess,json,urllib.request,time,hashlib
import os
w=Path(os.environ['FLUX_FUSION_WORK']);vmx=Path(os.environ['FLUX_FUSION_VMX']);definition=json.loads((w/'vm-definition.json').read_text());assert definition.get('disposable') is True and definition['vmx']==str(vmx), 'explicit disposable VM definition required'
out=w/'power-evidence';out.mkdir(exist_ok=True);checks=[]
def run(args,timeout=60):
 p=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
 if p.returncode:raise RuntimeError(p.stdout[-1000:]+p.stderr[-1000:])
 return p.stdout

def ops(command):return run(['python3',str(w/'guestops.py'),'run',command])
def pull(remote,name):run(['python3',str(w/'guestops.py'),'pull',remote,str(out/name)]);return json.loads((out/name).read_text())
def request(path,value=None):
 r=urllib.request.Request('http://172.16.246.1:18090/admin/'+path,data=json.dumps(value).encode() if value is not None else None,headers={'Content-Type':'application/json'})
 # A host-local address: no proxy and no external request.
 return json.load(urllib.request.build_opener(urllib.request.ProxyHandler({})).open(r,timeout=30))
def rpc(typ,data):
 r=request('rpc',{'type':typ,'data':data});assert r['success'],r;return r.get('data')
def wait(fn,seconds=120):
 end=time.monotonic()+seconds;last=None
 while time.monotonic()<end:
  try:
   r=fn()
   if r:return r
  except Exception as e:last=str(e)
  time.sleep(1)
 raise AssertionError('timeout '+str(last))
def check(name,value=True):assert value,name;checks.append(name);print('PASS',name,flush=True)
def snapshot(name):
 ops("python3 -c \"import json,pathlib; s=json.load(open('/var/lib/flux-agent/state.json'));s['observedHostBootId']=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip();pathlib.Path('/home/fluxlab/power-snapshot.json').write_text(json.dumps(s))\"")
 return pull('/home/fluxlab/power-snapshot.json',name)
def probe(port,blocked=False):ops(f"ip netns exec p1client python3 /opt/flux-p1/guest/power-probe.py {port}"+(' blocked' if blocked else ''))
try:
 wait(lambda:request('status')['online']);ops('systemctl stop systemd-timesyncd.service || true');ops('date -u -s @'+str(int(time.time())));request('policy',{'id':'2_2_3','totalGranted':65536,'validForMillis':60000})
 for identity,port,limited in [('1_1_0',18000,False),('2_2_3',18001,True)]:
  rpc('ApplyForward',{'schemaVersion':3,'id':identity,'revision':1,'enabled':True,'leaseRequired':limited,'listen':{'host':'10.230.1.1','port':port},'targets':[{'endpoint':{'host':'10.230.2.2','port':19000},'weight':1}]})
 wait(lambda:request('status')['policies']['2_2_3']['grant']);probe(18000);probe(18001);time.sleep(2)
 request('policy',{'id':'3_2_3','totalGranted':524288,'validForMillis':15000})
 rpc('ApplyForward',{'schemaVersion':3,'id':'3_2_3','revision':1,'enabled':True,'leaseRequired':True,'listen':{'host':'10.230.1.1','port':18002},'targets':[{'endpoint':{'host':'10.230.2.2','port':19000},'weight':1}]})
 wait(lambda:request('status')['policies']['3_2_3']['grant']);probe(18002)
 ops('date -u -s @'+str(int(time.time())-3600));time.sleep(18);probe(18002,True)
 check('backward wall-clock step does not extend monotonic kernel credit expiry')
 ops('date -u -s @'+str(int(time.time())))

 before=snapshot('before-power.json');coordinator=request('status');(out/'coordinator-before.json').write_text(json.dumps(coordinator,indent=2))
 check('real helper/network services forward on private veth with one 64 KiB reservation',before['totals']['2_2_3']['up']+before['totals']['2_2_3']['down']>0)
 boot=before['observedHostBootId'];epoch=before['epoch'];serial=coordinator['serial']
 run(['/Applications/VMware Fusion.app/Contents/Library/vmrun','stop',str(vmx),'hard'])
 check('Fusion hard stop removes the entire guest without a graceful shutdown',str(vmx) not in run(['/Applications/VMware Fusion.app/Contents/Library/vmrun','list']))
 # Give each boot its own serial file so Fusion does not ask to overwrite a log.
 text=vmx.read_text();text=__import__('re').sub(r'serial0.fileName = ".*"','serial0.fileName = "console-power-recovery-'+str(time.time_ns())+'.log"',text);vmx.write_text(text)
 run(['/Applications/VMware Fusion.app/Contents/Library/vmrun','start',str(vmx),'gui']);wait(lambda:request('status')['serial']>serial,180)
 after=snapshot('after-power.json');new=request('status');(out/'coordinator-after.json').write_text(json.dumps(new,indent=2))
 check('whole-VM reboot changes the kernel boot ID and preserves the accounting epoch',after['observedHostBootId']!=boot and after['epoch']==epoch)
 for identity,u in coordinator['maxUsage'].items():
  recovered=after['totals'][identity];assert recovered['up']>=u['up'] and recovered['down']>=u['down']
 check('cumulative usage is at least the last externally acknowledged durable watermark',not new['regressions'])
 check('old quota is not reissued to a new guest boot',new['policies']['2_2_3']['grant']['bootId']==coordinator['policies']['2_2_3']['grant']['bootId'])
 probe(18001,True);check('limited TCP/UDP remain closed after reconnect without a new reservation')
 probe(18000);check('unlimited forwarding recovers through systemd and the real helper')
 check('recovery explicitly reports possible uncheckpointed loss',after['recovery']['possibleLoss'])
 (out/'power-result.json').write_text(json.dumps({'success':True,'checks':checks,'scope':'Fusion virtual hard power-off; host hardware power was not removed','externalForwardTestTargets':[]},indent=2))
except Exception:
 (out/'power-result.json').write_text(json.dumps({'success':False,'checks':checks},indent=2));raise
