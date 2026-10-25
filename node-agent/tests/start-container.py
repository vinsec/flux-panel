"""Bounded local Docker start, tolerating a stalled Desktop event stream.

Starting an already running container is idempotent; no service restart is used.
Only call this helper for disposable containers created by run-local.sh.
"""
import subprocess,sys,time,json
name=sys.argv[1]
assert name.startswith('flux-iptables-test-')
clients=[];deadline=time.monotonic()+15;retry=time.monotonic()+1
def launch():clients.append(subprocess.Popen(['docker','start',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL))
try:
    launch()
    while time.monotonic()<deadline:
        try:r=subprocess.run(['docker','inspect',name,'--format','{{json .State}}'],text=True,capture_output=True,timeout=3)
        except subprocess.TimeoutExpired:
            if len(clients)<2:launch()
            continue
        if r.returncode==0:
            state=json.loads(r.stdout)
            if state['Running'] or state['StartedAt']!='0001-01-01T00:00:00Z':sys.exit(0)
        if time.monotonic()>=retry and len(clients)<2:launch()
        time.sleep(.2)
    raise RuntimeError('disposable container did not start: '+name)
finally:
    for p in clients:
        if p.poll() is None:
            p.kill();p.wait()
