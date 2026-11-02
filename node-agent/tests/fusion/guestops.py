#!/usr/bin/env python3
"""Fusion's authenticated guest-operations API, scoped to this disposable VM."""
from pathlib import Path
import subprocess,sys
import os
w=Path(os.environ['FLUX_FUSION_WORK']);vmx=os.environ['FLUX_FUSION_VMX']
import json
definition=json.loads((w/'vm-definition.json').read_text());assert definition.get('disposable') is True and definition['vmx']==vmx, 'explicit disposable VM definition required'
base=['/Applications/VMware Fusion.app/Contents/Library/vmrun','-T','fusion','-gu','fluxlab','-gp',(w/'keys/guestops-password').read_text()]
a=sys.argv[1:]
if a[0]=='run':cmd=base+['runScriptInGuest',vmx,'/bin/bash','sudo -n /bin/bash -c '+__import__('shlex').quote(a[1])]
elif a[0]=='push':cmd=base+['copyFileFromHostToGuest',vmx,a[1],a[2]]
elif a[0]=='pull':cmd=base+['copyFileFromGuestToHost',vmx,a[1],a[2]]
else:raise ValueError('run, push or pull only')
p=subprocess.run(cmd,capture_output=True,text=True);print(p.stdout,end='');print(p.stderr,end='',file=sys.stderr);sys.exit(p.returncode)
