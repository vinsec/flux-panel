#!/usr/bin/env python3
"""Build a checksum-pinned offline release; never publishes or deploys it."""
import argparse,hashlib,json,pathlib,shutil,subprocess,tarfile
p=argparse.ArgumentParser();p.add_argument('--output',required=True,type=pathlib.Path);p.add_argument('--gost-amd64',type=pathlib.Path);p.add_argument('--gost-arm64',type=pathlib.Path);p.add_argument('--gost-proof',type=pathlib.Path);a=p.parse_args()
root=pathlib.Path(__file__).resolve().parents[2];out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip();dirty=bool(subprocess.check_output(['git','status','--porcelain'],cwd=root,text=True).strip())
for arch in ['amd64','arm64']:
 env=__import__('os').environ.copy();env.update(CGO_ENABLED='0',GOOS='linux',GOARCH=arch)
 subprocess.run(['go','build','-trimpath','-buildvcs=false','-o',str(out/('flux-agent-linux-'+arch)),'./cmd/flux-agent'],cwd=root/'node-agent',env=env,check=True)
for arch in ['amd64','arm64']:
 env=__import__('os').environ.copy();env.update(CGO_ENABLED='0',GOOS='linux',GOARCH=arch,GOTOOLCHAIN='go1.25.4')
 subprocess.run(['go','build','-trimpath','-buildvcs=false','-o',str(out/('gost-managed-linux-'+arch)),'.'],cwd=root/'go-gost',env=env,check=True)
shutil.copyfile(root/'node-agent/packaging/flux-agent-tmpfiles.conf',out/'flux-agent-tmpfiles.conf');shutil.copyfile(root/'node-agent/packaging/install.sh',out/'install.sh');shutil.copyfile(root/'node-agent/packaging/flux-agent.service',out/'flux-agent.service');shutil.copyfile(root/'node-agent/packaging/flux-kernel.service',out/'flux-kernel.service');shutil.copyfile(root/'node-agent/packaging/flux-kernel-local-shaping.conf',out/'flux-kernel-local-shaping.conf');shutil.copyfile(root/'node-agent/packaging/flux-local-shaping-prepare.service',out/'flux-local-shaping-prepare.service')
proof={}
if a.gost_amd64 or a.gost_arm64:
 if not(a.gost_amd64 and a.gost_arm64 and a.gost_proof):p.error('both GOST binaries and native WS/WSS verification evidence are required')
 proof=json.loads(a.gost_proof.read_text())
 for arch,source in [('amd64',a.gost_amd64),('arm64',a.gost_arm64)]:
  expected=proof.get(arch,{})
  sha=hashlib.sha256(source.read_bytes()).hexdigest()
  if expected.get('sha256')!=sha or not expected.get('ws') or not expected.get('wss'):p.error('unverified GOST binary '+arch)
  shutil.copyfile(source,out/('gost-linux-'+arch));(out/('gost-linux-'+arch)).chmod(0o755)
 (out/'gost-wss-evidence.json').write_text(json.dumps(proof,indent=2))
args=['python3',str(root/'node-agent/packaging/finalize-release.py'),'--directory',str(out),'--source',commit]
if dirty:args+=['--dirty']
if a.gost_proof:args+=['--gost-proof',str(a.gost_proof)]
subprocess.run(args,check=True)
pin=(out/'MANIFEST.sha256').read_text().strip()
archive=out.parent/(out.name+'.tar.gz')
with tarfile.open(archive,'w:gz') as t:t.add(out,arcname=out.name)
print(json.dumps({'directory':str(out),'archive':str(archive),'manifestSha256':pin,'published':False}))
