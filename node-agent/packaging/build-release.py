#!/usr/bin/env python3
"""Build a checksum-pinned offline release; never publishes or deploys it."""
import argparse,hashlib,json,pathlib,shutil,subprocess,tarfile
p=argparse.ArgumentParser();p.add_argument('--output',required=True,type=pathlib.Path);p.add_argument('--gost-amd64',type=pathlib.Path);p.add_argument('--gost-arm64',type=pathlib.Path);p.add_argument('--gost-proof',type=pathlib.Path);a=p.parse_args()
root=pathlib.Path(__file__).resolve().parents[2];out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip();dirty=bool(subprocess.check_output(['git','status','--porcelain'],cwd=root,text=True).strip())
for arch in ['amd64','arm64']:
 env=__import__('os').environ.copy();env.update(CGO_ENABLED='0',GOOS='linux',GOARCH=arch)
 subprocess.run(['go','build','-trimpath','-buildvcs=false','-o',str(out/('flux-agent-linux-'+arch)),'./cmd/flux-agent'],cwd=root/'node-agent',env=env,check=True)
shutil.copyfile(root/'node-agent/packaging/flux-agent-tmpfiles.conf',out/'flux-agent-tmpfiles.conf');shutil.copyfile(root/'node-agent/packaging/install.sh',out/'install.sh');shutil.copyfile(root/'node-agent/packaging/flux-agent.service',out/'flux-agent.service')
proof={}
if a.gost_amd64 or a.gost_arm64:
 if not(a.gost_amd64 and a.gost_arm64 and a.gost_proof):p.error('both GOST binaries and native WS/WSS verification evidence are required')
 proof=json.loads(a.gost_proof.read_text())
 for arch,source in [('amd64',a.gost_amd64),('arm64',a.gost_arm64)]:
  expected=proof.get(arch,{})
  sha=hashlib.sha256(source.read_bytes()).hexdigest()
  if expected.get('sha256')!=sha or not expected.get('ws') or not expected.get('wss'):p.error('unverified GOST binary '+arch)
  shutil.copyfile(source,out/('gost-linux-'+arch))
 (out/'gost-wss-evidence.json').write_text(json.dumps(proof,indent=2))
manifest={'format':1,'sourceCommit':commit,'sourceDirty':dirty,'engines':['iptables']+(['gost'] if proof else []),'stateVersion':3,'requiresExplicitDatabaseMigration':['001-forward-engines.sql','002-engine-foundation.sql']}
(out/'release.json').write_text(json.dumps(manifest,indent=2)+'\n')
lines=[]
for f in sorted(out.iterdir()):
 if f.is_file():lines.append(hashlib.sha256(f.read_bytes()).hexdigest()+'  '+f.name)
checks='\n'.join(lines)+'\n';(out/'SHA256SUMS').write_text(checks);pin=hashlib.sha256(checks.encode()).hexdigest();(out/'MANIFEST.sha256').write_text(pin+'\n')
archive=out.with_suffix('.tar.gz')
with tarfile.open(archive,'w:gz') as t:t.add(out,arcname=out.name)
print(json.dumps({'directory':str(out),'archive':str(archive),'manifestSha256':pin,'published':False}))
