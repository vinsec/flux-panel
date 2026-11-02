#!/usr/bin/env python3
"""Assemble already-built node programs into an immutable, checked bundle."""
import argparse,hashlib,json,pathlib,shutil
p=argparse.ArgumentParser();p.add_argument('--directory',required=True,type=pathlib.Path);p.add_argument('--source',default='source-checkout');p.add_argument('--dirty',action='store_true');p.add_argument('--gost-proof',type=pathlib.Path);a=p.parse_args()
root=pathlib.Path(__file__).resolve().parent;out=a.directory.resolve();out.mkdir(parents=True,exist_ok=True)
proof=json.loads((a.gost_proof or root/'gost-compatibility.json').read_text())
for arch in ['amd64','arm64']:
 agent=out/('flux-agent-linux-'+arch);managed=out/('gost-managed-linux-'+arch)
 if not agent.is_file() or not managed.is_file():p.error('missing program '+arch)
 legacy=out/('gost-linux-'+arch)
 if not legacy.exists():shutil.copyfile(managed,legacy)
 entry=proof.get(arch,{})
 if hashlib.sha256(legacy.read_bytes()).hexdigest()!=entry.get('sha256') or not entry.get('ws') or not entry.get('wss'):p.error('GOST compatibility evidence does not match '+arch)
 for f in [agent,managed,legacy]:f.chmod(0o755)
for name in ['install.sh','flux-agent.service','flux-kernel.service','flux-agent-tmpfiles.conf','flux-kernel-local-shaping.conf','flux-local-shaping-prepare.service']:shutil.copyfile(root/name,out/name)
(out/'gost-wss-evidence.json').write_text(json.dumps(proof,indent=2)+'\n')
manifest={'format':1,'sourceCommit':a.source,'sourceDirty':a.dirty,'engines':['kernel','gost'],'kernelBackends':['nftables'],'stateVersion':8,'managedGost':True,'forwardingModes':['kernel','gost'],'requiresExplicitDatabaseMigration':['001-forward-engines.sql','002-engine-foundation.sql','003-engine-p1.sql','004-node-kernel-backend.sql','005-native-only.sql','006-go-panel-runtime.sql','007-managed-agent.sql']}
(out/'release.json').write_text(json.dumps(manifest,indent=2)+'\n')
allowed={f'{prefix}-linux-{arch}' for prefix in ['flux-agent','gost-managed','gost'] for arch in ['amd64','arm64']}|{'install.sh','flux-agent.service','flux-kernel.service','flux-agent-tmpfiles.conf','flux-kernel-local-shaping.conf','flux-local-shaping-prepare.service','gost-wss-evidence.json','release.json','SHA256SUMS','MANIFEST.sha256'}
if any(f.name not in allowed or not f.is_file() or f.is_symlink() for f in out.iterdir()):p.error('unexpected files in node package')
checks=''.join(hashlib.sha256(f.read_bytes()).hexdigest()+'  '+f.name+'\n' for f in sorted(out.iterdir()) if f.name not in ['SHA256SUMS','MANIFEST.sha256'])
(out/'SHA256SUMS').write_text(checks);pin=hashlib.sha256(checks.encode()).hexdigest();(out/'MANIFEST.sha256').write_text(pin+'\n');print(json.dumps({'manifestSha256':pin,'engines':['kernel','gost']}))
