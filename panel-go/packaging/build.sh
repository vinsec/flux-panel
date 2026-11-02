#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT="${1:-$ROOT/.build/release}"
GO_BIN="${FLUX_GO_BIN:-go}"
mkdir -p "$OUTPUT"
OUTPUT="$(cd "$OUTPUT" && pwd)"
cd "$ROOT"
# Caller can select an already cached toolchain; never download one implicitly.
export GOTOOLCHAIN=local GOPROXY=off
"$GO_BIN" version
for arch in arm64 amd64;do
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" "$GO_BIN" build -trimpath -buildvcs=false -ldflags='-s -w' -o "$OUTPUT/flux-panel-linux-$arch" ./cmd/panel
done
cp packaging/Dockerfile "$OUTPUT/Dockerfile"
cp ../gost.sql "$OUTPUT/gost.sql"
mkdir -p "$OUTPUT/migrations"
# Do not retain the retired reverse migration when reusing an older output directory.
rm -f "$OUTPUT/migrations/005-native-only-rollback.sql"
cp ../database/migrations/*.sql "$OUTPUT/migrations/"
python3 - "$OUTPUT" "$GO_BIN" <<'PY'
from pathlib import Path
import hashlib,json,subprocess,sys
out=Path(sys.argv[1]);root=Path.cwd()
files={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(out.glob('flux-panel-linux-*'))}
paths=sorted([*root.rglob('*.go'),root/'go.mod',root/'go.sum',*root.joinpath('internal/panel/captcha-assets').glob('*')])
h=hashlib.sha256()
for p in paths:
 if not any(x in p.parts for x in ['.build','.test-work']):
  h.update(str(p.relative_to(root)).encode()+b'\0'+p.read_bytes()+b'\0')
bundle={str(p.relative_to(out)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(out.rglob('*')) if p.is_file() and p.name not in ['release.json','SHA256SUMS'] and not p.name.startswith('flux-panel-linux-')}
manifest={'component':'flux-panel-go','java_baseline':'a08e3d8','source_tree_sha256':h.hexdigest(),
 'go_version':subprocess.check_output([sys.argv[2],'version'],text=True).strip(),
 'git_head':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
 'source_dirty':bool(subprocess.check_output(['git','status','--porcelain'],text=True).strip()),
 'files':files,'bundle_files':bundle,'supported_engines':['gost','kernel'],'kernel_backends':['nftables'],
 'migration_policy':'explicit only; 001–007; no ledger reset','deployed':False}
(out/'release.json').write_text(json.dumps(manifest,indent=2)+'\n')
checksums={**files,**bundle,'release.json':hashlib.sha256((out/'release.json').read_bytes()).hexdigest()}
(out/'SHA256SUMS').write_text(''.join(f'{digest}  {name}\n' for name,digest in sorted(checksums.items())))
print('Built pinned local artifacts; no deployment performed')
PY
