#!/usr/bin/env python3
"""Repository guard: panel installation/build/test entrypoints must be Go-only."""
from pathlib import Path
import subprocess
root=Path(__file__).resolve().parents[2]
tracked=subprocess.check_output(['git','-C',str(root),'ls-files','-z']).decode().split('\0')
violations=[]
for name in tracked:
 p=root/name
 if not p.is_file():continue
 if name.startswith('springboot-backend/') or name.endswith('.java') or p.name in ['pom.xml','mvnw','mvnw.cmd']:
  violations.append(name)
for name in ['panel_install.sh','docker-compose.yml','docker-compose-v4.yml','docker-compose-v6.yml','.github/workflows/docker-build.yml','node-agent/tests/run-local.sh','node-agent/tests/Linux.Dockerfile','node-agent/tests/integration.py','node-agent/tests/node_backend_integration.py','panel-go/packaging/build.sh']:
 s=(root/name).read_text()
 if any(x in s for x in ['springboot-backend','setup-java','mvn ','.jar','FLUX_TEST_PANEL','FLUX_TEST_JAVA']):violations.append('non-Go active entrypoint: '+name)
assert not (root/'docker-compose.override.yml').exists(),'host-specific override must be explicit opt-in'
assert not violations,'\n'.join(violations)
print('Go-only backend source, build, Compose, installer and verifier guard passed')
