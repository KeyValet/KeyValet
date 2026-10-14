#!/usr/bin/env python3
"""Expose a kernel process identity, then wait for its attended agent before exec."""
import json
import os
from pathlib import Path
import resource
import sys
import time

resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
os.umask(0o077)
phase = sys.argv[1]
if phase not in ('refresh', 'samples') or os.getuid() == 0:
    raise SystemExit('unknown_acceptance_phase')
if len(sys.argv)>2:
    if phase!='samples' or sys.argv[2:]!=['--wait-in-call-5s']:
        raise SystemExit('unknown_acceptance_wait_budget')
    # Only the caller's initial wait budget changes; no request expiry or auth policy changes.
    os.environ['KEYVALET_WAIT_IN_CALL_S']='5'
d = Path('/tmp/keyvalet-r3a-native')
if d.is_symlink() or d.stat().st_uid != os.getuid():
    raise SystemExit('acceptance_owner_mismatch')
pid = os.getpid()
stat = (Path('/proc')/str(pid)/'stat').read_text()
target = {'pid': pid, 'start_time': int(stat[stat.rfind(')')+2:].split()[19]),
          'uid': os.getuid(), 'parent_pid': os.getppid()}
p = d/(phase+'.pid.new')
with p.open('x') as f:
    json.dump(target, f)
os.replace(p, d/(phase+'.pid'))
ready = d/(phase+'-agent.ready')
deadline = time.monotonic()+30
while time.monotonic() < deadline:
    if ready.exists():
        if ready.is_symlink() or ready.stat().st_uid != os.getuid():
            raise SystemExit('acceptance_owner_mismatch')
        if json.loads(ready.read_text()) == target:
            break
    time.sleep(.05)
else:
    raise SystemExit('polkit_agent_registration_timeout')
os.execv('/usr/local/lib/keyvalet/bin/kv-mcp', ['/usr/local/lib/keyvalet/bin/kv-mcp'])
