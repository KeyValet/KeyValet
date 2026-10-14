#!/usr/bin/env python3
"""Read-only FD and stack sampling of the two installed processes; no prompts."""
import datetime
import json
import os
import re
import subprocess

if os.geteuid() != 0:
    raise SystemExit('Run in the owner sudo terminal')
report = {'observed_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'ui_requests': 0, 'processes': {}}
for service, domain in [('helper', 'system'), ('agent', 'gui/501')]:
    launch = subprocess.run(['/bin/launchctl', 'print', f'{domain}/dev.keyvalet.{service}'], capture_output=True, text=True)
    match = re.search(r'\n\s*pid = (\d+)', launch.stdout)
    if not match:
        continue
    pid = match[1]
    descriptors = subprocess.run(['/usr/sbin/lsof', '-nP', '-a', '-p', pid, '-U'], capture_output=True, text=True)
    sample = subprocess.run(['/usr/bin/sample', pid, '3', '1', '-file', '/dev/stdout'], capture_output=True, text=True, timeout=20)
    # Sample reports symbol stacks and thread state, never process memory contents.
    report['processes'][service] = {'pid': int(pid), 'unix_fds': descriptors.stdout.splitlines(),
                                   'sample_exit': sample.returncode,
                                   'sample': sample.stdout,
                                   'sample_stderr': sample.stderr[:500]}
print(json.dumps(report, indent=2))
