#!/usr/bin/env python3
"""Start only after the owner's explicit checklist acknowledgement."""
import json
import os
from pathlib import Path
import subprocess

if os.getuid() != 501:
    raise SystemExit('run_as_mac_owner_without_sudo')
assets = Path(__file__).resolve().parent
ci = json.loads((assets / 'r3a-se-child-closure-ci5-summary.json').read_text())
if ci.get('checks') != {'fmt': 0, 'clippy': 0, 'build': 0, 'test': 0}:
    raise SystemExit('producer_checks_not_ready')
if not (assets / 'r3a-se-child-signed-build.json').is_file():
    raise SystemExit('signed_producer_package_not_ready')
print('安装子进程错误保真修复；系统密码只在 Terminal 输入，之后直接补 SE 与吊销。', flush=True)
if subprocess.run(['/usr/bin/sudo', '-v']).returncode:
    raise SystemExit('admin_authentication_failed')
result = subprocess.run(['/usr/bin/sudo', '-n', '/usr/bin/python3', str(assets / 'r3a-install-se-child-mac.py')])
if result.returncode:
    raise SystemExit('producer_install_not_completed_no_automatic_retry')
result = subprocess.run(['/usr/bin/python3', str(assets / 'r3a-native-remaining.py'), '--refresh-presence', '--after-delivery'])
raise SystemExit(result.returncode)
