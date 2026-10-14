#!/usr/bin/env python3
"""Install the reviewed package, then resume only the unfinished T2 case."""
import json
import os
from pathlib import Path
import resource
import subprocess

if os.getuid() != 501:
    raise SystemExit('run_as_mac_owner_without_sudo')
os.umask(0o077)
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
assets = Path(__file__).resolve().parent
probe = json.loads((assets / 'r3a-label-input-native-diagnostic.json').read_text())
if (probe.get('fake_cli_exit') != 0
        or probe.get('fake_cli_result', {}).get('dummy_line_received') is not True):
    raise SystemExit('native_input_probe_not_verified; no approvals started')
print('原生假 CLI 输入已通过；先安装已核对的签名包，不触发 Touch ID。', flush=True)
if subprocess.run(['/usr/bin/sudo', '-v']).returncode:
    raise SystemExit('admin_authentication_failed')
installed = subprocess.run([
    '/usr/bin/sudo', '-n', '/usr/bin/python3',
    str(assets / 'r3a-install-revocations-mac.py'),
])
if installed.returncode:
    raise SystemExit('reviewed_install_not_completed; no approvals started')
print('安装完成；只补 T2，按 CLI 提示亲自输入两次完整标签 keyvalet。', flush=True)
resumed = subprocess.run([
    '/usr/bin/python3', str(assets / 'r3a-resume-unattended-only.py'),
])
raise SystemExit(resumed.returncode)
