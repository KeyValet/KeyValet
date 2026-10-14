#!/usr/bin/env python3
"""Owner-started install, one read-only timeout case, then genuine OS transitions."""
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
ci = json.loads((assets / 'r3a-audit-presence-ci-summary.json').read_text())
if ci.get('checks') != {'fmt': 0, 'clippy': 0, 'build': 0, 'test': 0} or not ci.get('source_unchanged_during_checks'):
    raise SystemExit('verified_source_snapshot_not_ready')
if not (assets / 'r3a-audit-presence-signed-build.json').is_file():
    raise SystemExit('reviewed_signed_package_not_ready')
print('本段安装审计/在场修复包，并做一次只读查询超时与恢复；KeyValet Touch ID 请求为 0。', flush=True)
print('如要求 Mac 管理员密码，只在此 Terminal 输入；不读取或更新 Graph token。', flush=True)
if subprocess.run(['/usr/bin/sudo', '-v']).returncode:
    raise SystemExit('admin_authentication_failed')
for name in ('r3a-install-audit-presence-mac.py', 'r3a-audit-timeout-native.py'):
    result = subprocess.run(['/usr/bin/sudo', '-n', '/usr/bin/python3', str(assets / name)])
    if result.returncode:
        raise SystemExit('prepared_native_step_not_completed; no automatic retry')
print('只读审计段完成；接下来按 Terminal 提示开启屏保，再完成两轮正常锁屏/解锁。', flush=True)
result = subprocess.run(['/usr/bin/python3', str(assets / 'r3a-presence-transitions.py')])
raise SystemExit(result.returncode)
