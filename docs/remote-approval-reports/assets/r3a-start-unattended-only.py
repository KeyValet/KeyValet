#!/usr/bin/env python3
"""Attended repair install and the remaining T2 case; never repeat prior successes."""
import json
import os
from pathlib import Path
import subprocess

if os.getuid() != 501:
    raise SystemExit('run_as_mac_owner_without_sudo')
os.umask(0o077)
assets = Path(__file__).resolve().parent
print('本段只补无人值守；系统密码仅在 Terminal 输入。', flush=True)
if subprocess.run(['/usr/bin/sudo','-v']).returncode:
    raise SystemExit('admin_authentication_failed')
for name in ('r3a-label-preflight.py','r3a-install-owner-ui.py'):
    if subprocess.run(['/usr/bin/sudo','-n','/usr/bin/python3',str(assets/name)]).returncode:
        raise SystemExit('prepared_install_or_tty_preflight_failed')
receipts = sorted(assets.glob('r3a-owner-ui-install-*.json'),key=lambda p:p.stat().st_mtime)
if not receipts or json.loads(receipts[-1].read_text()).get('owner_ipc_ok') is not True:
    raise SystemExit('installed_owner_ipc_not_verified')
print('修复包与 IPC 已核对；下一步确认 T2、按 Touch ID，再亲自输入两次完整标签。', flush=True)
process = subprocess.run(['/usr/bin/python3',str(assets/'r3a-controls.py'),'--unattended-only'])
receipts = sorted(assets.glob('r3a-controls-*.json'),key=lambda p:p.stat().st_mtime)
final = json.loads(receipts[-1].read_text()) if receipts else {}
complete = final.get('resume_unattended_only') is True and not final.get('fixed_error') and final.get('unattended_observed') is True and final.get('final_unattended') is False and final.get('final_mode') == 'per_use'
raise SystemExit(0 if process.returncode == 0 and complete else 1)
