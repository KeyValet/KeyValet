#!/usr/bin/env python3
"""Resume only after the real fake-CLI input probe and reviewed install succeed."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

if os.getuid()!=501:raise SystemExit('run_as_mac_owner_without_sudo')
os.umask(0o077)
assets=Path(__file__).resolve().parent
probe=json.loads((assets/'r3a-label-input-native-diagnostic.json').read_text())
if probe.get('fake_cli_exit')!=0 or probe.get('fake_cli_result',{}).get('dummy_line_received') is not True:
    raise SystemExit('native_input_probe_not_verified; no approvals started')
manifest=json.loads((assets/'r3a-executor-revocation-signed-build.json').read_text())
if manifest.get('package_verified') is not True:raise SystemExit('reviewed_package_not_verified')
identifiers={'kv-helper':'helper','kv-cli':'cli','kv-touchid':'touchid','kv-relay-client':'relay-client'}
for name,identifier in identifiers.items():
    path=Path('/usr/local/lib/keyvalet/bin')/name
    if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest()!=manifest['binaries'][name]['sha256']:
        raise SystemExit('reviewed_package_not_installed; no approvals started')
    requirement='=identifier "dev.keyvalet.'+identifier+'" and anchor apple generic and certificate leaf[subject.OU] = "PWCRJPY7YC"'
    p=subprocess.run(['/usr/bin/codesign','--verify','--strict','-R',requirement,str(path)],capture_output=True,timeout=15)
    if p.returncode:raise SystemExit('installed_signature_requirement_failed')
print('签名包与原生输入诊断已核对；这次不重复安装或已成功的控制面用例。',flush=True)
if subprocess.run(['/usr/bin/sudo','-v']).returncode:raise SystemExit('admin_authentication_failed')
p=subprocess.run(['/usr/bin/sudo','-n','/usr/local/lib/keyvalet/bin/kv-cli','devices','list','--json'],capture_output=True,text=True,timeout=15)
try:owner=json.loads(p.stdout)
except ValueError:owner={}
if p.returncode or owner.get('ok') is not True:raise SystemExit('owner_ipc_not_available; no approvals started')
process=subprocess.run(['/usr/bin/python3',str(assets/'r3a-controls.py'),'--unattended-only'])
receipts=sorted(assets.glob('r3a-controls-*.json'),key=lambda p:p.stat().st_mtime)
final=json.loads(receipts[-1].read_text()) if receipts else {}
complete=final.get('resume_unattended_only') is True and not final.get('fixed_error') and final.get('unattended_observed') is True and final.get('final_unattended') is False and final.get('final_mode')=='per_use'
raise SystemExit(0 if process.returncode==0 and complete else 1)
