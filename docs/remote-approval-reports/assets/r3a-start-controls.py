#!/usr/bin/env python3
"""One attended Terminal: install the reviewed signed package, then native controls."""
import json
import os
from pathlib import Path
import resource
import subprocess

if os.getuid()!=501:raise SystemExit('Run as the Mac owner, without sudo')
os.umask(0o077)
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
assets=Path(__file__).resolve().parent
print('先安装已通过四项 CI 的签名修复包；如提示 Mac 管理员密码，请只在此 Terminal 输入。',flush=True)
if subprocess.run(['/usr/bin/sudo','-v']).returncode:raise SystemExit('admin_auth_failed')
result=subprocess.run(['/usr/bin/sudo','-n','/usr/bin/python3',str(assets/'r3a-install-controls.py')])
if result.returncode:raise SystemExit('signed_controls_install_failed')
paths=sorted(assets.glob('r3a-controls-install-*.json'),key=lambda p:p.stat().st_mtime,reverse=True)
if not paths or json.loads(paths[0].read_text()).get('owner_ipc_ok') is not True:
    raise SystemExit('installed_owner_ipc_not_ready')
print('新包与 owner IPC 已核对；现在进入控制面清单。',flush=True)
raise SystemExit(subprocess.run(['/usr/bin/python3',str(assets/'r3a-controls.py')]).returncode)
