#!/usr/bin/env python3
"""Run after the owner's explicit retry: signed install, then the same attended checklist."""
import os
from pathlib import Path
import subprocess

if os.getuid() != 501:
    raise SystemExit('Run as the Mac owner, without sudo')
assets = Path('/Users/guang/dev/keyvalet/docs/remote-approval-reports/assets')
print('先安装已复现测试通过的签名修复；若提示 sudo，请输入 Mac 管理员密码。', flush=True)
install = subprocess.run(['/usr/bin/sudo', '/usr/bin/python3', str(assets / 'r3a-install-native.py')])
if install.returncode:
    raise SystemExit('签名安装未成功，首次请求未重试。')
print('签名安装完成；继续原先 6–8 分钟清单，先 Mac 凭证认证、再 ndu polkit 密码与一次 GET。', flush=True)
subprocess.run(['/usr/bin/python3', str(assets / 'r3a-first-use.py')], check=True)
