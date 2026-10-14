#!/usr/bin/env python3
"""Root-only foreground-TTY probe; no IPC, authentication, or input consumption."""
import datetime
import importlib.util
import json
import os
from pathlib import Path
import select
import subprocess
import sys

os.umask(0o077)
if os.geteuid() != 0:
    raise SystemExit('root_required_for_sudo_tty_preflight')
probe = '''import json, os, select
with open('/dev/tty', 'rb', buffering=0) as tty:
 p=select.poll();p.register(tty.fileno(),select.POLLIN)
 print(json.dumps({'process_group':os.getpgrp(),'foreground_group':os.tcgetpgrp(tty.fileno()),'poll_events':[v for _,v in p.poll(0)]}))
'''
assets = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('label_command', assets/'r3a-label-command.py')
module = importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
receipt = {'observed_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
           'read_only':True,'touch_id_requests':0,'password_prompts':0,
           'input_read_count':0,'secret_values_in_evidence':False}
process = subprocess.run([sys.executable,'-c',probe],capture_output=True,text=True,timeout=5)
receipt['captured_stdio'] = {'exit':process.returncode}
if process.returncode == 0:
    receipt['captured_stdio'].update(json.loads(process.stdout))
terminal = os.open('/dev/tty',os.O_RDWR)
try:
    code,output = module.run([sys.executable,'-c',probe],terminal,timeout=5)
    receipt['isolated_foreground_tty'] = {'exit':code}
    if code == 0:
        receipt['isolated_foreground_tty'].update(json.loads(output))
finally:
    os.close(terminal)
out = assets/'r3a-label-native-preflight.json'
out.write_text(json.dumps(receipt,indent=2)+'\n');os.chown(out,501,20);os.chmod(out,0o600)
print('终端前台进程组核对完成；未调用 helper、未读取键盘输入。',flush=True)
