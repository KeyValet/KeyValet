#!/usr/bin/env python3
"""Read private control metadata using an existing sudo timestamp; never prompt."""
import datetime
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys

os.umask(0o077)
assets = Path(__file__).resolve().parent
if sys.argv[1:] == ['--root'] and os.geteuid() == 0:
    result = {}
    with open('/dev/tty', 'rb', buffering=0) as terminal:
        result['tty'] = {'process_group': os.getpgrp(),
                         'foreground_group': os.tcgetpgrp(terminal.fileno())}
    database = sqlite3.connect('file:/var/db/keyvalet/remote/approvals.sqlite3?mode=ro', uri=True)
    records = []
    for seq, raw in database.execute('SELECT seq,entry_json FROM remote_audit ORDER BY seq DESC LIMIT 300'):
        value = json.loads(raw)
        if value.get('ts_unix', 0) < 1791902181:
            continue
        row = {key: value[key] for key in ('op', 'ts_unix', 'approval_id', 'peer',
                                          'device_id', 'approval_level', 'ok', 'event',
                                          'id', 'jti', 'max_tier') if key in value}
        for key in ('reason', 'error'):
            text = value.get(key)
            if isinstance(text, str) and re.fullmatch('[a-z_:-]{1,128}', text):
                row[key] = text
        row['audit_seq'] = seq
        records.append(row)
    result['audit'] = list(reversed(records))
    database.close()
    print(json.dumps(result))
elif not sys.argv[1:] and os.getuid() == 501:
    result = {'observed_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'read_only': True, 'touch_id_requests': 0, 'password_prompts': 0,
              'secret_values_in_evidence': False}
    process = subprocess.run(['/usr/bin/sudo', '-n', '/usr/bin/python3', str(Path(__file__).resolve()), '--root'],
                             capture_output=True, text=True, timeout=20)
    result['exit'] = process.returncode
    if process.returncode == 0:
        result.update(json.loads(process.stdout))
    else:
        result['fixed_error'] = 'existing_admin_timestamp_unavailable'
    out = assets / 'r3a-controls-native-readback.json'
    out.write_text(json.dumps(result, indent=2) + '\n')
    print('只读控制面收据已保存；未触发密码或 Touch ID 提示。', flush=True)
else:
    raise SystemExit('invalid_readback_context')
