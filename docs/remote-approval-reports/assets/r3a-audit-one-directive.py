#!/usr/bin/env python3
"""Read one discrepant directive without retaining arguments or signed objects."""
import datetime
import json
import os
from pathlib import Path
import re
import resource
import sqlite3
import subprocess
import sys

os.umask(0o077)
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
assets = Path(__file__).resolve().parent
directive_id = '01M4TNJG10T64E6D72NQ0VMM7A'


def project(value):
    row = {}
    for key in ('op', 'id', 'peer', 'iss', 'directive_op', 'ts_unix',
                'issued_at', 'applied_at', 'ok', 'result_ok', 'event',
                'error', 'reason', 'directive_hash'):
        item = value.get(key)
        if isinstance(item, (bool, int)) or item is None:
            if key in value:
                row[key] = item
        elif isinstance(item, str) and re.fullmatch(r'[A-Za-z0-9_:-]{1,128}', item):
            row[key] = item
    return row


if os.geteuid() == 0 and sys.argv[1:] == ['--root']:
    directory = '/var/db/keyvalet' if sys.platform == 'darwin' else '/var/lib/keyvalet'
    database = sqlite3.connect('file:' + directory + '/remote/approvals.sqlite3?mode=ro', uri=True)
    database.row_factory = sqlite3.Row
    result = {'directive_id': directive_id, 'issued': [], 'received': [], 'audit': []}
    for row in database.execute('SELECT id,peer,op,issued_at,result_ok,result_summary '
                                'FROM issued_directives WHERE id=?', (directive_id,)):
        value = dict(row)
        summary = value.pop('result_summary', None)
        projected = project(value)
        if summary:
            try:
                projected['public_result'] = project(json.loads(summary))
            except (ValueError, TypeError):
                projected['result_summary_available'] = False
        result['issued'].append(projected)
    for row in database.execute('SELECT id,iss,op,applied_at,ok,error '
                                'FROM directives WHERE id=?', (directive_id,)):
        result['received'].append(project(dict(row)))
    for row in database.execute('SELECT seq,entry_json FROM remote_audit '
                                'WHERE instr(entry_json,?)>0 ORDER BY seq', (directive_id,)):
        projected = project(json.loads(row['entry_json']))
        projected['audit_seq'] = row['seq']
        result['audit'].append(projected)
    database.close()
    print(json.dumps(result))
elif os.getuid() == 501 and not sys.argv[1:]:
    result = {'observed_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'read_only': True, 'touch_id_requests': 0, 'password_prompts': 0,
              'secret_values_in_evidence': False}
    process = subprocess.run(['/usr/bin/sudo', '-n', '/usr/bin/python3',
                              str(Path(__file__).resolve()), '--root'],
                             capture_output=True, text=True, timeout=20)
    result['exit'] = process.returncode
    if process.returncode == 0:
        result['mac'] = json.loads(process.stdout)
    else:
        result['fixed_error'] = 'existing_admin_timestamp_unavailable'
    path = assets / 'r3a-audit-one-directive-mac.json'
    path.write_text(json.dumps(result, indent=2) + '\n')
    print('旧指令只读诊断结束；未触发密码或 Touch ID。', flush=True)
else:
    raise SystemExit('invalid_readback_context')
