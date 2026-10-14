#!/usr/bin/env python3
"""Read-only root diagnostics after the source-token wait; no authentication operations."""
import datetime
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import time

if os.geteuid() != 0:
    raise SystemExit('Root is required for the private audit metadata')
os.umask(0o077)
assets = Path('/Users/guang/dev/keyvalet/docs/remote-approval-reports/assets')
result = {'observed_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'read_only': True, 'touch_id_requests': 0, 'cli': {}, 'audit': {}}
cli = '/usr/local/lib/keyvalet/bin/kv-cli'
for name, args in [('status', ['status', '--json']),
                   ('devices', ['devices', 'list', '--json']),
                   ('approvals', ['approvals', '--json'])]:
    started = time.monotonic()
    process = subprocess.run([cli] + args, capture_output=True, text=True, timeout=30)
    try:
        value = json.loads(process.stdout)
    except ValueError:
        value = {}
    projected = {'exit': process.returncode, 'elapsed_s': round(time.monotonic() - started, 6),
                 'ok': value.get('ok'), 'error_code': value.get('error', {}).get('code')}
    data = value.get('result', {})
    if name == 'status':
        remote = data.get('remote') or {}
        projected['remote'] = {key: remote[key] for key in (
            'relay', 'approvers', 'pending_n', 'grants_n', 'unattended', 'mode') if key in remote}
    elif name == 'devices':
        projected['devices'] = [{key: device[key] for key in (
            'device_id', 'label', 'os', 'revoked', 'caps') if key in device}
            for device in data.get('devices', [])]
    else:
        projected['pending'] = [{key: item[key] for key in (
            'approval_id', 'kind', 'tier', 'min_level', 'exp', 'requested_scope') if key in item}
            for item in data.get('pending', [])]
    result['cli'][name] = projected
database = sqlite3.connect('file:/var/db/keyvalet/remote/approvals.sqlite3?mode=ro', uri=True)
result['pending_rows'] = [dict(zip(('approval_id', 'kind', 'state', 'created_at', 'exp'), row))
                          for row in database.execute(
                              'SELECT id,kind,state,created_at,exp FROM pending_approvals ORDER BY created_at DESC LIMIT 20')]
entries = []
for seq, raw in database.execute('SELECT seq,entry_json FROM remote_audit ORDER BY seq DESC LIMIT 160'):
    value = json.loads(raw)
    entry = {key: value[key] for key in (
        'op', 'event', 'ts_unix', 'ok', 'approval_id', 'kind', 'tier', 'min_level',
        'state', 'approval_level', 'approval_latency_ms', 'peer', 'device_id') if key in value}
    reason = value.get('reason')
    if isinstance(reason, str) and re.fullmatch('[a-z_:-]{1,128}', reason):
        entry['reason'] = reason
    entry['audit_seq'] = seq
    entries.append(entry)
result['audit']['remote'] = list(reversed(entries))
database.close()
path = Path('/var/db/keyvalet/audit.log')
with path.open('rb') as file:
    file.seek(0, 2)
    size = file.tell()
    file.seek(max(0, size - 512 * 1024))
    lines = file.read().splitlines()
entries = []
for line in lines:
    try:
        value = json.loads(line)
    except ValueError:
        continue
    entry = {key: value[key] for key in ('op', 'ok', 'ts', 'ts_unix', 'timestamp') if key in value}
    if value.get('op') == 'presence_updated':
        entry['state'] = value.get('state')
    entries.append(entry)
result['audit']['vault'] = entries[-100:]
out = assets / ('r3a-approval-diagnostics-' + datetime.datetime.now(datetime.timezone.utc).strftime('%H%M%S') + '.json')
out.write_text(json.dumps(result, indent=2) + '\n')
os.chown(out, 501, 20)
os.chmod(out, 0o600)
print('只读审批诊断完成；未发起认证、配对或审批。', flush=True)
