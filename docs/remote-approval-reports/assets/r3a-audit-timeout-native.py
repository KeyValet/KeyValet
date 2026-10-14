#!/usr/bin/env python3
"""One installed read-only Directive timeout and late receipt; metadata-only evidence."""
import datetime
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import signal
import sqlite3
import subprocess
import time

if os.geteuid() != 0:
    raise SystemExit('run_in_owner_admin_terminal')
os.umask(0o077)
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
ASSETS = Path(__file__).resolve().parent
CLI = '/usr/local/lib/keyvalet/bin/kv-cli'
PEER = '01M4S8KJ48BSMNK1S4BEGT07FC'
LEGACY_ID = '01M4TNJG10T64E6D72NQ0VMM7A'
RELAY = 'gui/501/dev.keyvalet.relay'
PLIST = '/Library/LaunchAgents/dev.keyvalet.relay.plist'
DB = 'file:/var/db/keyvalet/remote/approvals.sqlite3?mode=ro'
receipt = {'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
           'credential_operations': 0, 'keyvalet_touch_id_requests': 0,
           'query_attempts': 0, 'secret_values_in_evidence': False}
started = time.monotonic()
relay_stopped = False


def interrupted(_signal, _frame):
    raise RuntimeError('native_timeout_verification_interrupted')


for signal_name in (signal.SIGHUP, signal.SIGTERM):
    signal.signal(signal_name, interrupted)


def public_id(value):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9A-HJKMNP-TV-Z]{26}', value):
        raise RuntimeError('invalid_public_identifier')
    return value


def command(arguments, timeout=30):
    return subprocess.run(arguments, capture_output=True, text=True, timeout=timeout)


def issued():
    with sqlite3.connect(DB, uri=True) as db:
        return [{'id': public_id(row[0]), 'peer': public_id(row[1]), 'issued_at': row[2], 'result_ok': row[3]}
                for row in db.execute("SELECT id,peer,issued_at,result_ok FROM issued_directives WHERE peer=? AND op='query_grants'", [PEER])]


def local_events(identifier):
    with sqlite3.connect(DB, uri=True) as db:
        rows = db.execute("SELECT entry_json FROM remote_audit WHERE json_extract(entry_json,'$.id')=? ORDER BY seq", [identifier])
        result = []
        for (raw,) in rows:
            value = json.loads(raw)
            if value.get('op') not in ('directive_issued', 'directive_wait_timeout', 'directive_result'):
                continue
            entry = {key: value[key] for key in ('op', 'ts_unix', 'audit_seq', 'ok') if key in value}
            entry['id'] = public_id(value['id'])
            entry['peer'] = public_id(value['peer'])
            if value.get('directive_op') == 'query_grants':
                entry['directive_op'] = 'query_grants'
            digest = value.get('directive_hash')
            if isinstance(digest, str) and re.fullmatch(r'[0-9a-f]{64}', digest):
                entry['directive_hash'] = digest
            if value.get('state') == 'unconfirmed':
                entry['state'] = 'unconfirmed'
            if value.get('reason') == 'directive_result_timeout':
                entry['reason'] = 'directive_result_timeout'
            result.append(entry)
        return result


def restore_relay():
    global relay_stopped
    if relay_stopped:
        process = command(['/bin/launchctl', 'bootstrap', 'gui/501', PLIST])
        receipt['relay_restore_exit'] = process.returncode
        if process.returncode == 0:
            relay_stopped = False
        else:
            raise RuntimeError('relay_restore_failed')


try:
    before = {row['id'] for row in issued()}
    # Pause only this Mac's delivery process, preserving both helpers and the private agent.
    # The read-only command's original expiry/nonce/tier are never modified.
    stopped = command(['/bin/launchctl', 'bootout', RELAY])
    receipt['relay_pause_exit'] = stopped.returncode
    if stopped.returncode:
        raise RuntimeError('relay_pause_failed')
    relay_stopped = True
    receipt['query_attempts'] = 1
    wait_started = time.monotonic()
    try:
        process = command([CLI, '--lang', 'en', 'remote', PEER, 'grants', '--json'], timeout=30)
        receipt['query_wait_s'] = round(time.monotonic() - wait_started, 6)
        receipt['query_cli_exit'] = process.returncode
        reply = json.loads(process.stdout)
        receipt['query_error_code'] = 'directive_result_timeout' if reply.get('error', {}).get('code') == 'directive_result_timeout' else 'unexpected_native_query_outcome'
    finally:
        restore_relay()
    if receipt['query_cli_exit'] != 4 or receipt['query_error_code'] != 'directive_result_timeout':
        raise RuntimeError('expected_wait_timeout_not_observed')
    new = [row for row in issued() if row['id'] not in before]
    if len(new) != 1:
        raise RuntimeError('native_query_identifier_not_unique')
    identifier = new[0]['id']
    receipt['directive_id'] = identifier
    until = time.monotonic() + 30
    while time.monotonic() < until:
        row = next(row for row in issued() if row['id'] == identifier)
        if row['result_ok'] is not None:
            receipt['late_result_ok'] = bool(row['result_ok'])
            receipt['late_result_elapsed_s'] = round(time.monotonic() - wait_started, 6)
            break
        time.sleep(.5)
    if receipt.get('late_result_ok') is not True:
        raise RuntimeError('late_verified_query_result_not_observed')
    receipt['issuer_events'] = local_events(identifier)
    waits = [event for event in receipt['issuer_events'] if event['op'] == 'directive_wait_timeout']
    if len(waits) != 1 or waits[0].get('state') != 'unconfirmed':
        raise RuntimeError('bound_native_wait_event_not_observed')
    # Existing installed query receiver; use SELECT only and emit a count, never raw rows.
    remote = 'import sqlite3,json; d=sqlite3.connect("file:/var/lib/keyvalet/remote/approvals.sqlite3?mode=ro",uri=True); i=' + repr(identifier) + '; print(json.dumps({"directive_applied_rows":d.execute("SELECT count(*) FROM directives WHERE id=? AND op=? AND ok=1",(i,"query_grants")).fetchone()[0],"directive_applied_events":d.execute("SELECT count(*) FROM remote_audit WHERE json_extract(entry_json,\'$.id\')=? AND json_extract(entry_json,\'$.op\')=?",(i,"directive_applied")).fetchone()[0]}))'
    import shlex
    process = command(['/usr/bin/sudo', '-n', '-u', 'guang', '/usr/bin/ssh', '-T', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5', 'ndu',
                       'sudo -n /usr/bin/python3 -c ' + shlex.quote(remote)], timeout=15)
    if process.returncode:
        raise RuntimeError('receiver_readback_unavailable')
    receipt['receiver_counts'] = json.loads(process.stdout)
    if receipt['receiver_counts'] != {'directive_applied_rows': 1, 'directive_applied_events': 1}:
        raise RuntimeError('native_query_application_count_mismatch')
    print('已安装只读查询：等待超时有指令 ID，恢复后收到真实回执，ndu 应用 1 次。', flush=True)
    spec = importlib.util.spec_from_file_location('audit_project', ASSETS / 'r3a-audit-report.py')
    audit_project = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(audit_project)
    process = command([CLI, '--lang', 'en', 'audit', '--remote', '--since', '2026-10-13T05:26:00Z', '--limit', '200', '--json'], timeout=150)
    receipt['audit_cli_exit'] = process.returncode
    if process.returncode not in (0, 3):
        raise RuntimeError('native_authenticated_audit_unavailable')
    value = json.loads(process.stdout)
    receipt['audit'] = audit_project.project(value)
    receipt['findings'] = [{key: finding[key] for key in ('kind', 'id', 'issuer', 'receiver', 'problem', 'fields')}
                           for finding in value['result']['comparison']['findings']]
    for finding in receipt['findings']:
        for key in ('id', 'issuer', 'receiver'):
            public_id(finding[key])
    outcomes = value['result'].get('directive_outcomes', [])
    receipt['legacy_directive_outcome'] = [{key: outcome[key] for key in
        ('id', 'issuer', 'receiver', 'directive_op', 'wait_timeout_recorded', 'result_ok')}
        for outcome in outcomes if outcome.get('id') == LEGACY_ID]
    if not receipt['audit']['two_endpoint_snapshots'] or receipt['audit']['unavailable_count']:
        raise RuntimeError('authenticated_endpoint_audit_incomplete')
    if any(finding['id'] == identifier for finding in receipt['findings']):
        raise RuntimeError('late_native_query_audit_did_not_match')
    receipt['native_timeout_case_passed'] = True
    print('全量审计：匹配 ' + str(receipt['audit']['matched']) + '，差异 ' + str(receipt['audit']['findings_count']) + '；旧历史差异保留。', flush=True)
except (RuntimeError, ValueError, KeyError, StopIteration, subprocess.TimeoutExpired, sqlite3.Error, KeyboardInterrupt) as error:
    receipt['fixed_error'] = str(error) if isinstance(error, RuntimeError) else 'native_timeout_verification_interrupted'
    print('实机段已停止，保存实际结果，不自动重发查询。', flush=True)
finally:
    if relay_stopped:
        try:
            restore_relay()
        except (RuntimeError, subprocess.TimeoutExpired):
            receipt['relay_restore_failed'] = True
    receipt['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    receipt['elapsed_s'] = round(time.monotonic() - started, 6)
    path = ASSETS / ('r3a-audit-timeout-native-' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '.json')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as output:
        output.write(json.dumps(receipt, indent=2) + '\n')
        output.flush()
        os.fsync(output.fileno())
        os.fchown(output.fileno(), 501, 20)
if not receipt.get('native_timeout_case_passed'):
    raise SystemExit(1)
