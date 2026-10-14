#!/usr/bin/env python3
"""Root, read-only metadata projection; never export signed objects or credential data."""
import datetime
import json
import os
from pathlib import Path
import re
import sqlite3
import sys


def snapshot(database, target, approval_ids, actor_pid=None):
    db = sqlite3.connect('file:' + str(database) + '?mode=ro', uri=True)
    db.row_factory = sqlite3.Row
    try:
        result = {'observed_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  'device': None, 'grants': [], 'approvals': [], 'events': []}
        row = db.execute('SELECT id,os,revoked_at FROM devices WHERE id=?', (target,)).fetchone()
        if row:
            result['device'] = dict(row)
        result['active_phone_n'] = db.execute(
            "SELECT COUNT(*) FROM devices WHERE revoked_at IS NULL AND os IN ('ios','android')"
        ).fetchone()[0]
        result['grants'] = [dict(row) for row in db.execute(
            'SELECT jti,iss,aud,exp,revoked_at FROM grants ORDER BY installed_at,jti')]
        rows = db.execute('SELECT id,state,agent_pid,exp,request_json FROM pending_approvals ORDER BY created_at,id')
        for row in rows:
            if row['id'] not in approval_ids and (actor_pid is None or row['agent_pid'] != actor_pid):
                continue
            request = json.loads(row['request_json'])
            result['approvals'].append({
                'id': row['id'], 'state': row['state'], 'agent_pid': row['agent_pid'], 'exp': row['exp'],
                'min_level': request.get('min_level'), 'tier': request.get('tier'),
                'delivery_mode': request.get('delivery', {}).get('mode'),
            })
        identifiers = approval_ids | {row['id'] for row in result['approvals']}
        for row in db.execute('SELECT entry_json FROM remote_audit ORDER BY seq'):
            value = json.loads(row[0])
            if value.get('approval_id') not in identifiers and value.get('device_id') != target:
                continue
            event = {key: value[key] for key in (
                'ts', 'op', 'approval_id', 'device_id', 'by', 'reason', 'state',
                'decision', 'approval_level', 'peer', 'digest',
            ) if key in value}
            if event.get('reason') not in ('user_cancelled', 'remote_request_expired',
                                           'remote_ui_unavailable', 'invalid_remote_response',
                                           'key_operation_failed', 'key_operation_cancelled',
                                           'key_authentication_failed', 'revoked_device',
                                           'expired', 'cancelled', 'already_consumed'):
                event.pop('reason', None)
            result['events'].append(event)
        for row in result['approvals']:
            events = [event for event in result['events'] if event.get('approval_id') == row['id']]
            row['execution_started_n'] = sum(event.get('op') == 'approval_execution_started' for event in events)
            row['execution_completed_n'] = sum(event.get('op') == 'approval_execution_completed' for event in events)
        return result
    finally:
        db.close()


def main():
    if os.geteuid() != 0 or len(sys.argv) != 3 or sys.argv[1] not in ('mac', 'ndu'):
        raise SystemExit('root_readonly_snapshot_required')
    arguments = json.loads(sys.argv[2])
    target = arguments['target']
    ids = arguments.get('approval_ids', [])
    if not re.fullmatch('[0-9A-HJKMNP-TV-Z]{26}', target) or any(
            not isinstance(value, str) or not re.fullmatch('[0-9A-HJKMNP-TV-Z]{26}', value) for value in ids):
        raise SystemExit('snapshot_identifier_invalid')
    actor_pid = arguments.get('actor_pid')
    if actor_pid is not None and (type(actor_pid) is not int or actor_pid <= 1):
        raise SystemExit('snapshot_actor_invalid')
    base = Path('/var/db/keyvalet/remote' if sys.argv[1] == 'mac' else '/var/lib/keyvalet/remote')
    print(json.dumps(snapshot(base / 'approvals.sqlite3', target, set(ids), actor_pid)))


if __name__ == '__main__':
    main()
