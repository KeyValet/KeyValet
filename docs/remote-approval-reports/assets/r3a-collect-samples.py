#!/usr/bin/env python3
"""Root read-only projection of one real runtime's approval times; no signed capabilities."""
import datetime
import json
import os
from pathlib import Path
import sqlite3
import sys

if os.geteuid() != 0 or len(sys.argv) != 2 or not sys.argv[1].isdigit():
    raise SystemExit('root_readonly_metric_requires_agent_pid')
pid = int(sys.argv[1])
base = Path('/var/lib/keyvalet/remote')
db = sqlite3.connect('file:'+str(base/'approvals.sqlite3')+'?mode=ro', uri=True)
db.row_factory = sqlite3.Row
rows = []
for row in db.execute('SELECT id,kind,state,agent_pid,level,request_json,scope_json FROM pending_approvals WHERE agent_pid=? ORDER BY created_at,id', (pid,)):
    item = dict(row)
    request = json.loads(item.pop('request_json'))
    raw_scope = item.pop('scope_json')
    scope = json.loads(raw_scope) if raw_scope else {}
    item['scope_mode'] = scope.get('mode')
    item['tier'] = request.get('tier')
    item['digest'] = request.get('digest')
    item['delivery_mode'] = request.get('delivery', {}).get('mode')
    operation=request.get('operation')
    if isinstance(operation,dict):
        item['operation']={key:operation[key] for key in ('method','host','path','query_keys') if key in operation}
    rows.append(item)
ids = {row['id'] for row in rows}
public = {'ts','op','approval_id','digest','decision_hash','decision','approval_level',
          'agent_pid','approver_device','state','reason'}
events = []
for line in (base/'audit.log').read_text().splitlines():
    try:
        event = json.loads(line)
        if event.get('approval_id') in ids:
            events.append({k: v for k, v in event.items() if k in public})
    except ValueError:
        pass
parse = lambda t: datetime.datetime.fromisoformat(t.replace('Z','+00:00'))
for row in rows:
    selected = [e for e in events if e['approval_id'] == row['id']]
    start = next((e for e in selected if e['op'] == 'approval_requested'), None)
    end = next((e for e in selected if e['op'] in ('remote_approval_accepted','remote_approval_denied')), None)
    row['helper_request_to_decision_s'] = round((parse(end['ts'])-parse(start['ts'])).total_seconds(),6) if start and end else None
    row['execution_started_count'] = sum(e['op']=='approval_execution_started' for e in selected)
    row['execution_completed_count'] = sum(e['op']=='approval_execution_completed' for e in selected)
    row['touch_id_user_time_s'] = 0 if row['level']=='quick' else None
print(json.dumps({'agent_pid':pid,'approvals':rows,'events':events,
                  'measurement':'same helper millisecond audit ts: approval_requested to accepted/denied',
                  'observed_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()}))
