#!/usr/bin/env python3
"""Read authenticated native audit differences; retain only public identifiers."""
import datetime
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import subprocess
import time

if os.getuid() != 501:
    raise SystemExit('run_as_mac_owner_without_sudo')
os.umask(0o077)
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
assets = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('audit_report', assets / 'r3a-audit-report.py')
audit_report = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit_report)


def public_id(value):
    if isinstance(value, str) and (value in ('', '*') or re.fullmatch(
            r'(?:approval:)?[0-9A-HJKMNP-TV-Z]{26}', value)):
        return value
    return 'invalid_public_identifier'


receipt = {'observed_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
           'read_only': True, 'touch_id_requests': 0,
           'secret_values_in_evidence': False, 'collection_timeout_s': 120}
started = time.monotonic()
try:
    process = subprocess.run([
        '/usr/bin/sudo', '-n', '/usr/local/lib/keyvalet/bin/kv-cli',
        'audit', '--remote', '--since', '2026-10-13T05:26:00Z',
        '--limit', '200', '--json',
    ], capture_output=True, text=True, timeout=120)
    receipt['cli_exit'] = process.returncode
    if process.returncode not in (0, 3):
        raise ValueError('native_audit_noninteractive_unavailable')
    value = json.loads(process.stdout)
    receipt['native_report'] = audit_report.project(value)
    findings = value['result']['comparison']['findings']
    if not isinstance(findings, list) or len(findings) > 200:
        raise ValueError('native_audit_findings_unavailable')
    receipt['findings'] = []
    for finding in findings:
        kind = finding.get('kind')
        problem = finding.get('problem')
        if kind not in ('approval', 'grant', 'directive') or problem not in (
                'missing_binding', 'missing_issuer_record', 'missing_receiver_record',
                'duplicate_record', 'field_mismatch'):
            raise ValueError('native_audit_finding_type_unavailable')
        fields = finding.get('fields', [])
        allowed = {'digest', 'approval_level', 'decision', 'decision_hash',
                   'max_tier', 'grant_hash', 'directive_op', 'directive_hash'}
        if not isinstance(fields, list) or any(field not in allowed for field in fields):
            raise ValueError('native_audit_finding_fields_unavailable')
        receipt['findings'].append({
            'kind': kind, 'problem': problem, 'fields': fields,
            'id': public_id(finding.get('id')),
            'issuer': public_id(finding.get('issuer')),
            'receiver': public_id(finding.get('receiver')),
        })
    print('原生审计差异诊断完成；仅保存类型、公开 ID 与字段名称。', flush=True)
except (ValueError, KeyError, TypeError, subprocess.TimeoutExpired):
    receipt['fixed_error'] = 'native_audit_findings_readback_unavailable'
    print('非交互只读审计未取得结果；未触发密码或 Touch ID。', flush=True)
finally:
    receipt['elapsed_s'] = round(time.monotonic() - started, 6)
    receipt['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    path = assets / ('r3a-native-audit-findings-' + datetime.datetime.now(
        datetime.timezone.utc).strftime('%H%M%S') + '.json')
    path.write_text(json.dumps(receipt, indent=2) + '\n')
