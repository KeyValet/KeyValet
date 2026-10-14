#!/usr/bin/env python3
"""Read-only installed two-endpoint audit; noninteractive sudo, public aggregate only."""
import datetime
import importlib.util
import json
import os
from pathlib import Path
import subprocess

os.umask(0o077)
assets=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('audit_report',assets/'r3a-audit-report.py')
audit_report=importlib.util.module_from_spec(spec);spec.loader.exec_module(audit_report)
receipt={'observed_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
         'read_only':True,'touch_id_requests':0,'secret_values_in_evidence':False}
try:
    result=subprocess.run(['/usr/bin/sudo','-n','/usr/local/lib/keyvalet/bin/kv-cli',
                           'audit','--remote','--since','2026-10-13T05:26:00Z',
                           '--limit','200','--json'],capture_output=True,text=True,timeout=30)
    receipt['cli_exit']=result.returncode
    if result.returncode==0:
        receipt['native_report']=audit_report.project(json.loads(result.stdout))
        report=receipt['native_report']
        print('原生双端审计：匹配 '+str(report['matched'])+'，差异 '+str(report['findings_count'])+'。',flush=True)
    else:
        receipt['fixed_error']='native_audit_noninteractive_unavailable'
        print('只读审计未取得结果；未弹出密码或认证提示。',flush=True)
except (ValueError,KeyError,subprocess.TimeoutExpired):
    receipt['fixed_error']='native_audit_readback_failed'
    print('只读审计未取得结果；仅保存固定错误码。',flush=True)
finally:
    receipt['finished_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
    path=assets/('r3a-native-audit-'+datetime.datetime.now(datetime.timezone.utc).strftime('%H%M%S')+'.json')
    path.write_text(json.dumps(receipt,indent=2)+'\n')
