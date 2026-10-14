#!/usr/bin/env python3
"""Attended native OAuth refresh, proxy update, then installed run or MCP samples."""
import argparse
import datetime
import importlib.util
import json
import os
from pathlib import Path
import resource
import subprocess
import time

if os.getuid() != 501:
    raise SystemExit('Run as the Mac owner, without sudo')
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--follow-up', choices=('run', 'samples'), default='run')
options = parser.parse_args()
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
os.umask(0o077)
assets = Path('/Users/guang/dev/keyvalet/docs/remote-approval-reports/assets')
spec = importlib.util.spec_from_file_location('mcp', assets/'r3a-mcp-client.py')
mcp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mcp)
spec = importlib.util.spec_from_file_location('params', assets/'r3a-refresh-params.py')
params = importlib.util.module_from_spec(spec)
spec.loader.exec_module(params)
spec = importlib.util.spec_from_file_location('audit_report', assets/'r3a-audit-report.py')
audit_report = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit_report)
ssh = ['/usr/bin/ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8']
started = time.monotonic()
receipt = {'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
           'source_credential': 'oauth2/outlook-hhstuhacker-graph',
           'test_credential': 'api_key/r3a-graph-readonly',
           'method': 'GET', 'url': 'https://graph.microsoft.com/v1.0/me',
           'force_refresh': True, 'refresh_token_transferred': False,
           'follow_up': options.follow_up,
           'secret_values_in_evidence': False}
mac = remote = agent = None


def prepare():
    sources = {n: (assets/n).read_text() for n in
               ('r3a-run-agent.py', 'r3a-run-readiness.py', 'r3a-mcp-session-exec.py')}
    code = "from pathlib import Path\nimport os\nd=Path('/tmp/keyvalet-r3a-native')\nif d.is_symlink() or d.stat().st_uid!=os.getuid():raise SystemExit(1)\nfor name,source in "+repr(sources)+".items():\n p=d/name\n if p.is_symlink():raise SystemExit(1)\n p.write_text(source)\n os.chmod(p,0o600)\nfor name in ('refresh.pid','refresh.pid.new','refresh-agent.ready','refresh-agent.ready.new'):\n p=d/name\n if p.is_symlink():raise SystemExit(1)\n if p.exists():p.unlink()\n"
    result = subprocess.run(ssh+['ndu', '/usr/bin/python3 -'], input=code,
                            capture_output=True, text=True, timeout=20)
    if result.returncode:
        raise mcp.McpFailure('refresh_driver_setup_failed')


def pid_ready():
    deadline = time.monotonic()+10
    while time.monotonic() < deadline:
        result = subprocess.run(ssh+['ndu', 'cat /tmp/keyvalet-r3a-native/refresh.pid'],
                                capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            identity = json.loads(result.stdout)
            if identity.get('uid') == 1000 and identity.get('pid', 0) > 1:
                return identity
        time.sleep(.1)
    raise mcp.McpFailure('refresh_process_unavailable')


def collect_pair_audit():
    print('先核对 Mac root-only 审计；如 Terminal 要求系统管理员密码，请只在 Terminal 输入。', flush=True)
    result = subprocess.run(['/usr/bin/sudo', '-v'])
    if result.returncode:
        raise mcp.McpFailure('mac_audit_admin_auth_failed')
    result = subprocess.run(['/usr/bin/sudo', '-n', '/usr/local/lib/keyvalet/bin/kv-cli',
                             'audit', '--remote', '--since', '2026-10-13T05:26:00Z', '--limit', '200', '--json'],
                            capture_output=True, text=True, timeout=20)
    if result.returncode:
        raise mcp.McpFailure('mac_root_audit_unavailable')
    value = json.loads(result.stdout)
    public = audit_report.project(value)
    mac_public = {'cli_exit': result.returncode, 'native_report': public,
                  'observed_utc': datetime.datetime.now(datetime.timezone.utc).isoformat()}
    (assets/'r3a-first-run-mac-audit.json').write_text(json.dumps(mac_public, indent=2)+'\n')
    receipt['audit_before_refresh'] = public
    print('原生双端审计：匹配 '+str(public['matched'])+' 项，差异 '+str(public['findings_count'])+
          ' 项；端点可用='+str(public['two_endpoint_snapshots'])+'。', flush=True)


try:
    prepare()
    collect_pair_audit()
    print('在 Mac 允许所选 Outlook 凭证的短期 token 更新并按 Touch ID；token 不显示。', flush=True)
    mac = mcp.Client(['/usr/local/lib/keyvalet/bin/kv-mcp'])
    mac.initialize()
    token_started = time.monotonic()
    value = mcp.payload(mac.tool('credential_access_token', {
        'type': 'oauth2', 'name': 'outlook-hhstuhacker-graph', 'force_refresh': True,
        'purpose': 'R3-A: refresh the selected short-lived Graph access token for the owner-selected read-only GET',
    }))
    if value.get('status') in ('approval_pending', 'still_pending'):
        ident = value.get('approval_id')
        if not isinstance(ident, str):
            raise mcp.McpFailure('source_pending_id_missing')
        receipt['source_approval_id'] = ident
        value = mcp.payload(mac.tool('credential_wait_approval', {
            'approval_id': ident, 'max_wait_s': 180,
        }, timeout=195))
    token = value.get('access_token')
    if not isinstance(token, str) or not token:
        raise mcp.McpFailure('source_refresh_not_authorized')
    expiry = value.get('expires_at')
    if not isinstance(expiry, str):
        raise mcp.McpFailure('source_expiration_unavailable')
    parsed = datetime.datetime.fromisoformat(expiry.replace('Z', '+00:00'))
    if parsed <= datetime.datetime.now(datetime.timezone.utc):
        raise mcp.McpFailure('source_refreshed_token_expired')
    receipt['source_expires_at'] = expiry
    if isinstance(value.get('scope'), str):
        receipt['source_scopes'] = value['scope']
    receipt['source_refresh_elapsed_s'] = round(time.monotonic()-token_started, 6)
    del value
    mac.close();mac = None
    print('短期 token 已更新；请在此 Terminal 输入 ndu 密码，确认覆盖同一 Graph 代理凭证。', flush=True)
    remote = mcp.Client(ssh+['ndu', '/usr/bin/python3 /tmp/keyvalet-r3a-native/r3a-mcp-session-exec.py refresh'])
    receipt['refresh_process'] = pid_ready()
    agent = subprocess.Popen(ssh+['-tt', 'ndu', '/usr/bin/python3 /tmp/keyvalet-r3a-native/r3a-run-agent.py --phase refresh'])
    remote.initialize()
    result = mcp.payload(remote.tool('credential_set', params.proxy_set_arguments(token)))
    del token
    if (result.get('type'), result.get('name')) != ('api_key', 'r3a-graph-readonly'):
        raise mcp.McpFailure('proxy_identity_mismatch')
    if result.get('proxy', {}).get('proxy_only') is not True or result.get('proxy', {}).get('allowed_hosts') != ['graph.microsoft.com']:
        raise mcp.McpFailure('proxy_restriction_mismatch')
    receipt['proxy_updated'] = True
    remote.close();remote = None
    agent.terminate();agent.wait(timeout=10);agent = None
    if parsed <= datetime.datetime.now(datetime.timezone.utc):
        raise mcp.McpFailure('source_token_expired_before_get')
    if options.follow_up == 'samples':
        print('同一代理凭证更新完成；接下来进入 20 次逐次审批与负面用例。', flush=True)
        driver = 'r3a-use-samples.py'
        receipt_prefix = 'r3a-samples-'
    else:
        print('同一代理凭证更新完成；接下来输入 ndu 解锁密码，并审批 Mac 的网关与 GET。', flush=True)
        driver = 'r3a-first-use-run.py'
        receipt_prefix = 'r3a-first-run-'
    before = datetime.datetime.now(datetime.timezone.utc).isoformat()
    result = subprocess.run(['/usr/bin/python3', str(assets/driver)])
    receipt['follow_up_driver_exit'] = result.returncode
    for path in sorted(assets.glob(receipt_prefix+'*.json'), key=lambda p: p.stat().st_mtime, reverse=True):
        run = json.loads(path.read_text())
        if run.get('started_utc', '') >= before:
            receipt['follow_up_receipt'] = path.name
            if options.follow_up == 'run':
                receipt['run_driver_exit'] = result.returncode
                receipt['run_receipt'] = path.name
                receipt['http_statuses'] = run.get('http_statuses', [])
                receipt['run_exit'] = run.get('run_exit')
            else:
                receipt['sample_count'] = len(run.get('samples', []))
                receipt['helper_latency'] = run.get('helper_latency')
                if 'fixed_error' in run:
                    receipt['follow_up_fixed_error'] = run['fixed_error']
            break
except (mcp.McpFailure, subprocess.TimeoutExpired, ValueError) as error:
    receipt['fixed_error'] = str(error) if isinstance(error, mcp.McpFailure) else 'refresh_driver_unavailable'
    print('本段停止；仅保存固定错误码。', flush=True)
finally:
    for client in (mac, remote):
        if client is not None:
            client.close()
    if agent is not None and agent.poll() is None:
        agent.terminate()
        try:
            agent.wait(timeout=10)
        except subprocess.TimeoutExpired:
            agent.kill();agent.wait()
    receipt['elapsed_s'] = round(time.monotonic()-started, 6)
    receipt['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    prefix = 'r3a-refresh-samples-' if options.follow_up == 'samples' else 'r3a-refresh-first-'
    path = assets/(prefix+datetime.datetime.now(datetime.timezone.utc).strftime('%H%M%S')+'.json')
    path.write_text(json.dumps(receipt, indent=2)+'\n')
    print('token 更新与后续请求段结束；收据不含凭证值或响应体。', flush=True)
