#!/usr/bin/env python3
"""Owner-attended native token staging and one Claude Code GET; no secret transcripts."""
import datetime
import importlib.util
import json
import os
from pathlib import Path
import queue
import resource
import shlex
import subprocess
import threading
import time

resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
os.umask(0o077)
ASSETS = Path('/Users/guang/dev/keyvalet/docs/remote-approval-reports/assets')
spec = importlib.util.spec_from_file_location('r3a_mcp', ASSETS / 'r3a-mcp-client.py')
mcp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mcp)
SSH = ['/usr/bin/ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8']
if os.getuid() != 501:
    raise SystemExit('Run as the Mac owner, without sudo')
receipt = {'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
           'source_credential': 'oauth2/outlook-hhstuhacker-graph',
           'test_credential': 'api_key/r3a-graph-readonly',
           'method': 'GET', 'url': 'https://graph.microsoft.com/v1.0/me',
           'credential_values_saved': False, 'refresh_token_transferred': False,
           'native_tool_calls': [], 'http_statuses': []}
started = time.monotonic()


def public_pid(phase):
    result = subprocess.run(SSH + ['ndu', 'cat /tmp/keyvalet-r3a-native/' + phase + '.pid'],
                            capture_output=True, text=True, timeout=10)
    text = result.stdout.strip()
    return int(text) if result.returncode == 0 and text.isdigit() and int(text) > 1 else None


def agent_for(pid):
    print('请在此 Terminal 按 ndu 的 polkit 提示输入 ndu 用户密码；不要发到聊天。', flush=True)
    process = subprocess.Popen(SSH + ['-tt', 'ndu', '/usr/local/bin/keyvalet approve ' + str(pid)])
    time.sleep(1)
    if process.poll() is not None:
        raise mcp.McpFailure('ndu_polkit_agent_closed')
    return process


def close_agent(process):
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def prepare_remote():
    # Public driver/configuration only. Tokens later travel through native MCP stdin.
    source = (ASSETS / 'r3a-mcp-exec.py').read_text()
    config = {'mcpServers': {'keyvalet': {
        'command': '/usr/bin/python3',
        'args': ['/tmp/keyvalet-r3a-native/mcp-exec.py', 'claude'],
    }}}
    code = """import os,json,pathlib
d=pathlib.Path('/tmp/keyvalet-r3a-native')
if d.exists() and (d.is_symlink() or d.stat().st_uid!=os.getuid()): raise SystemExit(1)
d.mkdir(mode=0o700,exist_ok=True)
os.chmod(d,0o700)
for name,text in DATA.items():
 p=d/name
 if p.is_symlink(): raise SystemExit(1)
 p.write_text(text);os.chmod(p,0o600)
for name in ('setup.pid','claude.pid','samples.pid','setup.pid.new','claude.pid.new','samples.pid.new'):
 p=d/name
 if p.exists() and not p.is_symlink(): p.unlink()
""".replace('DATA', repr({'mcp-exec.py': source, 'claude-mcp.json': json.dumps(config)}))
    result = subprocess.run(SSH + ['ndu', '/usr/bin/python3 -'], input=code,
                            capture_output=True, text=True, timeout=20)
    if result.returncode:
        raise mcp.McpFailure('ndu_public_driver_setup_failed')


def observe_claude(frame):
    if not isinstance(frame, dict):
        return
    if frame.get('type') == 'result':
        receipt['claude_result_subtype'] = frame.get('subtype')
        receipt['claude_reported_error'] = frame.get('is_error') is True
        receipt['claude_duration_ms'] = frame.get('duration_ms')
    message = frame.get('message', {})
    if not isinstance(message, dict):
        return
    for content in message.get('content', []):
        if not isinstance(content, dict):
            continue
        if content.get('type') == 'tool_use':
            name = content.get('name', '')
            if name.startswith('mcp__keyvalet__'):
                args = content.get('input', {})
                receipt['native_tool_calls'].append({
                    'tool': name,
                    'arguments': {k: args[k] for k in ('type', 'name', 'url', 'method', 'approval_id') if k in args},
                    'observed_elapsed_s': round(time.monotonic() - started, 6),
                })
        if content.get('type') == 'tool_result':
            raw = content.get('content')
            texts = [raw] if isinstance(raw, str) else [
                part.get('text', '') for part in (raw or []) if isinstance(part, dict)
            ]
            for text in texts:
                try:
                    value = mcp.payload({'content': [{'type': 'text', 'text': text}]})
                except mcp.McpFailure:
                    continue
                status = value.get('status')
                if isinstance(status, int) and 100 <= status <= 599:
                    receipt['http_statuses'].append(status)
                    receipt['first_http_result_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
                    receipt['elapsed_to_http_result_s'] = round(time.monotonic() - started, 6)
                elif status in ('approval_pending', 'still_pending', 'denied', 'cancelled', 'expired', 'already_consumed'):
                    receipt.setdefault('approval_results', []).append({
                        'status': status, 'approval_id': value.get('approval_id'),
                    })


mac = None
remote = None
agent = None
claude = None
try:
    prepare_remote()
    print('在 Mac 按所选 Outlook 凭证的本地解锁/使用提示按 Touch ID；短期 token 不显示、不写文件。', flush=True)
    mac = mcp.Client(['/usr/local/lib/keyvalet/bin/kv-mcp'])
    mac.initialize()
    token_started = time.monotonic()
    token_result = mcp.payload(mac.tool('credential_access_token', {
        'type': 'oauth2', 'name': 'outlook-hhstuhacker-graph',
        'purpose': 'R3-A: stage a short-lived Graph token for the selected read-only GET on ndu',
    }))
    if token_result.get('status') in ('pending', 'approval_pending', 'still_pending'):
        approval_id = token_result.get('approval_id')
        if not isinstance(approval_id, str) or not approval_id:
            raise mcp.McpFailure('source_pending_id_missing')
        receipt['source_approval_pending'] = True
        receipt['source_approval_id'] = approval_id
        print('本次调用预算结束，继续等待同一条审批，不重复发起 token 请求。', flush=True)
        token_result = mcp.payload(mac.tool('credential_wait_approval', {
            'approval_id': approval_id, 'max_wait_s': 180,
        }, timeout=195))
    token = token_result.get('access_token')
    if not isinstance(token, str) or not token:
        raise mcp.McpFailure('source_access_token_not_authorized')
    receipt['mac_token_elapsed_s'] = round(time.monotonic() - token_started, 6)
    receipt['mac_token_authorized'] = True
    mac.close()
    mac = None

    print('在 ndu 的原生 MCP 中创建仅限 graph.microsoft.com 的代理凭证。', flush=True)
    remote = mcp.Client(SSH + ['ndu', '/usr/bin/python3 /tmp/keyvalet-r3a-native/mcp-exec.py setup'])
    remote.initialize()
    pid = public_pid('setup')
    if not pid:
        raise mcp.McpFailure('ndu_setup_pid_unavailable')
    agent = agent_for(pid)
    result = mcp.payload(remote.tool('credential_set', {
        'type': 'api_key', 'name': 'r3a-graph-readonly', 'template': 'bearer',
        'value': token, 'allowed_hosts': ['graph.microsoft.com'],
        'proxy_only': True, 'verify': False,
        'purpose': 'R3-A: save the owner-selected short-lived Graph token for read-only GET acceptance',
        'description': 'R3-A owner-selected Graph token; test requests use GET /v1.0/me',
    }))
    if (result.get('type'), result.get('name')) != ('api_key', 'r3a-graph-readonly'):
        raise mcp.McpFailure('ndu_credential_identity_mismatch')
    receipt['ndu_proxy_credential_created'] = True
    receipt['proxy_only'] = result.get('proxy', {}).get('proxy_only') is True
    receipt['allowed_hosts'] = result.get('proxy', {}).get('allowed_hosts')
    del token
    del token_result
    remote.close()
    remote = None
    close_agent(agent)
    agent = None

    print('Claude Code 即将发出一次 GET；按 ndu 的解锁密码提示后，核对 Mac 远程审批框并批准。', flush=True)
    prompt = ('执行一次只读验收：仅使用 KeyValet MCP 的 credential_http_request，type=api_key，'
              'name=r3a-graph-readonly，method=GET，url=https://graph.microsoft.com/v1.0/me，'
              'purpose=R3-A first native Claude Code read-only GET。不要读取或打印凭证、access token，'
              '不要使用 curl、shell 或其他工具。若返回 approval_pending，请对同一个 approval_id '
              '调用 credential_wait_approval。收到 HTTP 结果后立即结束，最终只输出 HTTP 状态码，不输出响应体。')
    command = ['/usr/bin/claude', '--print', '--output-format', 'stream-json', '--verbose',
               '--tools', '', '--strict-mcp-config', '--mcp-config',
               '/tmp/keyvalet-r3a-native/claude-mcp.json', '--allowedTools',
               'mcp__keyvalet__credential_http_request', 'mcp__keyvalet__credential_wait_approval',
               '--', prompt]
    claude = subprocess.Popen(SSH + ['ndu', shlex.join(command)], stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    frames = queue.Queue()

    def read_claude():
        for line in claude.stdout:
            try:
                frames.put(json.loads(line))
            except ValueError:
                pass
        frames.put(None)

    threading.Thread(target=read_claude, daemon=True).start()
    deadline = time.monotonic() + 360
    while time.monotonic() < deadline:
        if agent is None:
            pid = public_pid('claude')
            if pid:
                agent = agent_for(pid)
        try:
            frame = frames.get(timeout=0.25)
        except queue.Empty:
            continue
        if frame is None:
            break
        observe_claude(frame)
    if claude.poll() is None:
        claude.terminate()
    try:
        claude.wait(timeout=5)
    except subprocess.TimeoutExpired:
        claude.kill()
        claude.wait()
    receipt['claude_exit'] = claude.returncode
    receipt['claude_http_tool_calls'] = sum(
        call['tool'] == 'mcp__keyvalet__credential_http_request' for call in receipt['native_tool_calls'])
    receipt['successful_http_results'] = sum(200 <= status < 300 for status in receipt['http_statuses'])
    print('本次 Claude HTTP 调用次数：', receipt['claude_http_tool_calls'],
          '；收到的 HTTP 状态：', receipt['http_statuses'], flush=True)
except mcp.McpFailure as error:
    receipt['driver_error'] = str(error)
    print('本段已停止，固定诊断码：' + str(error) + '；未保存 token 或原始输出。', flush=True)
finally:
    for client in (mac, remote):
        if client is not None:
            client.close()
    if claude is not None and claude.poll() is None:
        claude.terminate()
        claude.wait(timeout=5)
    close_agent(agent)
    receipt['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    receipt['elapsed_s'] = round(time.monotonic() - started, 6)
    path = ASSETS / ('r3a-first-use-' + datetime.datetime.now(datetime.timezone.utc).strftime('%H%M%S') + '.json')
    path.write_text(json.dumps(receipt, indent=2) + '\n')
    print('本段执行结束；收据仅含调用名称、HTTP 状态和计时。', flush=True)
