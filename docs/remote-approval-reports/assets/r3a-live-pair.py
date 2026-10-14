#!/usr/bin/env python3
"""Run only after the owner says 开始; never persist CLI output or pairing secrets."""
import datetime
import json
import os
from pathlib import Path
import pty
import resource
import select
import signal
import sys
import subprocess
import time

CLI = '/usr/local/lib/keyvalet/bin/kv-cli'
ASSETS = Path('/Users/guang/dev/keyvalet/docs/remote-approval-reports/assets')
SSH = ['/usr/bin/sudo', '-u', 'guang', '/usr/bin/ssh', '-o', 'BatchMode=yes',
       '-o', 'ConnectTimeout=8']
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

def json_lines(buffer, data):
    buffer += data
    replies = []
    while b'\n' in buffer:
        line, buffer = buffer.split(b'\n', 1)
        try:
            value = json.loads(line.strip())
        except (ValueError, UnicodeError):
            continue
        if isinstance(value, dict):
            replies.append(value)
    return buffer, replies

def directory(mac):
    args = [CLI, '--lang', 'en', 'devices', 'list', '--json'] if mac else SSH + ['ndu', '/usr/local/bin/keyvalet devices list --json']
    p = subprocess.run(args, capture_output=True, timeout=25)
    try:
        value = json.loads(p.stdout)
    except ValueError:
        value = {}
    return {'exit': p.returncode, 'ok': value.get('ok') is True,
            'devices': [{k: d[k] for k in ('device_id', 'label', 'os', 'caps', 'revoked') if k in d}
                        for d in value.get('result', {}).get('devices', [])]}

if os.geteuid() != 0:
    raise SystemExit('Run in the owner sudo terminal')
os.umask(0o077)
start = time.monotonic()
receipt = {'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
           'commands': ['ndu: keyvalet pair --new --json', 'Mac: keyvalet pair <redacted URI> --json'],
           'safety_code_equal': False, 'owner_confirmed': False}
resume = '--resume' in sys.argv
remote = subprocess.Popen(SSH + ['-tt', 'ndu', '/usr/local/bin/keyvalet pair ' + ('--resume' if resume else '--new') + ' --json'],
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
buffers = {remote.stdout.fileno(): b''}
mac_pid = None
mac_fd = None
codes = {}
paired = set()
if resume:
    mac_pid, mac_fd = pty.fork()
    if mac_pid == 0:
        os.execv(CLI, [CLI, '--lang', 'en', 'pair', '--resume', '--json'])
    buffers[mac_fd] = b''
    receipt['commands'] = ['ndu: keyvalet pair --resume --json', 'Mac: keyvalet pair --resume --json']
print('已从 ndu 和 Mac 的已安装 CLI 运行配对；链接不写证据。', flush=True)
try:
    deadline = start + 420
    while time.monotonic() < deadline and paired != {'Mac', 'ndu'}:
        ready, _, _ = select.select(list(buffers), [], [], 0.5)
        for fd in ready:
            try:
                data = os.read(fd, 65536)
            except OSError:
                data = b''
            if not data:
                del buffers[fd]
                continue
            buffers[fd], replies = json_lines(buffers[fd], data)
            side = 'Mac' if fd == mac_fd else 'ndu'
            for value in replies:
                if value.get('ok') is False:
                    receipt[side + '_error_code'] = value.get('error', {}).get('code')
                    raise RuntimeError('pair_cli_rejected')
                result = value.get('result', {})
                if result.get('recovery_code'):
                    # Product output is shown only to its owner in Terminal, never to
                    # Codex, a report, a transcript file or a screenshot collector.
                    print('产品生成了恢复码，请在你的密码管理器保存：', result['recovery_code'], flush=True)
                    receipt['recovery_code_displayed_to_owner'] = True
                if side == 'ndu' and result.get('uri') and mac_pid is None:
                    uri = result['uri']
                    mac_pid, mac_fd = pty.fork()
                    if mac_pid == 0:
                        os.execv(CLI, [CLI, '--lang', 'en', 'pair', uri, '--json'])
                    del uri
                    buffers[mac_fd] = b''
                if result.get('sas'):
                    codes[side] = result['sas']
                if result.get('paired') is True:
                    paired.add(side)
        if len(codes) == 2 and not receipt['owner_confirmed']:
            print('ndu 安全码：' + codes['ndu'] + '；Mac 安全码：' + codes['Mac'], flush=True)
            receipt['safety_code_equal'] = codes['ndu'] == codes['Mac']
            if not receipt['safety_code_equal']:
                raise RuntimeError('safety_code_mismatch')
            print('请亲自核对两端一致，在此 Terminal 输入 y 并回车；之后在 Mac 对话框确认并按 Touch ID。', flush=True)
            with open('/dev/tty', 'r') as owner_tty:
                while True:
                    answer = owner_tty.readline()
                    if not answer:
                        raise RuntimeError('owner_tty_closed')
                    if answer.strip().lower() == 'y':
                        break
                    if answer.strip():
                        raise RuntimeError('owner_cancelled')
                    print('空回车未提交确认；请核对安全码后输入 y 并回车，或输入 n 取消。', flush=True)
            receipt['owner_confirmed'] = True
            receipt['confirmation_elapsed_s'] = round(time.monotonic() - start, 6)
            remote.stdin.write(b'y\n')
            remote.stdin.flush()
            os.write(mac_fd, b'y\n')
        if not buffers and paired != {'Mac', 'ndu'}:
            raise RuntimeError('pair_cli_closed')
    if paired != {'Mac', 'ndu'}:
        raise RuntimeError('pair_deadline')
    receipt['mac_directory'] = directory(True)
    receipt['ndu_directory'] = directory(False)
    mac_peers = receipt['mac_directory']['devices']
    ndu_peers = receipt['ndu_directory']['devices']
    receipt['both_devices_visible'] = (any(d.get('os') == 'linux' and not d.get('revoked') for d in mac_peers)
                                       and any(d.get('os') == 'macos' and not d.get('revoked') for d in ndu_peers))
    receipt['elapsed_to_both_devices_s'] = round(time.monotonic() - start, 6)
    print('两端 devices list 看到对方：', receipt['both_devices_visible'], '；用时', receipt['elapsed_to_both_devices_s'], '秒。', flush=True)
except RuntimeError as error:
    receipt['driver_error'] = str(error)  # All RuntimeError messages above are fixed codes.
    print('配对没有完成；已保存固定错误码，未保存配对链接。', flush=True)
finally:
    receipt['paired_cli_sides'] = sorted(paired)
    receipt['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    receipt['total_elapsed_s'] = round(time.monotonic() - start, 6)
    try:
        remote.wait(timeout=2)
    except subprocess.TimeoutExpired:
        remote.terminate()
        try:
            remote.wait(timeout=5)
        except subprocess.TimeoutExpired:
            remote.kill()
            remote.wait()
    receipt['ndu_cli_exit'] = remote.returncode
    if mac_pid:
        found, status = os.waitpid(mac_pid, os.WNOHANG)
        grace = time.monotonic() + 2
        while not found and time.monotonic() < grace:
            time.sleep(0.05)
            found, status = os.waitpid(mac_pid, os.WNOHANG)
        if not found:
            os.kill(mac_pid, signal.SIGTERM)
            _, status = os.waitpid(mac_pid, 0)
        receipt['mac_cli_exit'] = os.waitstatus_to_exitcode(status)
    if mac_fd is not None:
        os.close(mac_fd)
    out = ASSETS / ('r3a-pair-' + datetime.datetime.now(datetime.timezone.utc).strftime('%H%M%S') + '.json')
    out.write_text(json.dumps(receipt, indent=2) + '\n')
    os.chown(out, 501, 20)
    os.chmod(out, 0o600)
if receipt.get('both_devices_visible') is not True:
    raise SystemExit(1)

# This prompt is included in the owner's six-minute list. Only type/name is
# projected; values, descriptions and attributes are never written to evidence.
print('接下来读取 Mac 凭证名称，请在 Mac 的本地解锁框按 Touch ID。', flush=True)
catalog_start = time.monotonic()
catalog = subprocess.run([CLI, '--lang', 'en', 'list'], capture_output=True, text=True, timeout=180)
names = []
if catalog.returncode == 0:
    for line in catalog.stdout.splitlines():
        name = line.split('\t', 1)[0].split(' [', 1)[0]
        if '/' in name and len(name) <= 256 and not any(ord(ch) < 32 or ord(ch) == 127 for ch in name):
            names.append(name)
catalog_receipt = {'observed_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                   'exit': catalog.returncode, 'elapsed_s': round(time.monotonic() - catalog_start, 6),
                   'credential_names': names, 'credential_values_saved': False}
out = ASSETS / 'r3a-mac-credential-catalog.json'
out.write_text(json.dumps(catalog_receipt, indent=2) + '\n')
os.chown(out, 501, 20)
os.chmod(out, 0o600)
print('Mac 凭证名称：' + ('、'.join(names) if names else '无 / 尚未成功解锁'), flush=True)
print('请在聊天选择一个凭证名称和只读 GET URL；不要发送凭证值。', flush=True)
