#!/usr/bin/env python3
"""Attended installed delivery/cancellation, unused approval and executor revocation."""
import datetime
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import shlex
import subprocess
import sys
import time

ASSETS = Path(__file__).resolve().parent
CLI = '/usr/local/lib/keyvalet/bin/kv-cli'
MAC = '01M4SM5QTRQKNQE1TD6FBJTG79'
NDU = '01M4S8KJ48BSMNK1S4BEGT07FC'
SSH = ['/usr/bin/ssh', '-T', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8', 'ndu']
GRAPH_ARGS = {'type': 'api_key', 'name': 'r3a-graph-readonly', 'method': 'GET',
              'url': 'https://graph.microsoft.com/v1.0/me',
              'purpose': 'R3-A: installed delivery, Escape and unused approval revocation acceptance'}


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ASSETS / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def public_result(value):
    result = {}
    if value.get('status') in ('approval_pending', 'still_pending', 'approval_denied',
                               'approval_expired', 'approval_cancelled', 'approved_retry_required',
                               'already_consumed', 'completed', 'executed', 'ok'):
        result['status'] = value['status']
    if isinstance(value.get('approval_id'), str) and re.fullmatch('[0-9A-HJKMNP-TV-Z]{26}', value['approval_id']):
        result['approval_id'] = value['approval_id']
    if type(value.get('expires_at')) is int:
        result['expires_at'] = value['expires_at']
    if value.get('reason') in ('cancelled', 'expired', 'revoked_device'):
        result['reason'] = value['reason']
    return result


def cli_result(value):
    result = {'ok': value.get('ok') is True}
    error = value.get('error') or {}
    code = error.get('code') if isinstance(error, dict) else None
    if isinstance(code, str) and re.fullmatch('[a-z_]{1,64}', code):
        result['error_code'] = code
    data = value.get('result') or {}
    if isinstance(data, dict):
        if isinstance(data.get('grants'), list):
            result['grant_ids'] = [row['jti'] for row in data['grants'] if isinstance(row, dict) and isinstance(row.get('jti'), str)]
        if isinstance(data.get('results'), list):
            result['target_results'] = [{'device_id': row.get('device_id'),
                                         'ok': (row.get('result') or {}).get('ok') is True}
                                        for row in data['results'] if isinstance(row, dict)]
    return result


class Acceptance:
    def __init__(self):
        self.mcp = module('r3a_remaining_mcp', 'r3a-mcp-client.py')
        self.remote = self.agent = None
        self.identities = []
        self.ids = []
        self.receipt = {'started_utc': self.now(), 'secret_values_in_evidence': False,
                        'cases': [], 'commands': [], 'revocation_started': False,
                        'credential': 'api_key/r3a-graph-readonly', 'method': 'GET',
                        'url': GRAPH_ARGS['url'], 'expected_successful_se_signatures': 2}

    @staticmethod
    def now():
        return datetime.datetime.now(datetime.timezone.utc).isoformat()

    def readback(self, side='ndu'):
        arguments = {'target': NDU, 'approval_ids': self.ids}
        if self.identities:
            arguments['actor_pid'] = self.identities[-1]['parent_pid']
        command = ['/usr/bin/sudo', '-n', '/usr/bin/python3', str(ASSETS / 'r3a-remaining-snapshot.py'),
                   side, json.dumps(arguments)]
        if side == 'ndu':
            remote_command = ['sudo', '-n', '/usr/bin/python3',
                              '/tmp/keyvalet-r3a-native/r3a-remaining-snapshot.py', side, json.dumps(arguments)]
            command = SSH + [shlex.join(remote_command)]
        process = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15)
        if process.returncode:
            raise RuntimeError('remaining_readonly_snapshot_unavailable')
        return json.loads(process.stdout)

    def status(self):
        process = subprocess.run(SSH + ['sudo -n ' + CLI + ' status --json'],
                                 stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15)
        if process.returncode:
            raise RuntimeError('remaining_executor_status_unavailable')
        state = json.loads(process.stdout).get('result', {}).get('remote') or {}
        return {'pending_n': state.get('pending_n'), 'grants_n': state.get('grants_n'),
                'unattended': state.get('unattended'), 'mode': state.get('mode'),
                'mac_presence': next((row.get('presence') for row in state.get('approvers', [])
                                      if row.get('device_id') == MAC), None)}

    def require_present(self, phase, seconds=30):
        started = time.monotonic()
        observed = {'phase': phase, 'samples': []}
        self.receipt.setdefault('presence_readiness', []).append(observed)
        while True:
            state = self.status()
            observed['samples'].append(dict(state, elapsed_s=round(time.monotonic() - started, 6)))
            if any(state.get(key) != wanted for key, wanted in
                   (('pending_n', 0), ('grants_n', 0), ('unattended', False), ('mode', 'per_use'))):
                raise RuntimeError('remaining_requires_clean_executor')
            if state['mac_presence'] == 'present':
                return state
            if time.monotonic() - started >= seconds:
                raise RuntimeError('remaining_present_hint_not_observed')
            time.sleep(1)

    def refresh_presence(self):
        # A restarted agent has no lock/saver notification history. Never invent it.
        self.cue('在场恢复：按回车开启真实系统屏保；保持约 10 秒，再移动鼠标退出并正常解锁。')
        opened = subprocess.run(['/usr/bin/open', '-a', '/System/Library/CoreServices/ScreenSaverEngine.app'],
                                stdin=subprocess.DEVNULL, capture_output=True, timeout=10)
        if opened.returncode:
            raise RuntimeError('remaining_real_screensaver_not_started')
        self.receipt['presence_refresh'] = {'real_screensaver_open_exit': opened.returncode,
                                            'keyvalet_approval_requests': 0,
                                            'keyvalet_touch_id_requests': 0}
        self.cue('退出屏保后，按 Control+Command+Q 锁屏，保持 10 秒再正常解锁；回到此 Terminal 按回车。')
        self.require_present('after_real_saver_and_unlock')
        print('ndu 已收到真实 Mac presence=present；现在进入剩余用例。', flush=True)

    def command(self, name, arguments, expect_ok=True):
        started = time.monotonic()
        process = subprocess.run(['/usr/bin/sudo', '-n', CLI] + arguments + ['--json'],
                                 stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=190)
        try:
            result = cli_result(json.loads(process.stdout))
        except (ValueError, TypeError):
            result = {'ok': False, 'error_code': 'remaining_cli_response_unavailable'}
        row = {'case': name, 'exit': process.returncode, 'elapsed_s': round(time.monotonic() - started, 6),
               'result': result}
        self.receipt['commands'].append(row)
        print(name + '：exit=' + str(process.returncode) + '，' + str(row['elapsed_s']) + ' s。', flush=True)
        if expect_ok and (process.returncode or not result['ok']
                          or any(not row['ok'] for row in result.get('target_results', []))):
            raise RuntimeError('remaining_owner_command_failed')
        return row

    def prepare(self):
        names = ('r3a-run-agent.py', 'r3a-run-readiness.py', 'r3a-mcp-session-exec.py',
                 'r3a-remaining-snapshot.py')
        sources = {name: (ASSETS / name).read_text() for name in names}
        code = ('from pathlib import Path\nimport os\nd=Path("/tmp/keyvalet-r3a-native")\n'
                'if d.is_symlink() or d.stat().st_uid!=os.getuid():raise SystemExit(1)\n'
                'for name,source in ' + repr(sources) + '.items():\n p=d/name\n'
                ' if p.is_symlink():raise SystemExit(1)\n p.write_text(source)\n os.chmod(p,0o600)\n')
        process = subprocess.run(SSH + ['/usr/bin/python3 -'], input=code,
                                 capture_output=True, text=True, timeout=20)
        if process.returncode:
            raise RuntimeError('remaining_driver_setup_failed')

    def stop_agent(self):
        if self.agent is not None and self.agent.poll() is None:
            self.agent.terminate()
            try:
                self.agent.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.agent.kill()
                self.agent.wait(timeout=5)
        self.agent = None

    def close_actor(self):
        self.stop_agent()
        if self.remote is not None:
            self.remote.close()
            self.remote = None

    def actor(self):
        self.close_actor()
        code = ('from pathlib import Path\nimport os\nd=Path("/tmp/keyvalet-r3a-native")\n'
                'if d.is_symlink() or d.stat().st_uid!=os.getuid():raise SystemExit(1)\n'
                'for name in ("samples.pid","samples.pid.new","samples-agent.ready","samples-agent.ready.new"):\n'
                ' p=d/name\n if p.is_symlink():raise SystemExit(1)\n p.unlink(missing_ok=True)\n')
        process = subprocess.run(SSH + ['/usr/bin/python3 -'], input=code,
                                 capture_output=True, text=True, timeout=15)
        if process.returncode:
            raise RuntimeError('remaining_actor_setup_failed')
        self.remote = self.mcp.Client(SSH + [
            '/usr/bin/python3 /tmp/keyvalet-r3a-native/r3a-mcp-session-exec.py samples --wait-in-call-5s'])
        end = time.monotonic() + 10
        while time.monotonic() < end:
            process = subprocess.run(SSH + ['cat /tmp/keyvalet-r3a-native/samples.pid'],
                                     stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10)
            if process.returncode == 0:
                identity = json.loads(process.stdout)
                if identity.get('uid') == 1000 and identity.get('parent_pid', 0) > 1:
                    break
            time.sleep(.1)
        else:
            raise RuntimeError('remaining_actor_identity_unavailable')
        self.identities.append(identity)
        self.agent = subprocess.Popen(SSH[:-1] + ['-tt', 'ndu',
            '/usr/bin/python3 /tmp/keyvalet-r3a-native/r3a-run-agent.py --phase samples'])
        self.remote.initialize()
        print('按 Terminal 的 ndu polkit 提示输入 guang 的密码，完成本会话解锁。', flush=True)
        self.mcp.payload(self.remote.tool('credential_settings', {
            'purpose': 'R3-A: unlock native owner session for remaining acceptance'}, timeout=190))
        self.stop_agent()  # No SSH reader may compete with the following Terminal cues.

    def cue(self, message):
        self.stop_agent()
        print(message, flush=True)
        input('读完本用例，准备好后按一次回车才开始：')

    def request(self):
        value = self.mcp.payload(self.remote.tool('credential_http_request', GRAPH_ARGS, timeout=190))
        result = public_result(value)
        identifier = result.get('approval_id')
        if isinstance(identifier, str) and re.fullmatch('[0-9A-HJKMNP-TV-Z]{26}', identifier):
            self.ids.append(identifier)
        return result

    def await_approval_state(self, identifier, wanted, seconds=45):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            state = self.readback()
            row = next((row for row in state['approvals'] if row['id'] == identifier), None)
            if row and row['state'] in wanted:
                return state, row
            time.sleep(1)
        raise RuntimeError('remaining_approval_state_not_observed')

    def verify_prior_delivery(self):
        origin = 'r3a-remaining-native-20261014T010532Z.json'
        prior = json.loads((ASSETS / origin).read_text())
        cases = {row['case']: row for row in prior['cases']}
        denial = cases['present_delivery_deny']['result']['approval_id']
        escape = cases['remote_escape']['result']['approval_id']
        self.ids.extend([denial, escape])
        executor = self.readback()
        rows = {row['id']: row for row in executor['approvals']}
        if (rows[denial]['state'] != 'denied' or rows[escape]['state'] not in ('waiting', 'expired')
                or any(rows[identifier]['execution_started_n'] or rows[identifier]['execution_completed_n']
                       for identifier in (denial, escape))):
            raise RuntimeError('remaining_prior_delivery_state_mismatch')
        approver = self.readback('mac')
        if not any(row.get('op') == 'remote_ui_rejected' and row.get('approval_id') == escape
                   and row.get('reason') == 'user_cancelled' for row in approver['events']):
            raise RuntimeError('remaining_prior_escape_producer_unavailable')
        self.receipt['prior_native_delivery'] = {'source': origin, 'executor': executor,
                                                'mac': approver, 'new_delivery_requests': 0}
        print('之前的 Deny / Esc 已从实际状态和 producer 审计核对；本段直接补 SE 与吊销。', flush=True)

    def run(self, refresh_presence=False, after_delivery=False):
        print('本段无需安装；如要求 Mac 管理员密码，只在 Terminal 输入。', flush=True)
        if subprocess.run(['/usr/bin/sudo', '-v']).returncode:
            raise RuntimeError('remaining_admin_auth_failed')
        self.prepare()
        self.receipt['before'] = self.status()
        before = self.receipt['before']
        if any(before.get(key) != wanted for key, wanted in
               (('pending_n', 0), ('grants_n', 0), ('unattended', False), ('mode', 'per_use'))):
            raise RuntimeError('remaining_requires_clean_executor')
        if refresh_presence:
            self.refresh_presence()
        else:
            self.require_present('initial_present')
        self.receipt['devices_before'] = self.readback()
        if after_delivery:
            self.verify_prior_delivery()
        else:
            self.actor()
            self.cue('在场投递／明确拒绝：下一条来自 ndu 的 GET，Mac 框请点击 Deny。')
            present_before = self.require_present('before_delivery_request')
            begin = time.monotonic()
            value = self.request()
            if value.get('status') in ('approval_pending', 'still_pending'):
                value = public_result(self.mcp.payload(self.remote.tool('credential_wait_approval', {
                    'approval_id': value['approval_id'], 'max_wait_s': 120}, timeout=135)))
            self.receipt['cases'].append({'case': 'present_delivery_deny', 'result': value,
                                          'elapsed_s': round(time.monotonic() - begin, 6),
                                          'before': present_before})
            if value.get('status') != 'approval_denied':
                raise RuntimeError('remaining_explicit_deny_not_observed')
            self.cue('Esc 用例：下一条 Mac GET 框按 Esc，随后保持在 Terminal 等待状态读回。')
            value = self.request()
            identifier = value.get('approval_id')
            if value.get('status') not in ('approval_pending', 'still_pending') or not identifier:
                raise RuntimeError('remaining_escape_became_terminal_result')
            self.cue('确认刚才已在 Mac GET 框按 Esc；本次没有授予权限，按回车核对等待状态。')
            state, row = self.await_approval_state(identifier, {'waiting'})
            if row['execution_started_n'] or row['execution_completed_n']:
                raise RuntimeError('remaining_escape_executed')
            self.receipt['cases'].append({'case': 'remote_escape', 'result': value, 'state': row})
            end = time.monotonic() + 30
            while time.monotonic() < end:
                observed = self.readback('mac')
                if any(event.get('op') == 'remote_ui_rejected'
                       and event.get('approval_id') == identifier
                       and event.get('reason') == 'user_cancelled' for event in observed['events']):
                    self.receipt['mac_escape_readback'] = observed
                    break
                time.sleep(1)
            else:
                raise RuntimeError('remaining_escape_not_observed_by_real_producer')
        self.cue('SE 取消用例：下一张一小时授权的普通确认请确认；系统 Touch ID 窗口请点击取消，不按指纹。')
        grant_args = ['remote', NDU, 'allow', '--credential', 'api_key/r3a-graph-readonly',
                      '--hosts', 'graph.microsoft.com', '--methods', 'GET', '--paths', '/v1.0/me', '--until', '1h']
        cancelled = self.command('strong_sign_cancelled', grant_args, expect_ok=False)
        if cancelled['exit'] == 0:
            raise RuntimeError('remaining_cancelled_signature_unexpected_success')
        self.receipt['native_se_cancel_verified'] = cancelled['result'].get('error_code') == 'key_operation_cancelled'
        if not self.receipt['native_se_cancel_verified']:
            raise RuntimeError('remaining_se_cancel_not_preserved_as_typed_result')
        self.receipt['after_se_cancel'] = self.readback()
        if any(row['revoked_at'] is None for row in self.receipt['after_se_cancel']['grants']):
            raise RuntimeError('remaining_cancelled_signature_created_grant')
        self.actor()
        self.cue('待用批准：下一条 Mac GET 先不要操作，等 Terminal 显示“执行进程已退出”后再点 Allow／仅本次。')
        value = self.request()
        identifier = value.get('approval_id')
        if value.get('status') not in ('approval_pending', 'still_pending') or not identifier:
            raise RuntimeError('remaining_unused_request_not_waiting')
        self.close_actor()
        identity = self.identities[-1]
        probe = ('from pathlib import Path\nimport json\np=Path("/proc")/'+repr(str(identity['parent_pid']))+'\n'
                 'print(json.dumps({"original_actor_absent":not p.exists()}))\n')
        process = subprocess.run(SSH + ['/usr/bin/python3 -'], input=probe,
                                 capture_output=True, text=True, timeout=15)
        if process.returncode or not json.loads(process.stdout).get('original_actor_absent'):
            raise RuntimeError('remaining_original_actor_still_running')
        print('执行进程已退出；现在在该 Mac GET 框点击 Allow／仅本次。', flush=True)
        state, unused = self.await_approval_state(identifier, {'approved_unused'})
        if unused['execution_started_n'] or unused['execution_completed_n']:
            raise RuntimeError('remaining_unused_approval_executed')
        self.receipt['cases'].append({'case': 'approved_unused', 'state': unused})
        self.cue('签发一小时 T1 Grant：在 Mac 完成普通确认，再按一次 Touch ID。')
        self.command('allow_1h', grant_args)
        end = time.monotonic() + 30
        while time.monotonic() < end:
            state = self.readback()
            active = [row for row in state['grants'] if row['revoked_at'] is None
                      and row['iss'] == MAC and row['aud'] == NDU]
            if active:
                break
            time.sleep(1)
        else:
            raise RuntimeError('remaining_grant_not_installed')
        unused = next(row for row in state['approvals'] if row['id'] == identifier)
        if unused['state'] != 'approved_unused':
            raise RuntimeError('remaining_unused_approval_expired_before_revoke')
        self.receipt['before_revoke'] = state
        self.receipt['test_grant_ids'] = [row['jti'] for row in active]
        self.cue('正向吊销：在 Mac 核对被吊销的是 ndu，确认并按一次 Touch ID；随后自动读回失效时间。')
        self.receipt['revocation_started'] = True
        begin = time.monotonic()
        self.command('devices_revoke_ndu', ['devices', 'revoke', NDU])
        end = begin + 60
        while time.monotonic() < end:
            state = self.readback()
            removed = bool(state['device'] and state['device']['revoked_at'] is not None)
            selected = [row for row in state['grants'] if row['jti'] in self.receipt['test_grant_ids']]
            unused = next(row for row in state['approvals'] if row['id'] == identifier)
            if removed and len(selected) == len(active) and all(row['revoked_at'] is not None for row in selected) and unused['state'] == 'cancelled':
                self.receipt['revocation_elapsed_s'] = round(time.monotonic() - begin, 6)
                self.receipt['after_revoke'] = state
                self.receipt['native_forward_revocation_passed'] = True
                break
            time.sleep(.5)
        else:
            self.receipt['after_revoke'] = state
            raise RuntimeError('remaining_revocation_not_applied_within_60s')
        print('ndu 待用批准已取消、测试 Grant 已吊销：' + str(self.receipt['revocation_elapsed_s']) + ' s。', flush=True)
        print('本段完成；保留历史和被吊销身份，不自动重置或重新配对。', flush=True)


def main():
    if os.getuid() != 501:
        raise SystemExit('run_as_mac_owner_without_sudo')
    if sys.argv[1:] not in ([], ['--refresh-presence'], ['--refresh-presence', '--after-delivery']):
        raise SystemExit('remaining_unknown_option')
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    acceptance = Acceptance()
    try:
        acceptance.run(refresh_presence='--refresh-presence' in sys.argv[1:],
                       after_delivery='--after-delivery' in sys.argv[1:])
    except (RuntimeError, KeyboardInterrupt, EOFError, subprocess.TimeoutExpired,
            acceptance.mcp.McpFailure) as error:
        code = str(error) if isinstance(error, RuntimeError) else 'remaining_segment_interrupted'
        acceptance.receipt['fixed_error'] = code if re.fullmatch('[a-z_]{1,100}', code) else 'remaining_segment_interrupted'
        print('本段停止；保留实际结果，不自动重弹或吊销。', flush=True)
        print('停止原因：' + acceptance.receipt['fixed_error'], flush=True)
    finally:
        acceptance.close_actor()
        acceptance.receipt['finished_utc'] = acceptance.now()
        path = ASSETS / ('r3a-remaining-native-' + datetime.datetime.now(
            datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '.json')
        path.write_text(json.dumps(acceptance.receipt, ensure_ascii=False, indent=2) + '\n')
        print('收据已保存。', flush=True)
    if acceptance.receipt.get('fixed_error'):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
