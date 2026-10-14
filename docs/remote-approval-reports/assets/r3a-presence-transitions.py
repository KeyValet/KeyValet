#!/usr/bin/env python3
"""Observe real OS transitions and the installed executor's authenticated hints."""
import ctypes
import datetime
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys
import threading
import time

if os.getuid() != 501:
    raise SystemExit('run_as_mac_owner_without_sudo')
os.umask(0o077)
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
assets = Path(__file__).resolve().parent
started = time.monotonic()
receipt = {'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
           'read_only_keyvalet': True, 'keyvalet_approval_requests': 0,
           'keyvalet_touch_id_requests': 0, 'secret_values_in_evidence': False,
           'samples': [], 'os_events': [], 'phases': []}
stop = threading.Event()
ready = threading.Event()
target = '01M4SM5QTRQKNQE1TD6FBJTG79'
self_check = sys.argv[1:] == ['--observer-self-check']
measure_only = sys.argv[1:] == ['--measure-only']
if sys.argv[1:] and not (self_check or measure_only):
    raise SystemExit('unknown_diagnostic_option')
receipt['observer_self_check_only'] = self_check
receipt['measurement_only'] = measure_only


def deadline(_signal, _frame):
    raise RuntimeError('presence_observation_window_expired')


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def notifications():
    if threading.current_thread() is not threading.main_thread():
        raise RuntimeError('notification_dispatch_not_on_main_thread')
    cf = ctypes.CDLL('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')
    pointer = ctypes.c_void_p
    cf.CFNotificationCenterGetDistributedCenter.restype = pointer
    cf.CFStringCreateWithCString.argtypes = [pointer, ctypes.c_char_p, ctypes.c_uint32]
    cf.CFStringCreateWithCString.restype = pointer
    cf.CFStringGetCString.argtypes = [pointer, pointer, ctypes.c_long, ctypes.c_uint32]
    cf.CFStringGetCString.restype = ctypes.c_ubyte
    callback_type = ctypes.CFUNCTYPE(None, pointer, pointer, pointer, pointer, pointer)
    cf.CFNotificationCenterAddObserver.argtypes = [pointer, pointer, callback_type, pointer, pointer, ctypes.c_long]
    cf.CFNotificationCenterRemoveEveryObserver.argtypes = [pointer, pointer]
    cf.CFNotificationCenterPostNotification.argtypes = [pointer, pointer, pointer, pointer, ctypes.c_ubyte]
    cf.CFRelease.argtypes = [pointer]
    cf.CFRunLoopRunInMode.argtypes = [pointer, ctypes.c_double, ctypes.c_ubyte]
    cf.CFRunLoopRunInMode.restype = ctypes.c_int32
    events = {'com.apple.screenIsLocked': 'locked',
              'com.apple.screenIsUnlocked': 'unlocked',
              'com.apple.screensaver.didstart': 'screensaver_started',
              'com.apple.screensaver.didstop': 'screensaver_stopped'}
    if self_check:
        # A private diagnostic name cannot change the product's lock/saver cache.
        events = {'dev.keyvalet.r3a.observer-check.' + str(os.getpid()): 'observer_check'}

    @callback_type
    def receive(_center, _observer, name, _object, _info):
        buffer = ctypes.create_string_buffer(256)
        if name and cf.CFStringGetCString(name, buffer, len(buffer), 0x08000100):
            kind = events.get(buffer.value.decode('utf-8', errors='replace'))
            if kind:
                receipt['os_events'].append({'event': kind, 'observed_utc': now(),
                                             'elapsed_s': round(time.monotonic() - started, 6),
                                             'callback_on_main_thread': threading.current_thread() is threading.main_thread()})
                if self_check:
                    stop.set()

    center = cf.CFNotificationCenterGetDistributedCenter()
    if not center:
        receipt['fixed_error'] = 'distributed_notification_center_unavailable'
        ready.set()
        return
    names = []
    observer = pointer(1)
    mode = pointer.in_dll(cf, 'kCFRunLoopDefaultMode')
    try:
        for name in events:
            value = cf.CFStringCreateWithCString(None, name.encode(), 0x08000100)
            if not value:
                receipt['fixed_error'] = 'notification_name_unavailable'
                ready.set()
                return
            names.append(value)
            cf.CFNotificationCenterAddObserver(center, observer, receive, value, None, 4)
        ready.set()
        if self_check:
            cf.CFNotificationCenterPostNotification(center, names[0], None, None, 1)
            receipt['events_before_main_loop_pump'] = len(receipt['os_events'])
        window_end = time.monotonic() + (5 if self_check else 300)
        while not stop.is_set():
            cf.CFRunLoopRunInMode(mode, .25, 1)
            if time.monotonic() >= window_end:
                raise RuntimeError('notification_observation_window_expired')
        if self_check:
            receipt['observer_self_check_passed'] = any(
                event['event'] == 'observer_check' and event['callback_on_main_thread']
                for event in receipt['os_events'])
    finally:
        cf.CFNotificationCenterRemoveEveryObserver(center, observer)
        for name in names:
            cf.CFRelease(name)


def poll_executor():
    while not stop.is_set():
        row = {'observed_utc': now(), 'elapsed_s': round(time.monotonic() - started, 6)}
        try:
            process = subprocess.run([
                '/usr/bin/ssh', '-T', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5',
                'ndu', 'sudo -n /usr/local/lib/keyvalet/bin/kv-cli status --json',
            ], stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10)
            row['exit'] = process.returncode
            value = json.loads(process.stdout)
            state = value.get('result', {}).get('remote') or {}
            row['ok'] = value.get('ok') is True and bool(state)
            for peer in state.get('approvers', []):
                if peer.get('device_id') == target and peer.get('presence') in ('present', 'away'):
                    row['mac_presence'] = peer['presence']
            for key in ('pending_n', 'grants_n', 'unattended'):
                if isinstance(state.get(key), (bool, int)):
                    row[key] = state[key]
        except (ValueError, KeyError, TypeError, subprocess.TimeoutExpired):
            row['fixed_error'] = 'executor_presence_readback_unavailable'
        row['request_started_elapsed_s'] = row['elapsed_s']
        row['elapsed_s'] = round(time.monotonic() - started, 6)
        row['observed_utc'] = now()
        receipt['samples'].append(row)
        stop.wait(1)


def phase(name, expected=None):
    phase_started = time.monotonic()
    time.sleep(6)
    value = receipt['samples'][-1].get('mac_presence') if receipt['samples'] else None
    while expected is not None and value != expected and time.monotonic() - phase_started < 30:
        if stop.wait(1):
            raise RuntimeError('presence_observation_interrupted')
        value = receipt['samples'][-1].get('mac_presence') if receipt['samples'] else None
    receipt['phases'].append({'phase': name, 'observed_utc': now(),
                              'elapsed_s': round(time.monotonic() - started, 6),
                              'mac_presence': value})
    print(name + '：ndu 看到 Mac presence=' + str(value), flush=True)
    return value


poller = threading.Thread(target=poll_executor, daemon=True)


def measured_transitions(event_offset):
    events = receipt['os_events'][event_offset:]
    transitions = []
    for index, event in enumerate(events):
        wanted = {'locked': 'away', 'unlocked': 'present'}.get(event['event'])
        if not wanted:
            continue
        previous = [sample for sample in receipt['samples'] if sample['elapsed_s'] < event['elapsed_s']]
        if not previous or previous[-1].get('mac_presence') == wanted:
            continue
        opposite = 'unlocked' if wanted == 'away' else 'locked'
        boundary = next((other['elapsed_s'] for other in events[index + 1:]
                         if other['event'] == opposite), float('inf'))
        later = [sample for sample in receipt['samples']
                 if event['elapsed_s'] <= sample['elapsed_s'] < boundary
                 and sample.get('mac_presence') == wanted]
        if later:
            transitions.append({'event': event['event'], 'state': wanted,
                                'elapsed_s': round(later[0]['elapsed_s'] - event['elapsed_s'], 6)})
    return transitions


def wait_measured_lock_cycle(event_offset):
    # Enter is only an operator acknowledgement. It is not evidence of OS unlock.
    print('等待真实锁屏、解锁事件和 ndu 状态读回；提前回车不会结束观察。', flush=True)
    while not stop.is_set():
        events = receipt['os_events'][event_offset:]
        locked = next((event for event in events if event['event'] == 'locked'), None)
        unlocked = next((event for event in events if event['event'] == 'unlocked'
                         and locked and event['elapsed_s'] > locked['elapsed_s']), None)
        transitions = measured_transitions(event_offset)
        if locked and unlocked and all(any(row['state'] == state for row in transitions)
                                      for state in ('away', 'present')):
            return transitions
        if unlocked and receipt['samples']:
            if receipt['samples'][-1]['elapsed_s'] >= unlocked['elapsed_s'] + 30:
                raise RuntimeError('authenticated_presence_transition_pair_not_observed')
        if stop.wait(.25):
            break
    raise RuntimeError('presence_observation_interrupted')


def operator_steps():
    try:
        if not ready.wait(5) or receipt.get('fixed_error'):
            raise RuntimeError('notification_observer_not_ready')
        poller.start()
        baseline = phase('baseline')
        print('只观察真实屏保/锁屏和已安装状态；不发起 KeyValet 审批。', flush=True)
        if measure_only:
            if baseline != 'present':
                raise RuntimeError('measurement_requires_authenticated_present_baseline')
        else:
            input('准备好后在此 Terminal 按一次回车，自动开启系统屏保；退出屏保并正常解锁后回到这里：')
            opened = subprocess.run(['/usr/bin/open', '-a', '/System/Library/CoreServices/ScreenSaverEngine.app'],
                                    capture_output=True, timeout=10)
            if opened.returncode:
                raise RuntimeError('screensaver_not_started')
            input('退出屏保并正常解锁后，在此 Terminal 按回车继续：')
            phase('after_screensaver', 'present')
            input('现在在 Mac 按 Control+Command+Q 锁屏，等 10 秒再正常解锁，然后回到这里按回车：')
            present = phase('after_first_unlock', 'present')
            if present != 'present':
                raise RuntimeError('installed_presence_remains_away_after_real_os_transitions')
        event_offset = len(receipt['os_events'])
        input('已确认 present；按 Control+Command+Q 锁屏，等 10 秒再正常解锁，回到这里按回车完成测量：')
        receipt['presence_transitions'] = wait_measured_lock_cycle(event_offset)
        if phase('after_measured_unlock', 'present') != 'present':
            raise RuntimeError('installed_presence_not_present_after_measured_unlock')
        print('在场信号诊断结束；手机投递、真实审批和设备吊销未由本段验证。', flush=True)
    except (RuntimeError, KeyboardInterrupt, EOFError, subprocess.TimeoutExpired) as error:
        receipt['fixed_error'] = str(error) if isinstance(error, RuntimeError) else 'presence_observation_interrupted'
        print('在场信号诊断停止；保留实际 OS 通知与安装路径结果。', flush=True)
    finally:
        stop.set()


operator = threading.Thread(target=operator_steps, daemon=True)
try:
    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(10 if self_check else 300)
    if not self_check:
        operator.start()
    notifications()
except (RuntimeError, KeyboardInterrupt) as error:
    receipt['fixed_error'] = str(error) if isinstance(error, RuntimeError) else 'presence_observation_interrupted'
    print('在场信号诊断停止；旧进程将退出，请不要继续向旧提示输入。', flush=True)
finally:
    signal.alarm(0)
    stop.set()
    if operator.ident is not None:
        operator.join(timeout=1)
    if poller.ident is not None:
        poller.join(timeout=12)
    receipt['finished_utc'] = now()
    stem = 'r3a-presence-observer-self-check-' if self_check else 'r3a-presence-transitions-'
    path = assets / (stem + datetime.datetime.now(
        datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '.json')
    path.write_text(json.dumps(receipt, indent=2) + '\n')
    if self_check:
        print(json.dumps({'observer_self_check_passed': receipt.get('observer_self_check_passed', False),
                          'fixed_error': receipt.get('fixed_error'),
                          'keyvalet_calls': 0, 'touch_id_requests': 0, 'receipt': str(path)}), flush=True)
        if not receipt.get('observer_self_check_passed') or receipt.get('fixed_error'):
            raise SystemExit(1)
    elif receipt.get('fixed_error'):
        raise SystemExit(1)
