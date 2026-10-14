#!/usr/bin/env python3
"""Exercise the actual status poller with a fake SSH runner; no install or GUI."""
import ast
import datetime
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest


class Stop:
    def __init__(self):
        self.stopped = False

    def is_set(self):
        return self.stopped

    def wait(self, _duration):
        self.stopped = True


class InputIsolation(unittest.TestCase):
    def exercise(self, timed_out):
        path = Path(__file__).with_name('r3a-presence-transitions.py')
        tree = ast.parse(path.read_text())
        function = next(node for node in tree.body
                        if isinstance(node, ast.FunctionDef) and node.name == 'poll_executor')
        module = ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[]))
        stop = Stop()
        receipt = {'samples': []}

        def run(argv, **kwargs):
            self.assertEqual(argv[0], '/usr/bin/ssh')
            self.assertEqual(kwargs.get('stdin'), subprocess.DEVNULL,
                             'SSH inherits the operator Terminal and can consume confirmation input')
            if timed_out:
                raise subprocess.TimeoutExpired(argv, 10)
            return SimpleNamespace(returncode=0, stdout=json.dumps({
                'ok': True, 'result': {'remote': {'approvers': [
                    {'device_id': 'fake-mac', 'presence': 'present'}],
                    'pending_n': 0, 'grants_n': 0, 'unattended': False,
                    'credential_value': 'synthetic-must-not-export'}}}))

        environment = {'subprocess': SimpleNamespace(run=run, TimeoutExpired=subprocess.TimeoutExpired,
                                                     DEVNULL=subprocess.DEVNULL),
                       'json': json, 'time': SimpleNamespace(monotonic=lambda: 3.0),
                       'now': lambda: datetime.datetime.now(datetime.timezone.utc).isoformat(),
                       'started': 1.0, 'target': 'fake-mac', 'stop': stop, 'receipt': receipt}
        exec(compile(module, str(path), 'exec'), environment)
        environment['poll_executor']()
        self.assertEqual(len(receipt['samples']), 1)
        self.assertNotIn('synthetic-must-not-export', json.dumps(receipt))
        if timed_out:
            self.assertEqual(receipt['samples'][0]['fixed_error'], 'executor_presence_readback_unavailable')
        else:
            self.assertEqual(receipt['samples'][0]['mac_presence'], 'present')

    def test_status_poll_cannot_consume_operator_input(self):
        self.exercise(False)

    def test_timeout_also_keeps_operator_input_private(self):
        self.exercise(True)


class LockObservation(unittest.TestCase):
    def test_early_enter_keeps_observing_until_real_lock_and_unlock(self):
        path = Path(__file__).with_name('r3a-presence-transitions.py')
        tree = ast.parse(path.read_text())
        names = {'operator_steps', 'measured_transitions', 'wait_measured_lock_cycle'}
        functions = [node for node in tree.body
                     if isinstance(node, ast.FunctionDef) and node.name in names]
        module = ast.fix_missing_locations(ast.Module(body=functions, type_ignores=[]))
        receipt = {'samples': [{'elapsed_s': 0, 'mac_presence': 'present'}],
                   'os_events': [], 'phases': []}
        clock = [0.0]

        class Events:
            stopped = False

            def is_set(self):
                return self.stopped

            def set(self):
                self.stopped = True

            def wait(self, duration):
                clock[0] += duration
                if clock[0] >= 2 and not receipt['os_events']:
                    receipt['os_events'].append({'event': 'locked', 'elapsed_s': 2})
                if clock[0] >= 3 and len(receipt['samples']) == 1:
                    receipt['samples'].append({'elapsed_s': 3, 'mac_presence': 'away'})
                if clock[0] >= 12 and len(receipt['os_events']) == 1:
                    receipt['os_events'].append({'event': 'unlocked', 'elapsed_s': 12})
                if clock[0] >= 13 and len(receipt['samples']) == 2:
                    receipt['samples'].append({'elapsed_s': 13, 'mac_presence': 'present'})
                if clock[0] > 45:
                    raise RuntimeError('fake_observation_deadline')
                return self.stopped

        def phase(name, _expected=None):
            if name == 'after_measured_unlock':
                self.assertGreaterEqual(clock[0], 13,
                                        'early Enter stopped the observer before real unlock/readback')
            return 'present'

        environment = {'receipt': receipt, 'ready': SimpleNamespace(wait=lambda _: True),
                       'poller': SimpleNamespace(start=lambda: None), 'stop': Events(),
                       'measure_only': True, 'phase': phase, 'input': lambda _: '',
                       'time': SimpleNamespace(monotonic=lambda: clock[0]),
                       'print': lambda *args, **kwargs: None,
                       'subprocess': SimpleNamespace(TimeoutExpired=subprocess.TimeoutExpired)}
        exec(compile(module, str(path), 'exec'), environment)
        environment['operator_steps']()
        self.assertNotIn('fixed_error', receipt)
        self.assertEqual([(row['event'], row['state']) for row in receipt['presence_transitions']],
                         [('locked', 'away'), ('unlocked', 'present')])


if __name__ == '__main__':
    unittest.main()
