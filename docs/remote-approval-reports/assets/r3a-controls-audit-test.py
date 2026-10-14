#!/usr/bin/env python3
"""A slow audit must be recorded without aborting the attended control sequence."""
import ast
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest


def snapshot(run):
    source = Path(__file__).with_name('r3a-controls.py').read_text()
    function = next(node for node in ast.parse(source).body
                    if isinstance(node, ast.FunctionDef) and node.name == 'audit_snapshot')
    receipt = {}
    environment = {'subprocess': SimpleNamespace(run=run, TimeoutExpired=subprocess.TimeoutExpired),
                   'cli': '/fake/installed/kv-cli', 'receipt': receipt,
                   'json': json, 'audit_report': SimpleNamespace(project=lambda value: {'matched': value['result']['matched']})}
    exec(compile(ast.Module(body=[function], type_ignores=[]), '<repo-audit-snapshot>', 'exec'), environment)
    environment['audit_snapshot']('baseline')
    return receipt['baseline']


class AuditCollection(unittest.TestCase):
    def test_timeout_is_local_to_the_audit(self):
        def run(args, **kwargs):
            raise subprocess.TimeoutExpired(args, kwargs['timeout'], output=b'fake-private-output')
        result = snapshot(run)
        self.assertEqual(result['fixed_error'], 'native_audit_timed_out')
        self.assertNotIn('fake-private-output', json.dumps(result))

    def test_failed_native_command_is_not_a_successful_audit(self):
        result = snapshot(lambda args, **kwargs: SimpleNamespace(returncode=1, stdout=''))
        self.assertEqual(result['cli_exit'], 1)
        self.assertEqual(result['fixed_error'], 'native_audit_unavailable')
        self.assertNotIn('report', result)

    def test_completed_native_aggregate_is_retained(self):
        result = snapshot(lambda args, **kwargs: SimpleNamespace(returncode=0, stdout='{"result":{"matched":27}}'))
        self.assertEqual(result['report']['matched'], 27)

    def test_exit_three_keeps_an_inconsistent_native_audit(self):
        result = snapshot(lambda args, **kwargs: SimpleNamespace(returncode=3, stdout='{"ok":false,"command":"audit","result":{"matched":37}}'))
        self.assertEqual(result['cli_exit'], 3)
        self.assertEqual(result['report']['matched'], 37)


if __name__ == '__main__':
    unittest.main()
