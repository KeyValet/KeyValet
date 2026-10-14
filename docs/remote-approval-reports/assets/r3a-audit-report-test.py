#!/usr/bin/env python3
"""CI acceptance-report regression; native audit DTOs contain aggregates, not entries."""
import copy
import importlib.util
from pathlib import Path
import unittest


def project(value):
    spec = importlib.util.spec_from_file_location('audit', Path(__file__).with_name('r3a-audit-report.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.project(value)


def frame():
    return {'ok': True, 'command': 'audit', 'result': {
        'consistent': True, 'comparison': {'matched': 2, 'findings': []},
        'unavailable': [], 'endpoints': [
            {'device_id': 'mac', 'entries': 7, 'checkpoint': 'vault_authenticated_metadata', 'head': {'seq': 7, 'hash': 'a'*64}},
            {'device_id': 'ndu', 'entries': 8, 'checkpoint': 'vault_authenticated_metadata', 'head': {'seq': 8, 'hash': 'b'*64}},
        ]}}


class AuditProjection(unittest.TestCase):
    def test_native_aggregate_matches_without_raw_entries(self):
        value = project(frame())
        self.assertEqual(value['matched'], 2)
        self.assertIs(value['consistent'], True)
        self.assertEqual(value['findings_count'], 0)

    def test_findings_are_retained_as_findings(self):
        value = frame()
        value['result']['consistent'] = False
        value['result']['comparison']['findings'] = [{'problem': 'hash_mismatch'}]
        projected = project(value)
        self.assertIs(projected['consistent'], False)
        self.assertEqual(projected['findings_count'], 1)

    def test_native_inconsistent_exit_still_retains_the_comparison(self):
        value = frame()
        value['ok'] = False
        value['result']['consistent'] = False
        value['result']['comparison']['findings'] = [{'problem': 'missing_receiver_record'}]
        projected = project(value)
        self.assertEqual(projected['matched'], 2)
        self.assertEqual(projected['findings_count'], 1)
        self.assertIs(projected['consistent'], False)

    def test_missing_peer_is_not_a_complete_two_endpoint_audit(self):
        value = frame()
        value['result']['consistent'] = False
        value['result']['unavailable'] = [['ndu', 'timeout']]
        value['result']['endpoints'] = value['result']['endpoints'][:1]
        projected = project(value)
        self.assertIs(projected['consistent'], False)
        self.assertEqual(projected['unavailable_count'], 1)


if __name__ == '__main__':
    unittest.main()
