#!/usr/bin/env python3
"""Fake transport and temporary SQLite tests; no installation, sudo, SSH or GUI."""
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest import mock


def load(name, filename):
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


driver = load('remaining_driver_test', 'r3a-native-remaining.py')
collector = load('remaining_collector_test', 'r3a-remaining-snapshot.py')


class PresenceReadiness(unittest.TestCase):
    def setUp(self):
        self.acceptance = driver.Acceptance()
        self.clock = 0
        self.clean = {'pending_n': 0, 'grants_n': 0, 'unattended': False,
                      'mode': 'per_use', 'mac_presence': 'away'}

    def sleep(self, seconds):
        self.clock += seconds

    def test_delivery_does_not_stop_on_the_first_away_read_after_unlock(self):
        present = dict(self.clean, mac_presence='present')

        def cue(message):
            if message.startswith('Esc 用例'):
                raise RuntimeError('ci_stop_after_delivery')

        with mock.patch.object(self.acceptance, 'status', side_effect=[present, present, self.clean, present]), \
                mock.patch.object(self.acceptance, 'prepare'), \
                mock.patch.object(self.acceptance, 'readback', return_value={}), \
                mock.patch.object(self.acceptance, 'actor'), \
                mock.patch.object(self.acceptance, 'cue', side_effect=cue), \
                mock.patch.object(self.acceptance, 'request', return_value={'status': 'approval_denied'}) as request, \
                mock.patch.object(driver.subprocess, 'run', return_value=mock.Mock(returncode=0)), \
                mock.patch.object(driver.time, 'monotonic', side_effect=lambda: self.clock), \
                mock.patch.object(driver.time, 'sleep', side_effect=self.sleep):
            with self.assertRaisesRegex(RuntimeError, '^ci_stop_after_delivery$'):
                self.acceptance.run()
        request.assert_called_once()
        self.assertEqual(self.acceptance.receipt['cases'][0]['before']['mac_presence'], 'present')

    def test_real_hint_may_arrive_after_the_operator_returns(self):
        states = [dict(self.clean), dict(self.clean),
                  dict(self.clean, mac_presence='present')]
        with mock.patch.object(self.acceptance, 'status', side_effect=states) as status, \
                mock.patch.object(driver.time, 'monotonic', side_effect=lambda: self.clock), \
                mock.patch.object(driver.time, 'sleep', side_effect=self.sleep):
            result = self.acceptance.require_present('before_request', seconds=3)
        self.assertEqual(status.call_count, 3)
        self.assertEqual(result['mac_presence'], 'present')
        self.assertEqual(self.acceptance.receipt['presence_readiness'][0]['samples'][0]['mac_presence'], 'away')
        self.assertEqual(self.acceptance.ids, [])

    def test_unknown_or_away_hint_never_gets_relabelled_as_present(self):
        with mock.patch.object(self.acceptance, 'status', return_value=self.clean), \
                mock.patch.object(self.acceptance, 'request') as request, \
                mock.patch.object(driver.time, 'monotonic', side_effect=lambda: self.clock), \
                mock.patch.object(driver.time, 'sleep', side_effect=self.sleep):
            with self.assertRaisesRegex(RuntimeError, '^remaining_present_hint_not_observed$'):
                self.acceptance.require_present('before_request', seconds=2)
        request.assert_not_called()
        self.assertEqual(self.acceptance.receipt['presence_readiness'][0]['samples'][-1]['mac_presence'], 'away')

    def test_presence_wait_cannot_mask_an_unexpected_grant(self):
        with mock.patch.object(self.acceptance, 'status', return_value=dict(self.clean, grants_n=1)), \
                mock.patch.object(driver.time, 'monotonic', side_effect=lambda: self.clock):
            with self.assertRaisesRegex(RuntimeError, '^remaining_requires_clean_executor$'):
                self.acceptance.require_present('before_request', seconds=2)


class Evidence(unittest.TestCase):
    def test_mcp_projection_never_exports_values_or_free_form_reasons(self):
        marker = 'CI_SYNTHETIC_FORBIDDEN_DATA'
        value = driver.public_result({'status': 'approval_pending', 'approval_id': driver.NDU,
                                      'expires_at': 1234, 'reason': marker,
                                      'result': {'body': marker, 'token': marker}})
        self.assertNotIn(marker, json.dumps(value))
        self.assertEqual(value['approval_id'], driver.NDU)

    def test_cli_projection_drops_signed_capabilities_and_raw_error_messages(self):
        marker = 'CI_SYNTHETIC_FORBIDDEN_DATA'
        result = driver.cli_result({'ok': False, 'error': {'code': 'key_operation_failed',
                                                         'message': marker},
                                    'result': {'grant': {'token': marker}, 'credential_value': marker}})
        self.assertEqual(result, {'ok': False, 'error_code': 'key_operation_failed'})

    def test_snapshot_drops_request_values_signed_objects_and_unknown_reasons(self):
        marker = 'CI_SYNTHETIC_FORBIDDEN_DATA'
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.sqlite3'
            db = sqlite3.connect(path)
            db.executescript('''
                CREATE TABLE devices (id TEXT, os TEXT, revoked_at INTEGER);
                CREATE TABLE grants (jti TEXT, iss TEXT, aud TEXT, exp INTEGER,
                                     revoked_at INTEGER, installed_at INTEGER);
                CREATE TABLE pending_approvals (id TEXT, state TEXT, agent_pid INTEGER,
                                               exp INTEGER, request_json TEXT, created_at INTEGER);
                CREATE TABLE remote_audit (seq INTEGER, entry_json TEXT);
            ''')
            db.execute('INSERT INTO devices VALUES(?,?,NULL)', (driver.NDU, 'linux'))
            db.execute('INSERT INTO pending_approvals VALUES(?,?,?,?,?,?)', (
                driver.MAC, 'waiting', 345, 1234,
                json.dumps({'min_level': 'quick', 'tier': 'T1', 'credential_value': marker,
                            'signed_grant': marker, 'delivery': {'mode': 'banner'}}), 1))
            db.execute('INSERT INTO remote_audit VALUES(?,?)', (1, json.dumps({
                'op': 'remote_ui_rejected', 'approval_id': driver.MAC, 'reason': marker, 'token': marker})))
            db.commit()
            db.close()
            result = collector.snapshot(path, driver.NDU, {driver.MAC})
            self.assertNotIn(marker, json.dumps(result))
            self.assertEqual(result['approvals'][0]['execution_started_n'], 0)
            self.assertEqual(result['approvals'][0]['delivery_mode'], 'banner')
            self.assertEqual(result['active_phone_n'], 0)


if __name__ == '__main__':
    unittest.main()
