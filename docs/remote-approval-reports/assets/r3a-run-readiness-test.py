#!/usr/bin/env python3
"""Isolated CI reproduction: authentication may begin only after agent registration."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import unittest


def load():
    path = Path(os.environ.get('R3A_READINESS_MODULE',
                              Path(__file__).with_name('r3a-run-readiness.py')))
    spec = importlib.util.spec_from_file_location('r3a_run_readiness', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RegistrationOrder(unittest.TestCase):
    def fake(self, source):
        reader, writer = os.pipe()
        agent = subprocess.Popen([sys.executable, '-c', source, str(writer)],
                                 pass_fds=(writer,), stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
        os.close(writer)
        self.addCleanup(os.close, reader)
        self.addCleanup(self.stop, agent)
        return agent, reader

    @staticmethod
    def stop(agent):
        if agent.poll() is None:
            agent.terminate()
        agent.wait(timeout=5)

    def test_authentication_waits_for_delayed_registration(self):
        # The fake helper refuses before registration; its state is the still-open
        # notify fd. No installed binaries, root, polkit or GUI are involved.
        agent, reader = self.fake('import os,sys,time; time.sleep(.15); '
                                  'os.close(int(sys.argv[1])); time.sleep(30)')
        load().wait_agent_registration(agent, reader, 2)
        os.set_blocking(reader, False)
        self.assertEqual(os.read(reader, 1), b'')
        self.assertIsNone(agent.poll())

    def test_failed_agent_cannot_start_authentication(self):
        agent, reader = self.fake('import sys; sys.exit(127)')
        with self.assertRaisesRegex(RuntimeError, 'polkit_agent_registration_failed'):
            load().wait_agent_registration(agent, reader, 2)

    def test_missing_registration_times_out_without_authentication(self):
        agent, reader = self.fake('import time; time.sleep(30)')
        with self.assertRaisesRegex(RuntimeError, 'polkit_agent_registration_timeout'):
            load().wait_agent_registration(agent, reader, .05)


if __name__ == '__main__':
    unittest.main()
