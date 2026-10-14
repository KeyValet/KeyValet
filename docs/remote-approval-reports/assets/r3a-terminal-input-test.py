#!/usr/bin/env python3
"""CI regression: fake agent and helper, pipe input only, no install/root/GUI."""
import importlib.util
import os
from pathlib import Path
import select
import subprocess
import sys
import time
import unittest

module_path=Path(os.environ.get('R3A_TERMINAL_INPUT_MODULE',Path(__file__).with_name('r3a-terminal-input.py')))
spec=importlib.util.spec_from_file_location('terminal_input',module_path)
terminal_input=importlib.util.module_from_spec(spec);spec.loader.exec_module(terminal_input)

@unittest.skipUnless(os.name=='posix','POSIX acceptance driver')
class TerminalOwnership(unittest.TestCase):
    def setUp(self):
        self.reader,self.writer=os.pipe()
        self.agent=subprocess.Popen([sys.executable,'-u','-c',
            'import sys; print("ready",flush=True); data=sys.stdin.readline(); print("read",flush=True)'],
            stdin=self.reader,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
        self.assertEqual(self.agent.stdout.readline(),b'ready\n')

    def tearDown(self):
        if self.agent.poll() is None:
            self.agent.terminate()
            self.agent.kill()
        self.agent.wait(timeout=3)
        self.agent.stdout.close()
        os.close(self.reader);os.close(self.writer)

    def test_cue_gets_enter_before_fake_helper_can_be_called(self):
        helper_calls=[]
        with terminal_input.pause_agent_input(self.agent):
            os.write(self.writer,b'\n')
            time.sleep(.05)
            ready=bool(select.select([self.reader],[],[],.2)[0])
            if ready and os.read(self.reader,1)==b'\n':
                helper_calls.append('announced_deny_request')
        self.assertEqual(helper_calls,['announced_deny_request'])

    def test_next_request_registers_a_fresh_agent_after_cue_exception(self):
        with self.assertRaisesRegex(RuntimeError,'synthetic_cue_stop'):
            with terminal_input.pause_agent_input(self.agent):
                raise RuntimeError('synthetic_cue_stop')
        self.assertIsNotNone(self.agent.poll())
        fresh=subprocess.Popen([sys.executable,'-u','-c',
            'import sys; print("ready",flush=True); sys.stdin.readline(); print("read",flush=True)'],
            stdin=self.reader,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
        try:
            self.assertEqual(fresh.stdout.readline(),b'ready\n')
            os.write(self.writer,b'resume\n')
            self.assertTrue(select.select([fresh.stdout],[],[],1)[0])
            self.assertEqual(fresh.stdout.readline(),b'read\n')
        finally:
            if fresh.poll() is None:
                fresh.kill()
            fresh.wait(timeout=3);fresh.stdout.close()

    def test_already_exited_agent_is_harmless(self):
        self.agent.terminate();self.agent.wait(timeout=3)
        with terminal_input.pause_agent_input(self.agent):
            os.write(self.writer,b'\n')
            self.assertEqual(os.read(self.reader,1),b'\n')

if __name__=='__main__':
    unittest.main()
