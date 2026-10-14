#!/usr/bin/env python3
"""Fake installed CLI and PTYs; no KeyValet installation, root or GUI."""
import importlib.util
import os
from pathlib import Path
import pty
import select
import sys
import termios
import threading
import time
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('label_command', Path(os.environ.get('R3A_LABEL_MODULE',Path(__file__).with_name('r3a-label-command.py'))))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class LabelCommand(unittest.TestCase):
    def setUp(self):
        self.master, self.terminal = pty.openpty()
        attrs = termios.tcgetattr(self.terminal)
        attrs[3] &= ~termios.ECHO
        termios.tcsetattr(self.terminal, termios.TCSANOW, attrs)

    def tearDown(self):
        os.close(self.master)
        os.close(self.terminal)

    def test_fake_cli_has_foreground_tty_and_reads_two_real_labels(self):
        transcript = bytearray()
        stop = threading.Event()
        def owner():
            answered = 0
            while not stop.is_set():
                if not select.select([self.master], [], [], .05)[0]:
                    continue
                data = os.read(self.master, 4096)
                transcript.extend(data)
                count = transcript.count(b'confirm:')
                if count > answered:
                    os.write(self.master, b'ci-executor\n')
                    answered += 1
        thread = threading.Thread(target=owner)
        thread.start()
        try:
            code, output = module.run([sys.executable, '-u', '-c', '''
import json, os, sys
with open('/dev/tty', 'r+b', buffering=0) as tty:
    assert os.tcgetpgrp(tty.fileno()) == os.getpgrp()
    assert not sys.stdout.isatty()
    for round in range(2):
        tty.write(b'type executor label ci-executor to confirm:')
        assert tty.readline() == b'ci-executor\\n'
print(json.dumps({'ok': True, 'test_private_output': 'NEVER_DISPLAY_ON_TTY'}))
'''], self.terminal, timeout=3)
            self.assertEqual(code, 0)
            self.assertIn(b'"ok": true', output)
        finally:
            stop.set()
            thread.join(timeout=2)
        self.assertEqual(transcript.count(b'confirm:'), 2)
        self.assertNotIn(b'NEVER_DISPLAY_ON_TTY', transcript)

    def test_timeout_terminates_the_fake_cli(self):
        with self.assertRaisesRegex(RuntimeError, 'label_command_timeout'):
            module.run([sys.executable, '-c', 'import time; time.sleep(30)'], self.terminal, timeout=.2)

    def test_missing_tty_readiness_does_not_hide_a_wrong_label(self):
        real_select=select.select
        transcript=bytearray()
        stop=threading.Event()
        def owner():
            while not stop.is_set():
                if not real_select([self.master],[],[],.05)[0]:continue
                transcript.extend(os.read(self.master,4096))
                if b'confirm:' in transcript:
                    os.write(self.master,b'aaa\n')
                    return
        def background_select(readers,writers,errors,timeout):
            return real_select([fd for fd in readers if fd!=self.terminal],writers,errors,timeout)
        thread=threading.Thread(target=owner);thread.start()
        try:
            with mock.patch.object(module.select,'select',side_effect=background_select):
                code,output=module.run([sys.executable,'-u','-c','import json,sys; tty=open("/dev/tty","r+b",buffering=0); tty.write(b"type executor label ci-executor to confirm:"); answer=tty.readline(); ok=answer==b"ci-executor\\n"; print(json.dumps({"ok":ok,"issued":0})); sys.exit(0 if ok else 6)'],self.terminal,timeout=.8)
            self.assertEqual(code,6)
            self.assertEqual(__import__('json').loads(output),{'ok':False,'issued':0})
        finally:
            stop.set();thread.join(timeout=2)

    def test_output_is_bounded(self):
        with self.assertRaisesRegex(RuntimeError, 'control_output_too_large'):
            module.run([sys.executable, '-c', 'import sys; sys.stdout.write("x"*(1024*1024+1))'], self.terminal, timeout=3)

    def test_controlling_terminal_alias_forwards_the_owners_input(self):
        result_reader, result_writer = os.pipe()
        controller, outer_master = pty.fork()
        if controller == 0:
            os.close(result_reader)
            terminal = getattr(module, 'open_terminal', lambda: os.open('/dev/tty', os.O_RDWR))()
            try:
                code, output = module.run([sys.executable, '-u', '-c', '''
import json
with open('/dev/tty', 'r+b', buffering=0) as tty:
    tty.write(b'type executor label ci-executor to confirm:')
    answer = tty.readline()
print(json.dumps({'ok': answer == b'ci-executor\\n'}))
'''], terminal, timeout=.8)
                import json
                result = {'exit': code, 'output': json.loads(output)}
            except RuntimeError as error:
                result = {'fixed_error': str(error)}
            os.write(result_writer, __import__('json').dumps(result).encode())
            os._exit(0)
        os.close(result_writer)
        transcript = bytearray()
        sent = False
        deadline = time.monotonic()+3
        try:
            while time.monotonic() < deadline:
                ready = select.select([outer_master,result_reader],[],[],.05)[0]
                if outer_master in ready:
                    try:
                        data = os.read(outer_master,4096)
                    except OSError:
                        data = b''
                    transcript.extend(data)
                    if b'confirm:' in transcript and not sent:
                        os.write(outer_master,b'ci-executor\n')
                        sent = True
                if result_reader in ready:
                    result = __import__('json').loads(os.read(result_reader,4096))
                    break
            else:
                self.fail('fake owner result not received')
            self.assertTrue(sent)
            self.assertEqual(result, {'exit':0,'output':{'ok':True}})
        finally:
            os.close(result_reader)
            os.close(outer_master)
            try:
                os.kill(controller,9)
            except ProcessLookupError:
                pass
            os.waitpid(controller,0)

    def test_sudo_style_separate_stdin_and_controlling_tty_rejects_wrong_label(self):
        input_master, input_slave = pty.openpty()
        result_reader, result_writer = os.pipe()
        controller, display_master = pty.fork()
        if controller == 0:
            os.close(result_reader)
            os.dup2(input_slave,0)
            os.close(input_slave)
            os.close(input_master)
            terminal = getattr(module, 'open_terminal', lambda: os.open('/dev/tty', os.O_RDWR))()
            try:
                code, output = module.run([sys.executable,'-u','-c','''
import json,sys
with open('/dev/tty','r+b',buffering=0) as tty:
    tty.write(b'type executor label ci-executor to confirm:')
    answer=tty.readline()
ok=answer==b'ci-executor\\n'
print(json.dumps({'ok':ok,'issued':0}))
sys.exit(0 if ok else 6)
'''],terminal,timeout=.8)
                result={'exit':code,'output':__import__('json').loads(output)}
            except RuntimeError as error:
                result={'fixed_error':str(error)}
            os.write(result_writer,__import__('json').dumps(result).encode())
            os._exit(0)
        os.close(result_writer)
        os.close(input_slave)
        transcript=bytearray()
        sent=False
        deadline=time.monotonic()+3
        try:
            while time.monotonic()<deadline:
                ready=select.select([display_master,input_master,result_reader],[],[],.05)[0]
                for fd in (display_master,input_master):
                    if fd in ready:
                        try:data=os.read(fd,4096)
                        except OSError:data=b''
                        transcript.extend(data)
                if b'confirm:' in transcript and not sent:
                    os.write(input_master,b'aaa\n')
                    sent=True
                if result_reader in ready:
                    result=__import__('json').loads(os.read(result_reader,4096))
                    break
            else:self.fail('fake sudo-style owner result not received')
            self.assertTrue(sent)
            self.assertEqual(result,{'exit':6,'output':{'ok':False,'issued':0}})
        finally:
            for fd in (input_master,display_master,result_reader):os.close(fd)
            try:os.kill(controller,9)
            except ProcessLookupError:pass
            os.waitpid(controller,0)

    def test_sudo_background_reader_requests_foreground_before_consuming_input(self):
        result_reader,result_writer=os.pipe()
        monitor,display_master=pty.fork()
        if monitor==0:
            import signal
            os.close(result_reader)
            worker=os.fork()
            if worker==0:
                os.setpgid(0,0)
                signal.signal(signal.SIGTTIN,signal.SIG_DFL)
                terminal=getattr(module,'open_terminal',lambda:os.open('/dev/tty',os.O_RDWR))()
                try:
                    code,output=module.run([sys.executable,'-u','-c','''
import json,sys
with open('/dev/tty','r+b',buffering=0) as tty:
    tty.write(b'type executor label ci-executor to confirm:')
    answer=tty.readline()
ok=answer==b'ci-executor\\n'
print(json.dumps({'ok':ok,'issued':0}))
sys.exit(0 if ok else 6)
'''],terminal,timeout=.8)
                    result={'exit':code,'output':__import__('json').loads(output)}
                except RuntimeError as error:result={'fixed_error':str(error)}
                os.write(result_writer,__import__('json').dumps(result).encode())
                os._exit(0)
            os.setpgid(worker,worker)
            signal.signal(signal.SIGTTOU,signal.SIG_IGN)
            requested=False
            while True:
                child,status=os.waitpid(worker,os.WUNTRACED)
                if os.WIFSTOPPED(status) and os.WSTOPSIG(status)==signal.SIGTTIN:
                    requested=True
                    os.tcsetpgrp(0,worker)
                    os.kill(worker,signal.SIGCONT)
                elif os.WIFEXITED(status) or os.WIFSIGNALED(status):break
            os._exit(0 if requested else 1)
        os.close(result_writer)
        sent=False
        transcript=bytearray()
        deadline=time.monotonic()+3
        try:
            while time.monotonic()<deadline:
                ready=select.select([display_master,result_reader],[],[],.05)[0]
                if display_master in ready:
                    try:data=os.read(display_master,4096)
                    except OSError:data=b''
                    transcript.extend(data)
                    if b'confirm:' in transcript and not sent:
                        os.write(display_master,b'aaa\n')
                        sent=True
                if result_reader in ready:
                    result=__import__('json').loads(os.read(result_reader,4096))
                    break
            else:self.fail('fake sudo monitor result not received')
            self.assertTrue(sent)
            self.assertEqual(result,{'exit':6,'output':{'ok':False,'issued':0}})
            _,status=os.waitpid(monitor,0)
            self.assertEqual(os.waitstatus_to_exitcode(status),0)
            monitor=None
        finally:
            for fd in (display_master,result_reader):os.close(fd)
            if monitor is not None:
                try:os.kill(monitor,9)
                except ProcessLookupError:pass
                os.waitpid(monitor,0)


if __name__ == '__main__':
    unittest.main()
