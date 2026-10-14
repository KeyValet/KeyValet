#!/usr/bin/env python3
"""Give the installed CLI its own foreground TTY; never display its JSON wire."""
import errno
import json
import os
import pty
import re
import resource
import select
import signal
import sys
import termios
import time


def open_terminal():
    # sudo can leave stdin attached to the owner's terminal while allocating a
    # separate controlling TTY. Input must follow the actual terminal stdin.
    if os.isatty(0):
        terminal = os.open(os.ttyname(0), os.O_RDWR | os.O_NOCTTY | os.O_NOFOLLOW)
        if not os.isatty(terminal) or os.fstat(terminal).st_rdev != os.fstat(0).st_rdev:
            os.close(terminal)
            raise RuntimeError('label_terminal_unavailable')
        return terminal
    return os.open('/dev/tty', os.O_RDWR)


def run(command, terminal_fd, timeout=190, diagnostic=None):
    reader, writer = os.pipe()
    child, master = pty.fork()
    if child == 0:
        os.close(reader)
        os.dup2(writer, 1)
        os.close(writer)
        os.close(terminal_fd)
        os.execv(command[0], command)
    os.close(writer)
    attrs = termios.tcgetattr(master)
    attrs[3] &= ~termios.ECHO
    termios.tcsetattr(master, termios.TCSANOW, attrs)
    if diagnostic is not None:
        diagnostic.update({'child_canonical_input':bool(attrs[3]&termios.ICANON),
                           'child_cr_to_nl':bool(attrs[0]&termios.ICRNL),
                           'owner_input_bytes':0,'owner_input_cr':0,'owner_input_nl':0,
                           'label_prompt_detected':False})
    output = bytearray()
    prompt = bytearray()
    awaiting_label = False
    status = None
    deadline = time.monotonic() + timeout
    initially_blocking=os.get_blocking(terminal_fd)
    os.set_blocking(terminal_fd,False)
    try:
        while reader is not None or status is None:
            if time.monotonic() >= deadline:
                raise RuntimeError('label_command_timeout')
            if status is None:
                exited, child_status = os.waitpid(child, os.WNOHANG)
                if exited:
                    status = child_status
            fds = [fd for fd in (reader, master) if fd is not None]
            ready = select.select(fds, [], [], min(.05, max(0, deadline-time.monotonic())))[0]
            if reader in ready:
                data = os.read(reader, 65536)
                if data:
                    output.extend(data)
                    if len(output) > 1024*1024:
                        raise RuntimeError('control_output_too_large')
                else:
                    os.close(reader)
                    reader = None
            if master in ready:
                try:
                    data = os.read(master, 4096)
                except OSError as error:
                    if error.errno != errno.EIO:
                        raise
                    data = b''
                if not data:
                    os.close(master)
                    master = None
                else:
                    # Only native CLI prompts/stderr go to the owner's Terminal. JSON
                    # stdout has a separate pipe and is never copied to the Terminal.
                    os.write(terminal_fd, data)
                    prompt.extend(data)
                    if len(prompt) > 8192:
                        raise RuntimeError('label_prompt_too_large')
                    text = prompt.decode('utf-8', errors='replace')
                    awaiting_label = bool(re.search(
                        r'(?:type executor label .+ (?:to confirm|again \(2/2\)): ?|'
                        r'(?:请输入|请再次输入)执行端标签 .+ 确认(?:（2/2）)?：)$', text))
                    if diagnostic is not None and awaiting_label:
                        diagnostic['label_prompt_detected']=True
            if awaiting_label and status is None and master is not None:
                # select alone cannot request foreground ownership from sudo.
                # A real read raises SIGTTIN for a background command; sudo then
                # resumes it in the foreground. Nonblocking I/O preserves the
                # same deadline while the owner has not entered a line yet.
                try:
                    data = os.read(terminal_fd,4096)
                except (BlockingIOError,InterruptedError):
                    continue
                if not data:
                    raise RuntimeError('label_terminal_unavailable')
                if diagnostic is not None:
                    diagnostic['owner_input_bytes']+=len(data)
                    diagnostic['owner_input_cr']+=data.count(b'\r')
                    diagnostic['owner_input_nl']+=data.count(b'\n')
                os.write(master, data)
                if b'\n' in data:
                    awaiting_label = False
                    prompt.clear()
        return os.waitstatus_to_exitcode(status), bytes(output)
    finally:
        os.set_blocking(terminal_fd,initially_blocking)
        if status is None:
            try:
                os.kill(child, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(child, 0)
        for fd in (reader, master):
            if fd is not None:
                os.close(fd)


if __name__ == '__main__':
    if os.geteuid() != 0 or sys.argv[1:] != ['unattended-1h']:
        raise SystemExit('invalid_label_command_context')
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    terminal = open_terminal()
    try:
        code, output = run(['/usr/local/lib/keyvalet/bin/kv-cli', 'remote',
                            '01M4S8KJ48BSMNK1S4BEGT07FC', 'unattended',
                            '--include-sensitive', '--until', '1h', '--json'], terminal)
        sys.stdout.buffer.write(output)
        sys.stdout.buffer.flush()
    except (OSError, RuntimeError, KeyboardInterrupt) as error:
        code = 6 if isinstance(error, KeyboardInterrupt) else 3
        reason = str(error) if isinstance(error, RuntimeError) else 'label_terminal_unavailable'
        print(json.dumps({'ok': False, 'error': {'code': reason}}))
    finally:
        os.close(terminal)
    raise SystemExit(code)
