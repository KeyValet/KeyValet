#!/usr/bin/env python3
"""Owner's attended system polkit agent, registered before installed CLI exec."""
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys


def start_time(pid):
    stat = (Path('/proc') / str(pid) / 'stat').read_text()
    return int(stat[stat.rfind(')')+2:].split()[19])


def stopped(signum, frame):
    raise SystemExit(128 + signum)


os.umask(0o077)
directory = Path(__file__).resolve().parent
if os.getuid() == 0 or directory.stat().st_uid != os.getuid():
    raise SystemExit('polkit_agent_owner_mismatch')
probe = sys.argv[1:] == ['--probe']
phase = sys.argv[2] if len(sys.argv) == 3 and sys.argv[1] == '--phase' else 'run'
if phase not in ('run', 'refresh', 'samples'):
    raise SystemExit('polkit_agent_unknown_phase')
target = {'pid': os.getpid(), 'start_time': start_time(os.getpid())} if probe else json.loads(
    (directory / (phase+'.pid')).read_text())
pid = target['pid']
status = (Path('/proc') / str(pid) / 'status').read_text().splitlines()
uids = next(row[4:].split() for row in status if row.startswith('Uid:'))
if uids != [str(os.getuid())]*4 or start_time(pid) != target['start_time']:
    raise SystemExit('polkit_agent_subject_mismatch')
for name in ('SIGTERM', 'SIGHUP', 'SIGINT'):
    signal.signal(getattr(signal, name), stopped)
spec = importlib.util.spec_from_file_location('readiness', directory/'r3a-run-readiness.py')
readiness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(readiness)
reader, writer = os.pipe()
agent = None
try:
    tty = open('/dev/tty', 'r+b', buffering=0)
    agent = subprocess.Popen(['/usr/bin/pkttyagent', '--fallback', '--process',
                              str(pid)+','+str(target['start_time']),
                              '--notify-fd', str(writer)],
                             pass_fds=(writer,), stdin=tty, stdout=tty, stderr=tty)
    os.close(writer)
    readiness.wait_agent_registration(agent, reader, 10)
    if probe:
        print('polkit agent registered; authentication requests: 0', flush=True)
    else:
        path = directory/(phase+'-agent.ready.new')
        with path.open('x') as f:
            json.dump(target, f)
        os.replace(path, directory/(phase+'-agent.ready'))
        print('ndu polkit 代理已就绪；接下来是解锁密码提示。', flush=True)
        agent.wait()
finally:
    os.close(reader)
    if agent is not None and agent.poll() is None:
        agent.terminate()
        try:
            agent.wait(timeout=5)
        except subprocess.TimeoutExpired:
            agent.kill();agent.wait()
