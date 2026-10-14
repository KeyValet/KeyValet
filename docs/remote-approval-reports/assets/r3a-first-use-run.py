#!/usr/bin/env python3
"""Owner-attended installed keyvalet run + curl fallback; no proxy/credential transcripts."""
import datetime
import json
import os
from pathlib import Path
import queue
import resource
import subprocess
import threading
import time

if os.getuid() != 501:
    raise SystemExit('Run as the Mac owner, without sudo')
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
os.umask(0o077)
assets = Path('/Users/guang/dev/keyvalet/docs/remote-approval-reports/assets')
ssh = ['/usr/bin/ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8']
receipt = {'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
           'runtime': 'installed keyvalet run + curl',
           'credential': 'api_key/r3a-graph-readonly',
           'method': 'GET', 'url': 'https://graph.microsoft.com/v1.0/me',
           'credential_values_saved': False, 'http_statuses': []}
started = time.monotonic()
agent = None
child = None

# The owner wrapper waits for pkttyagent registration, then execs the installed
# CLI with the same PID, start time and UID. No runtime authentication starts early.
find_code = r'''
import json,os
from pathlib import Path
p=Path('/tmp/keyvalet-r3a-native/run.pid')
if not p.exists(): raise SystemExit(0)
target=json.loads(p.read_text());base=Path('/proc')/str(target['pid'])
uids=next(row[4:].split() for row in (base/'status').read_text().splitlines() if row.startswith('Uid:'))
stat=(base/'stat').read_text();start=int(stat[stat.rfind(')')+2:].split()[19])
if uids==[str(os.getuid())]*4 and start==target['start_time']:
 print(json.dumps(target))
'''

try:
    wrapper = r'''import json,os,resource,time
from pathlib import Path
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
d=Path('/tmp/keyvalet-r3a-native')
if d.is_symlink() or d.stat().st_uid!=os.getuid():raise SystemExit(1)
stat=(Path('/proc')/str(os.getpid())/'stat').read_text()
target={'pid':os.getpid(),'start_time':int(stat[stat.rfind(')')+2:].split()[19]),'uid':os.getuid()}
p=d/'run.pid.new'
with p.open('x') as f:json.dump(target,f)
os.chmod(p,0o600)
os.replace(p,d/'run.pid')
ready=d/'run-agent.ready'
deadline=time.monotonic()+30
while time.monotonic()<deadline:
 if ready.exists():
  if ready.is_symlink() or ready.stat().st_uid!=os.getuid():raise SystemExit(1)
  if json.loads(ready.read_text())==target:break
 time.sleep(.05)
else:raise SystemExit('polkit_agent_registration_timeout')
os.execv('/usr/local/lib/keyvalet/bin/kv-cli',['keyvalet','run','--inject','api_key/r3a-graph-readonly','--','/usr/bin/curl','--silent','--show-error','--output','/dev/null','--write-out','%{http_code}\n','--max-time','120','--request','GET','https://graph.microsoft.com/v1.0/me'])
'''
    sources = {'run-exec.py': wrapper,
               'r3a-run-agent.py': (assets/'r3a-run-agent.py').read_text(),
               'r3a-run-readiness.py': (assets/'r3a-run-readiness.py').read_text()}
    code = "from pathlib import Path\nimport os\nd=Path('/tmp/keyvalet-r3a-native')\nif d.is_symlink() or d.stat().st_uid!=os.getuid():raise SystemExit(1)\nfor name,source in "+repr(sources)+".items():\n p=d/name\n if p.is_symlink():raise SystemExit(1)\n p.write_text(source)\n os.chmod(p,0o600)\nfor name in ('run.pid','run.pid.new','run-agent.ready','run-agent.ready.new'):\n p=d/name\n if p.is_symlink():raise SystemExit(1)\n if p.exists():p.unlink()\n"
    setup = subprocess.run(ssh+['ndu', '/usr/bin/python3 -'], input=code,
                           capture_output=True, text=True, timeout=20)
    if setup.returncode:
        raise RuntimeError('run_driver_setup_failed')
    print('先准备 ndu 的 polkit 代理；代理就绪后才启动已安装 keyvalet run。', flush=True)
    child = subprocess.Popen(ssh+['ndu', '/usr/bin/python3 /tmp/keyvalet-r3a-native/run-exec.py'],
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    events = queue.Queue()

    def read_output():
        for line in child.stdout:
            text = line.decode(errors='replace').strip()
            if len(text) == 3 and text.isdigit():
                events.put(int(text))
        events.put(None)

    def read_errors():
        fixed = ['Helper authentication failed', 'Cannot drop root privileges',
                 'Helper connection closed', 'Proxy control request timed out',
                 'Gateway approval did not authorize this binding',
                 'Reusable gateways are unavailable in per-use mode',
                 'The KeyValet daemon is not running']
        for line in child.stderr:
            text = line.decode(errors='replace')
            for code in fixed:
                if code in text:
                    receipt.setdefault('fixed_errors', []).append(code)

    threading.Thread(target=read_output, daemon=True).start()
    threading.Thread(target=read_errors, daemon=True).start()
    deadline = time.monotonic()+360
    while time.monotonic() < deadline:
        if agent is None and child.poll() is None:
            probe = subprocess.run(ssh+['ndu', '/usr/bin/python3 -'],
                                   input=find_code, capture_output=True, text=True, timeout=15)
            if probe.returncode == 0 and probe.stdout.strip():
                identity = json.loads(probe.stdout)
                receipt['run_process'] = identity
                print('请在此 Terminal 输入 ndu 用户 guang 的 polkit 密码；之后审批 Mac 的网关确认与 GET。', flush=True)
                agent = subprocess.Popen(ssh+['-tt', 'ndu', '/usr/bin/python3 /tmp/keyvalet-r3a-native/r3a-run-agent.py'])
        try:
            event = events.get(timeout=0.25)
        except queue.Empty:
            continue
        if event is None:
            break
        receipt['http_statuses'].append(event)
        receipt['http_result_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        receipt['elapsed_to_http_result_s'] = round(time.monotonic()-started, 6)
    if child.poll() is None:
        child.terminate()
    child.wait(timeout=5)
    receipt['run_exit'] = child.returncode
    print('HTTP 状态：'+str(receipt['http_statuses'])+'；run 退出码：'+str(child.returncode), flush=True)
except (RuntimeError, subprocess.TimeoutExpired, ValueError) as error:
    receipt['fixed_error'] = str(error) if isinstance(error, RuntimeError) else 'run_driver_unavailable'
    print('本段停止；仅保存固定诊断码。', flush=True)
finally:
    for process in (agent, child):
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill();process.wait()
    receipt['elapsed_s'] = round(time.monotonic()-started, 6)
    receipt['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    path = assets/('r3a-first-run-'+datetime.datetime.now(datetime.timezone.utc).strftime('%H%M%S')+'.json')
    path.write_text(json.dumps(receipt, indent=2)+'\n')
    print('本段执行结束；收据不含 token、代理会话令牌或响应体。', flush=True)
