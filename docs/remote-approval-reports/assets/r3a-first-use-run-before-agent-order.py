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

# The ordinary wrapper runs sudo, then the installed run command permanently drops
# privileges. Find that actual CLI child through the wrapper's kernel process tree.
find_code = r'''
import json,os
from pathlib import Path
p=Path('/tmp/keyvalet-r3a-native/run.pid')
if not p.exists(): raise SystemExit(0)
text=p.read_text().strip()
if not text.isdigit(): raise SystemExit(0)
pending=[int(text)];seen=set()
for _ in range(5):
 next_level=[]
 for pid in pending:
  if pid in seen:continue
  seen.add(pid);base=Path('/proc')/str(pid)
  try:
   exe=str((base/'exe').readlink())
   uid=next(row[4:].split() for row in (base/'status').read_text().splitlines() if row.startswith('Uid:'))
   if exe=='/usr/local/lib/keyvalet/bin/kv-cli' and uid==['1000']*4:
    print(json.dumps({'pid':pid,'uid':1000,'executable':exe}));raise SystemExit(0)
   next_level.extend(int(v) for v in (base/'task'/str(pid)/'children').read_text().split())
  except OSError:pass
 pending=next_level
'''

try:
    wrapper = r'''import os,resource
from pathlib import Path
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
p=Path('/tmp/keyvalet-r3a-native/run.pid')
if p.is_symlink():raise SystemExit(1)
with p.open('w') as f:f.write(str(os.getpid())+'\n')
os.chmod(p,0o600)
os.execv('/usr/local/bin/keyvalet',['keyvalet','run','--inject','api_key/r3a-graph-readonly','--','/usr/bin/curl','--silent','--show-error','--output','/dev/null','--write-out','%{http_code}\n','--max-time','120','--request','GET','https://graph.microsoft.com/v1.0/me'])
'''
    code = "from pathlib import Path\nimport os\np=Path('/tmp/keyvalet-r3a-native/run-exec.py')\nif p.is_symlink():raise SystemExit(1)\np.write_text("+repr(wrapper)+")\nos.chmod(p,0o600)\n"
    setup = subprocess.run(ssh+['ndu', '/usr/bin/python3 -'], input=code,
                           capture_output=True, text=True, timeout=20)
    if setup.returncode:
        raise RuntimeError('run_driver_setup_failed')
    print('启动已安装的 keyvalet run；请按 Terminal 的 ndu polkit 提示解锁。', flush=True)
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
            probe = subprocess.run(ssh+['ndu', 'sudo -n /usr/bin/python3 -'],
                                   input=find_code, capture_output=True, text=True, timeout=15)
            if probe.returncode == 0 and probe.stdout.strip():
                identity = json.loads(probe.stdout)
                receipt['run_process'] = identity
                print('请在此 Terminal 输入 ndu 用户 guang 的 polkit 密码；之后审批 Mac 的网关确认与 GET。', flush=True)
                agent = subprocess.Popen(ssh+['-tt', 'ndu', '/usr/local/bin/keyvalet approve '+str(identity['pid'])])
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
