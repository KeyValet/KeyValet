#!/usr/bin/env python3
"""Attended 20 native MCP GETs plus denial, continuation, consumption replay and query change."""
import argparse
import datetime
import importlib.util
import json
import math
import os
from pathlib import Path
import resource
import subprocess
import time

if os.getuid() != 501:
    raise SystemExit('Run as the Mac owner, without sudo')
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--negative-only',action='store_true',help='Resume only the announced negative cases, with Terminal pauses.')
parser.add_argument('--wait-only',action='store_true',help='Continuation/reclaim/query cases only; initial MCP wait budget 5 seconds.')
options=parser.parse_args()
options.negative_only=options.negative_only or options.wait_only
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
os.umask(0o077)
assets = Path('/Users/guang/dev/keyvalet/docs/remote-approval-reports/assets')
spec = importlib.util.spec_from_file_location('mcp', assets/'r3a-mcp-client.py')
mcp = importlib.util.module_from_spec(spec);spec.loader.exec_module(mcp)
spec = importlib.util.spec_from_file_location('audit', assets/'r3a-audit-report.py')
audit = importlib.util.module_from_spec(spec);spec.loader.exec_module(audit)
spec = importlib.util.spec_from_file_location('terminal_input', assets/'r3a-terminal-input.py')
terminal_input = importlib.util.module_from_spec(spec);spec.loader.exec_module(terminal_input)
ssh = ['/usr/bin/ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8']
url = 'https://graph.microsoft.com/v1.0/me'
started = time.monotonic()
receipt = {'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
           'runtime': 'installed native MCP, persistent owner session',
           'method': 'GET', 'url': url, 'credential': 'api_key/r3a-graph-readonly',
           'upstream_403_accepted_for_approval_measurement': True,
           'secret_values_in_evidence': False, 'samples': [], 'negative_cases': [],
           'negative_only':options.negative_only}
if options.wait_only:
    receipt['initial_mcp_wait_budget_s']=5
remote = agent = None


def prepare():
    names = ('r3a-run-agent.py','r3a-run-readiness.py','r3a-mcp-session-exec.py','r3a-collect-samples.py')
    sources = {name:(assets/name).read_text() for name in names}
    code = "from pathlib import Path\nimport os\nd=Path('/tmp/keyvalet-r3a-native')\nif d.is_symlink() or d.stat().st_uid!=os.getuid():raise SystemExit(1)\nfor name,source in "+repr(sources)+".items():\n p=d/name\n if p.is_symlink():raise SystemExit(1)\n p.write_text(source)\n os.chmod(p,0o600)\nfor name in ('samples.pid','samples.pid.new','samples-agent.ready','samples-agent.ready.new'):\n p=d/name\n if p.is_symlink():raise SystemExit(1)\n if p.exists():p.unlink()\n"
    result = subprocess.run(ssh+['ndu','/usr/bin/python3 -'],input=code,capture_output=True,text=True,timeout=20)
    if result.returncode:
        raise mcp.McpFailure('sample_driver_setup_failed')


def identity():
    deadline = time.monotonic()+10
    while time.monotonic()<deadline:
        result = subprocess.run(ssh+['ndu','cat /tmp/keyvalet-r3a-native/samples.pid'],capture_output=True,text=True,timeout=10)
        if result.returncode==0:
            value=json.loads(result.stdout)
            if value.get('uid')==1000 and value.get('parent_pid',0)>1:
                return value
        time.sleep(.1)
    raise mcp.McpFailure('sample_actor_unavailable')


def request(target=url):
    return mcp.payload(remote.tool('credential_http_request', {
        'type':'api_key','name':'r3a-graph-readonly','method':'GET','url':target,
        'purpose':'R3-A: repeat the owner-selected read-only GET to measure real remote approvals',
    },timeout=190))


def public_result(value):
    result={k:value[k] for k in ('status','approval_id','expires_at') if k in value}
    if isinstance(value.get('result'),dict) and isinstance(value['result'].get('status'),int):
        result['http_status']=value['result']['status']
    return result


def pending(value):
    return value.get('status') in ('approval_pending','still_pending','pending')


def wait(value, seconds=180):
    ident=value.get('approval_id')
    if not isinstance(ident,str) or not ident:
        raise mcp.McpFailure('sample_pending_id_missing')
    return mcp.payload(remote.tool('credential_wait_approval', {'approval_id':ident,'max_wait_s':seconds},timeout=seconds+15))


def cue(message):
    global agent
    if options.negative_only:
        with terminal_input.pause_agent_input(agent):
            agent=None
            print(message,flush=True)
            input('请先读完本用例操作；准备好后在此 Terminal 按回车，才发起下一条请求：')
        cleanup='from pathlib import Path; d=Path("/tmp/keyvalet-r3a-native"); names=("samples-agent.ready","samples-agent.ready.new"); [(d/n).unlink(missing_ok=True) for n in names if not (d/n).is_symlink()]'
        import shlex
        result=subprocess.run(ssh+['ndu','/usr/bin/python3 -c '+shlex.quote(cleanup)],capture_output=True,text=True,timeout=15)
        if result.returncode:
            raise mcp.McpFailure('sample_agent_reregistration_failed')
        agent=subprocess.Popen(ssh+['-tt','ndu','/usr/bin/python3 /tmp/keyvalet-r3a-native/r3a-run-agent.py --phase samples'])
        deadline=time.monotonic()+10
        expected=receipt['process_identity']
        while time.monotonic()<deadline and agent.poll() is None:
            result=subprocess.run(ssh+['ndu','cat /tmp/keyvalet-r3a-native/samples-agent.ready'],capture_output=True,text=True,timeout=10)
            if result.returncode==0 and json.loads(result.stdout)==expected:
                break
            time.sleep(.1)
        else:
            raise mcp.McpFailure('sample_agent_reregistration_failed')
    else:
        print(message,flush=True)


def collect_metrics():
    result=subprocess.run(ssh+['ndu','sudo -n /usr/bin/python3 /tmp/keyvalet-r3a-native/r3a-collect-samples.py '+str(receipt['process_identity']['parent_pid'])],capture_output=True,text=True,timeout=20)
    if result.returncode:
        raise mcp.McpFailure('sample_audit_readback_failed')
    value=json.loads(result.stdout)
    path=assets/('r3a-samples-audit-'+datetime.datetime.now(datetime.timezone.utc).strftime('%H%M%S')+'.json')
    path.write_text(json.dumps(value,indent=2)+'\n')
    receipt['audit_receipt']=path.name
    # The first 20 requests are the homogeneous cohort; later requests are the
    # explicitly announced denial/wait/replay/query-change cases.
    cohort=value['approvals'][:len(receipt['samples'])]
    valid=[row for row in cohort if row['state']=='executed' and row['level']=='quick'
           and row['scope_mode']=='per_use' and row['execution_started_count']==1
           and row['execution_completed_count']==1 and row['helper_request_to_decision_s'] is not None]
    times=sorted(row['helper_request_to_decision_s'] for row in valid)
    def quantile(p):
        at=(len(times)-1)*p
        low=math.floor(at);high=math.ceil(at)
        return round(times[low]+(times[high]-times[low])*(at-low),6)
    receipt['helper_latency']={'n':len(times),'cohort_calls':len(receipt['samples']),
                              'all_quick_per_use_once':len(valid)==20,
                              'quantile_method':'linear interpolation at (n-1)*p',
                              'p50_s':quantile(.5) if times else None,
                              'p95_s':quantile(.95) if times else None,
                              'touch_id_user_time_s':0}


try:
    prepare()
    if options.negative_only:
        code='import json,sqlite3; c=sqlite3.connect("file:/var/lib/keyvalet/remote/approvals.sqlite3?mode=ro",uri=True); row=c.execute("select value_json from settings where key=?",("mode",)).fetchone(); print(row[0] if row else "null")'
        import shlex
        result=subprocess.run(ssh+['ndu','sudo -n /usr/bin/python3 -c '+shlex.quote(code)],capture_output=True,text=True,timeout=15)
        if result.returncode or json.loads(result.stdout)!='per_use':
            raise mcp.McpFailure('sample_per_use_mode_not_applied')
        receipt['existing_mode_verified']='per_use'
    else:
        print('如 Terminal 要求 Mac 管理员密码，请在这里输入；随后在 Mac 确认 ndu 切换为 per_use 并按 Touch ID。',flush=True)
        result=subprocess.run(['/usr/bin/sudo','-v'])
        if result.returncode:
            raise mcp.McpFailure('sample_admin_auth_failed')
        mode_started=time.monotonic()
        result=subprocess.run(['/usr/bin/sudo','-n','/usr/local/lib/keyvalet/bin/kv-cli','remote','01M4S8KJ48BSMNK1S4BEGT07FC','mode','per_use','--json'],capture_output=True,text=True,timeout=190)
        receipt['set_per_use_cli_elapsed_s']=round(time.monotonic()-mode_started,6)
        receipt['set_per_use_cli_exit']=result.returncode
        if result.returncode:
            raise mcp.McpFailure('sample_per_use_mode_not_applied')
    print('逐次审批模式已生效；输入 ndu 用户 guang 的 polkit 解锁密码。',flush=True)
    command='/usr/bin/python3 /tmp/keyvalet-r3a-native/r3a-mcp-session-exec.py samples'
    if options.wait_only:
        command+=' --wait-in-call-5s'
    remote=mcp.Client(ssh+['ndu',command])
    receipt['process_identity']=identity()
    agent=subprocess.Popen(ssh+['-tt','ndu','/usr/bin/python3 /tmp/keyvalet-r3a-native/r3a-run-agent.py --phase samples'])
    remote.initialize()
    for index in range(0 if options.negative_only else 20):
        print('相同 GET '+str(index+1)+'/20：在 Mac 点击 Allow（仅本次）。',flush=True)
        begin=time.monotonic()
        value=request()
        if pending(value):
            value=wait(value)
        item=public_result(value)
        item['call_elapsed_s']=round(time.monotonic()-begin,6)
        item['index']=index+1
        receipt['samples'].append(item)
        status=item.get('http_status',item.get('status'))
        print('GET '+str(index+1)+'/20 返回 '+str(status)+'；审批与上游状态分开计。',flush=True)
        if not isinstance(status,int):
            raise mcp.McpFailure('sample_request_not_executed')
    if not options.wait_only:
        cue('拒绝用例：下一条 Mac GET 请点击 Deny。')
        negative_begin=time.monotonic()
        value=request()
        receipt['negative_cases'].append({'case':'deny','result':public_result(value),'call_elapsed_s':round(time.monotonic()-negative_begin,6)})
        if value.get('status') not in ('approval_denied','denied'):
            raise mcp.McpFailure('sample_denial_not_observed')
    cue('续等用例：下一条 Mac GET 暂时不要操作；等这里显示“已进入 credential_wait_approval”后再点击 Allow。')
    negative_begin=time.monotonic()
    value=request()
    receipt['negative_cases'].append({'case':'initial_timeout','result':public_result(value),'call_elapsed_s':round(time.monotonic()-negative_begin,6)})
    if not pending(value):
        raise mcp.McpFailure('sample_initial_wait_did_not_time_out')
    ident=value['approval_id']
    print('已进入 credential_wait_approval，沿用同一个批准 ID；现在在 Mac 点击 Allow。',flush=True)
    negative_begin=time.monotonic()
    value=wait(value)
    receipt['negative_cases'].append({'case':'wait_same_approval','approval_id':ident,'result':public_result(value),'call_elapsed_s':round(time.monotonic()-negative_begin,6)})
    print('同一批准的第二次领取：不弹新框，必须拒绝再次执行。',flush=True)
    negative_begin=time.monotonic()
    replay=mcp.payload(remote.tool('credential_wait_approval',{'approval_id':ident,'max_wait_s':5},timeout=20))
    receipt['negative_cases'].append({'case':'reclaim_same_approval','approval_id':ident,'result':public_result(replay),'call_elapsed_s':round(time.monotonic()-negative_begin,6)})
    if replay.get('status')!='already_consumed':
        raise mcp.McpFailure('sample_replay_not_rejected')
    cue('改参数用例：Mac 新出现 GET /v1.0/me?$select=id，请核对新 URL 后选择仅本次并点击 Allow。')
    negative_begin=time.monotonic()
    changed=request(url+'?$select=id')
    if pending(changed):
        changed=wait(changed)
    receipt['negative_cases'].append({'case':'query_changed','url':url+'?$select=id','result':public_result(changed),'call_elapsed_s':round(time.monotonic()-negative_begin,6)})
    collect_metrics()
    print('负面用例段完成；不输出 Graph 响应体或凭证值。' if options.negative_only else '≥20 次与四个负面用例段完成；不输出 Graph 响应体或凭证值。',flush=True)
except (mcp.McpFailure,subprocess.TimeoutExpired,ValueError,KeyError,EOFError,KeyboardInterrupt,RuntimeError) as error:
    receipt['fixed_error']=str(error) if isinstance(error,mcp.McpFailure) else 'sample_driver_unavailable'
    print('测量段停止；保留实际已完成的数量，不自动重弹。',flush=True)
    if 'process_identity' in receipt:
        try:
            collect_metrics()
        except (mcp.McpFailure,ValueError,KeyError,subprocess.TimeoutExpired):
            receipt['metric_readback_failed']=True
finally:
    if remote is not None:
        remote.close()
    if agent is not None and agent.poll() is None:
        agent.terminate()
        try:
            agent.wait(timeout=10)
        except subprocess.TimeoutExpired:
            agent.kill();agent.wait()
    receipt['elapsed_s']=round(time.monotonic()-started,6)
    receipt['finished_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
    prefix='r3a-wait-' if options.wait_only else ('r3a-negative-' if options.negative_only else 'r3a-samples-')
    path=assets/(prefix+datetime.datetime.now(datetime.timezone.utc).strftime('%H%M%S')+'.json')
    path.write_text(json.dumps(receipt,indent=2)+'\n')
    print('收据已保存。',flush=True)
