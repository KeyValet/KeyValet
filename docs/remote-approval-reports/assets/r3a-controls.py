#!/usr/bin/env python3
"""Attended installed control commands; only public metadata is retained."""
import datetime
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import shlex
import subprocess
import sys
import time

if os.getuid()!=501:
    raise SystemExit('Run as the Mac owner, without sudo')
os.umask(0o077)
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
assets=Path(__file__).resolve().parent
target='01M4S8KJ48BSMNK1S4BEGT07FC'
cli='/usr/local/lib/keyvalet/bin/kv-cli'
ssh=['/usr/bin/ssh','-o','BatchMode=yes','-o','ConnectTimeout=8','ndu']
receipt={'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
         'commands':[],'secret_values_in_evidence':False}
spec=importlib.util.spec_from_file_location('audit_report',assets/'r3a-audit-report.py')
audit_report=importlib.util.module_from_spec(spec);spec.loader.exec_module(audit_report)
spec=importlib.util.spec_from_file_location('mcp',assets/'r3a-mcp-client.py')
mcp=importlib.util.module_from_spec(spec);spec.loader.exec_module(mcp)
remote=agent=None
resume_after_mode=sys.argv[1:]==['--resume-after-mode']
unattended_only=sys.argv[1:]==['--unattended-only']
if sys.argv[1:] and not (resume_after_mode or unattended_only):
    raise SystemExit('unknown_controls_acceptance_arguments')
receipt['resume_after_verified_mode']=resume_after_mode
receipt['resume_unattended_only']=unattended_only

def settings_result(name,arguments):
    begin=time.monotonic()
    frame=remote.tool('credential_settings',arguments)
    diagnostic={'elapsed_s':round(time.monotonic()-begin,6),'is_error':frame.get('isError') is True}
    if diagnostic['is_error']:
        texts=[c.get('text','') for c in frame.get('content',[]) if c.get('type')=='text']
        known=['polkit authentication failed','polkit 认证未通过','handshake timed out',
               'authentication or TPM command timed out','settings_changed',
               'remote settings unavailable','process_binding_mismatch','ipc_unavailable']
        diagnostic['known_error_markers']=[k for k in known if any(k in t for t in texts)]
    receipt[name+'_diagnostic']=diagnostic
    return mcp.payload(frame)

def mcp_settings():
    global remote,agent
    sources={name:(assets/name).read_text() for name in ('r3a-run-agent.py','r3a-run-readiness.py','r3a-mcp-session-exec.py')}
    code='from pathlib import Path\nimport os\nd=Path("/tmp/keyvalet-r3a-native")\nif d.is_symlink() or d.stat().st_uid!=os.getuid():raise SystemExit(1)\nfor name,source in '+repr(sources)+'.items():\n p=d/name\n if p.is_symlink():raise SystemExit(1)\n p.write_text(source)\n os.chmod(p,0o600)\nfor name in ("refresh.pid","refresh.pid.new","refresh-agent.ready","refresh-agent.ready.new"):\n p=d/name\n if p.is_symlink():raise SystemExit(1)\n p.unlink(missing_ok=True)\n'
    result=subprocess.run(ssh+['/usr/bin/python3 -'],input=code,capture_output=True,text=True,timeout=20)
    if result.returncode:raise RuntimeError('control_mcp_setup_failed')
    remote=mcp.Client(ssh+['/usr/bin/python3 /tmp/keyvalet-r3a-native/r3a-mcp-session-exec.py refresh'])
    deadline=time.monotonic()+10
    while time.monotonic()<deadline:
        result=subprocess.run(ssh+['cat /tmp/keyvalet-r3a-native/refresh.pid'],capture_output=True,text=True,timeout=10)
        if result.returncode==0:
            identity=json.loads(result.stdout)
            if identity.get('uid')==1000 and identity.get('pid',0)>1:break
        time.sleep(.1)
    else:raise RuntimeError('control_mcp_actor_unavailable')
    receipt['settings_mcp_process']=identity
    agent=subprocess.Popen(ssh[:-1]+['-tt','ndu','/usr/bin/python3 /tmp/keyvalet-r3a-native/r3a-run-agent.py --phase refresh'])
    remote.initialize()
    print('核对 /keyvalet:mode 的原生 MCP 设置后端；如要求 ndu 解锁密码，请在此输入。',flush=True)
    current=settings_result('read_settings',{'purpose':'R3-A: verify /keyvalet:mode sees the signed remote set_mode result'})
    receipt['native_mcp_settings_after_remote']={k:current[k] for k in ('grant_mode','remember_hours','remember_until') if k in current}
    if current.get('grant_mode')!='per_session':raise RuntimeError('shared_settings_remote_to_mcp_mismatch')
    changed=settings_result('tighten_settings',{'grant_mode':'per_use','purpose':'R3-A: test the local /keyvalet:mode backend by tightening to per_use'})
    receipt['native_mcp_settings_after_local_change']={k:changed[k] for k in ('grant_mode','remember_hours','remember_until') if k in changed}
    if changed.get('grant_mode')!='per_use':raise RuntimeError('native_mcp_local_mode_change_failed')
    remote.close();remote=None
    agent.terminate();agent.wait(timeout=10);agent=None

def grant_metadata(grant):
    row={k:grant[k] for k in ('jti','aud','exp','nbf','revoked_at','origin') if k in grant}
    scope=grant.get('scope')
    if isinstance(scope,dict):
        row['scope']={k:scope[k] for k in ('level','credential','hosts','methods','paths','max_tier') if k in scope}
    return row

def state_metadata(state):
    row={k:state[k] for k in ('mode','pending_n','grants_n','unattended','label',
                             'unlock_ttl_s','device_revocations_pending','locked','epoch',
                             'revoked','revoked_count','cleared','cleared_count','presence') if k in state}
    if isinstance(state.get('grants'),list):
        row['grants']=[grant_metadata(g) for g in state['grants']]
    if isinstance(state.get('pending'),list):
        row['pending_count']=len(state['pending'])
    if isinstance(state.get('entries'),list):
        row['audit_entry_count']=len(state['entries'])
    if isinstance(state.get('approvers'),list):
        row['approvers']=[{k:p[k] for k in ('device_id','label','online','presence','state') if k in p} for p in state['approvers']]
    return row

def projection(value):
    out={'ok':value.get('ok'),'command':value.get('command')}
    error=value.get('error',{})
    code=error.get('code') if isinstance(error,dict) else None
    if isinstance(code,str) and re.fullmatch('[a-z_]{1,64}',code):out['error_code']=code
    message=error.get('message') if isinstance(error,dict) else None
    if isinstance(message,str):
        match=re.search(r'\((remote\.[a-z_.]{1,64}) / (connect|write_request|read_response) / (TimedOut|WouldBlock|BrokenPipe|UnexpectedEof|ConnectionReset|ConnectionRefused|NotConnected|PermissionDenied|Interrupted|Other)\)',message)
        if match:
            out['transport']={'op':match[1],'stage':match[2],'io_error_kind':match[3]}
    data=value.get('result',{})
    if isinstance(data,dict):
        if isinstance(data.get('results'),list):
            out['results']=[]
            for item in data['results']:
                result=item.get('result',{})
                out['results'].append({'device_id':item.get('device_id'),'id':result.get('id'),
                                       'ok':result.get('ok'),'state':state_metadata(result.get('state',{}))})
        if isinstance(data.get('grants'),list):
            out['grants']=[grant_metadata(g) for g in data['grants']]
    return out

def command(name,args):
    begin=time.monotonic()
    invocation=['/usr/bin/sudo','-n',cli]+args+['--json']
    if name=='unattended_1h_two_labels':
        invocation=['/usr/bin/sudo','-n','/usr/bin/python3',str(assets/'r3a-label-command.py'),'unattended-1h']
    result=subprocess.run(invocation,capture_output=True,text=True,timeout=200)
    row={'case':name,'elapsed_s':round(time.monotonic()-begin,6),'exit':result.returncode}
    try:row['public_result']=projection(json.loads(result.stdout))
    except (ValueError,KeyError):row['fixed_error']='control_result_unavailable'
    receipt['commands'].append(row)
    print(name+'：退出码 '+str(result.returncode)+'，'+str(row['elapsed_s'])+' s。',flush=True)
    if result.returncode or row.get('public_result',{}).get('ok') is not True:
        raise RuntimeError('control_command_not_applied')
    results=row['public_result'].get('results',[])
    if any(r.get('ok') is not True for r in results):
        raise RuntimeError('control_target_not_applied')
    return row

def local_mode():
    result=subprocess.run(ssh+['sudo -n '+cli+' grant-mode'],capture_output=True,text=True,timeout=20)
    mode=result.stdout.strip()
    if result.returncode or mode not in ('per_use','per_credential','per_session'):
        raise RuntimeError('native_local_mode_unavailable')
    return mode

def audit_snapshot(label):
    try:
        result=subprocess.run(['/usr/bin/sudo','-n',cli,'audit','--remote','--since',
                               '2026-10-13T05:26:00Z','--limit','200','--json'],capture_output=True,text=True,timeout=120)
    except subprocess.TimeoutExpired:
        receipt[label]={'fixed_error':'native_audit_timed_out','collection_timeout_s':120}
        print('全量审计采集超过 120 秒；已记录超时，继续独立的控制面用例。',flush=True)
        return
    if result.returncode not in (0, 3):
        receipt[label]={'cli_exit':result.returncode,'fixed_error':'native_audit_unavailable'}
        return
    try:
        receipt[label]={'cli_exit':result.returncode,'report':audit_report.project(json.loads(result.stdout))}
    except (ValueError, KeyError, TypeError):
        receipt[label]={'cli_exit':result.returncode,'fixed_error':'native_audit_unavailable'}

try:
    print('如 Terminal 要求 Mac 管理员密码，请在此输入；随后依次完成清单中的 Strong 确认。',flush=True)
    if subprocess.run(['/usr/bin/sudo','-v']).returncode:
        raise RuntimeError('control_admin_auth_failed')
    if unattended_only:
        receipt['completed_controls_receipt']='r3a-controls-143754.json'
        if local_mode()!='per_use':raise RuntimeError('unattended_resume_mode_mismatch')
        print('仅补无人值守两轮标签确认；已成功的控制用例不再重复。',flush=True)
    elif resume_after_mode:
        receipt['audit_before_controls_receipt']='r3a-native-audit-extended-125228.json'
        receipt['completed_mode_receipt']='r3a-controls-124930.json'
        print('继续已成功的 per_session 之后的用例；现在核对原生 MCP 设置。',flush=True)
    else:
        audit_snapshot('audit_before_controls')
        command('cleanup_previous_test_grants',['remote',target,'grant','revoke-all'])
        print('切换 per_session：在 Mac 确认并按 Touch ID。',flush=True)
        command('set_per_session',['remote',target,'mode','per_session'])
    if not unattended_only:
        receipt['native_local_mode_after_remote']=local_mode()
        if receipt['native_local_mode_after_remote']!='per_session':
            raise RuntimeError('shared_settings_remote_to_local_mismatch')
        mcp_settings()
        print('签发所选凭证的一小时 T1 授权：在 Mac 确认并按 Touch ID。',flush=True)
        command('allow_1h',['remote',target,'allow','--credential','api_key/r3a-graph-readonly','--until','1h'])
        command('grant_list',['grant','list'])
        command('remote_grants_before_revoke',['remote',target,'grants'])
        command('revoke_all',['remote',target,'grant','revoke-all'])
        command('lock',['remote',target,'lock'])
        print('由远程查询核对本地 MCP 已收紧的 per_use 设置。',flush=True)
        receipt['native_local_mode_after_local_change']=local_mode()
        for action in ('status','pending','grants','audit'):
            args=['remote',target,action]
            if action=='audit':args+=['--since','2026-10-13T09:00:00Z','--limit','200']
            row=command('remote_'+action,args)
            if action=='status':
                receipt['remote_mode_after_local_change']=row['public_result']['results'][0]['state'].get('mode')
        receipt['shared_settings_both_directions']=receipt['remote_mode_after_local_change']==receipt['native_local_mode_after_local_change']=='per_use'
    print('有限期无人值守：先在 Mac 完成 Strong；随后在此 Terminal 两次输入原生 CLI 显示的执行端标签。',flush=True)
    command('unattended_1h_two_labels',['remote',target,'unattended','--include-sensitive','--until','1h'])
    command('unattended_grants',['remote',target,'grants'])
    row=command('unattended_status',['remote',target,'status'])
    receipt['unattended_observed']=row['public_result']['results'][0]['state'].get('unattended') is True
    if not receipt['unattended_observed']:raise RuntimeError('unattended_not_installed_on_executor')
    command('cleanup_unattended',['remote',target,'grant','revoke-all'])
    row=command('final_status',['remote',target,'status'])
    receipt['final_unattended']=row['public_result']['results'][0]['state'].get('unattended')
    receipt['final_mode']=row['public_result']['results'][0]['state'].get('mode')
    if receipt['final_unattended'] is not False or receipt['final_mode']!='per_use':
        raise RuntimeError('control_cleanup_not_verified')
    audit_snapshot('audit_after_controls')
    print('控制面本段结束；ndu 为 per_use、无人值守授权已收回；设备吊销尚未执行。',flush=True)
except (RuntimeError,mcp.McpFailure,ValueError,KeyError,subprocess.TimeoutExpired,KeyboardInterrupt) as error:
    receipt['fixed_error']=str(error) if isinstance(error,(RuntimeError,mcp.McpFailure)) else 'control_driver_unavailable'
    print('控制面本段停止；保留实际结果。',flush=True)
finally:
    if remote is not None:remote.close()
    if agent is not None and agent.poll() is None:
        agent.terminate()
        try:agent.wait(timeout=10)
        except subprocess.TimeoutExpired:agent.kill();agent.wait()
    receipt['finished_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
    path=assets/('r3a-controls-'+datetime.datetime.now(datetime.timezone.utc).strftime('%H%M%S')+'.json')
    path.write_text(json.dumps(receipt,indent=2)+'\n')
