#!/usr/bin/env python3
"""Real sudo stdio + fake CLI input probe; no KeyValet calls or authentication UI."""
import datetime
import importlib.util
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys
import termios

os.umask(0o077)
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
assets=Path(__file__).resolve().parent
if os.getuid()==501 and not sys.argv[1:]:
    print('仅诊断 Terminal 输入；不调用 KeyValet、不请求 Touch ID。若要求 Mac 管理员密码，只在这里输入。',flush=True)
    if subprocess.run(['/usr/bin/sudo','-v']).returncode:raise SystemExit('admin_authentication_failed')
    print('看到假的标签提示后，输入 aaa 并回车；这里的 aaa 只用于输入诊断，不是产品授权。',flush=True)
    p=subprocess.run(['/usr/bin/sudo','-n','/usr/bin/python3',str(Path(__file__).resolve()),'--root'],capture_output=True,text=True,timeout=45)
    try:r=json.loads(p.stdout)
    except ValueError:r={'fixed_error':'input_diagnostic_unavailable','exit':p.returncode}
    r.update({'observed_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'read_only':True,
              'keyvalet_calls':0,'touch_id_requests':0,'secret_values_in_evidence':False})
    (assets/'r3a-label-input-native-diagnostic.json').write_text(json.dumps(r,indent=2)+'\n')
    print('输入诊断结果：'+json.dumps(r,ensure_ascii=False),flush=True)
elif os.geteuid()==0 and sys.argv[1:]==['--root']:
    spec=importlib.util.spec_from_file_location('label_command',assets/'r3a-label-command.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    ttin=signal.getsignal(signal.SIGTTIN)
    result={'stdin_is_terminal':os.isatty(0),'process_group':os.getpgrp(),
            'session_id':os.getsid(0),
            'sigttin_disposition':'default' if ttin==signal.SIG_DFL else 'ignored' if ttin==signal.SIG_IGN else 'handler'}
    if os.isatty(0):
        result['stdin_foreground_group']=os.tcgetpgrp(0)
        result['stdin_terminal']=os.ttyname(0)
    alias=os.open('/dev/tty',os.O_RDWR)
    result['controlling_foreground_group']=os.tcgetpgrp(alias)
    result['stdin_device_matches_controlling_alias']=os.fstat(0).st_rdev==os.fstat(alias).st_rdev
    os.close(alias)
    terminal=module.open_terminal()
    result['selected_terminal']=os.ttyname(terminal)
    result['io_counts']={}
    try:
        code,output=module.run([sys.executable,'-u','-c','''
import json,os,sys
with open('/dev/tty','r+b',buffering=0) as tty:
    tty.write(b'Input diagnostic only: type executor label aaa to confirm: ')
    answer=tty.readline()
ok=answer==b'aaa\\n'
print(json.dumps({'dummy_line_received':ok,'byte_count':len(answer),'issued':0}))
sys.exit(0 if ok else 6)
'''],terminal,timeout=30,diagnostic=result['io_counts'])
        result['fake_cli_exit']=code
        result['fake_cli_result']=json.loads(output)
    except (OSError,RuntimeError) as error:
        result['fixed_error']=str(error) if isinstance(error,RuntimeError) else 'input_diagnostic_io_failed'
    finally:
        result['selected_terminal_foreground_group_after_attempt']=os.tcgetpgrp(terminal)
        os.close(terminal)
    print(json.dumps(result))
else:raise SystemExit('invalid_input_diagnostic_context')
